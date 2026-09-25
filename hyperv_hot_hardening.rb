# -------------------------------------------------------------------------- #
# Copyright 2002-2026, OpenNebula Project / LayerSentry downstream           #
#                                                                            #
# Licensed under the Apache License, Version 2.0.                             #
# -------------------------------------------------------------------------- #

# Production hardening layered on top of hyperv_hot_helper.rb.
#
# Key invariants:
# - RCT changed-byte offsets are applied only to an unmodified RAW mirror of
#   the exported Hyper-V reference point. Guest morphing happens once, after
#   the final source delta has been applied.
# - GetVirtualDiskChanges is never replayed after an asynchronous 4096 result.
#   Until asynchronous output-parameter recovery is live-qualified, such a
#   host fails closed rather than issuing a second RCT query.
# - after source shutdown, MORPHING/IMPORTING are explicit ambiguity barriers;
#   a restarted/manual command cannot blindly replay either mutation.
# - full Hyper-V VLAN topology participates in the prepare/cutover digest.

require 'base64'
require 'digest'
require 'fileutils'
require 'json'
require 'open3'
require_relative 'hyperv_hot_helper'

module OneSwapHyperV
    module HotUtil
        class << self
            # safe_file_component is not injective (for example a:b and a_b
            # both become a_b). Add a digest suffix so two valid operation IDs
            # can never share the same local durable-state directory.
            def state_dir(options, operation_id)
                base = File.expand_path((options[:work_dir] || '/var/tmp').to_s)
                safe = Util.safe_file_component(operation_id)
                suffix = Digest::SHA256.hexdigest(operation_id.to_s)[0, 16]
                File.join(base, 'oneswap-hyperv-hot', "#{safe}-#{suffix}")
            end
        end
    end

    class HotSource
        unless method_defined?(:layersentry_hot_inspect_before_vlan_hardening)
            alias_method :layersentry_hot_inspect_before_vlan_hardening, :inspect
        end

        def inspect(vm_name, require_state: 'Running')
            metadata = layersentry_hot_inspect_before_vlan_hardening(vm_name, require_state: require_state)
            full_vlans = inspect_full_vlan_topology(vm_name)
            by_identity = full_vlans.each_with_object({}) do |nic, out|
                out[vlan_identity(nic)] = nic
            end
            Array(metadata['NICs']).each do |nic|
                extended = by_identity[vlan_identity(nic)]
                raise Error, "unable to resolve complete VLAN topology for Hyper-V NIC #{nic['Name'].inspect}" unless extended
                nic.merge!(extended)
            end
            metadata
        end

        # RCT changed offsets are offsets in the virtual disk address space.
        # Generate a compact bundle by reading those offsets from a read-only
        # mounted source VHDX only after the VM is confirmed Off.
        def create_remote_delta_bundle!(state, disk, index)
            path64 = Base64.strict_encode64(disk.fetch('source_path').encode(Encoding::UTF_8))
            rct64 = Base64.strict_encode64(disk.fetch('rct_id').encode(Encoding::UTF_8))
            dir64 = Base64.strict_encode64(state.fetch('remote_export_dir').encode(Encoding::UTF_8))
            op64 = Base64.strict_encode64(state.fetch('operation_id').encode(Encoding::UTF_8))
            name64 = Base64.strict_encode64(state.fetch('vm_name').encode(Encoding::UTF_8))
            virtual_size = Integer(disk.fetch('virtual_size'))
            script = <<~POWERSHELL
                $ErrorActionPreference='Stop'
                $ProgressPreference='SilentlyContinue'
                [Console]::OutputEncoding=[Text.Encoding]::UTF8
                $path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{path64}'))
                $rct=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{rct64}'))
                $dir=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{dir64}'))
                $op=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{op64}'))
                $name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{name64}'))
                $virtualSize=[int64]#{virtual_size}
                $vm=Get-VM -Name $name -ErrorAction Stop
                if ([string]$vm.State -ne 'Off') { throw "source VM must remain Off while the final RCT delta is read; state=$($vm.State)" }
                $svc=Get-WmiObject -Namespace root/virtualization/v2 -Class Msvm_ImageManagementService
                $ranges=New-Object System.Collections.Generic.List[object]
                $offset=[int64]0
                $chunk=[int64]#{HOT_QUERY_CHUNK}
                while ($offset -lt $virtualSize) {
                    $remaining=$virtualSize-$offset
                    $length=[Math]::Min($chunk,$remaining)
                    # Hyper-V documents ByteLength as strictly less than the
                    # virtual disk size. Split an otherwise whole-disk query.
                    if ($offset -eq 0 -and $length -eq $virtualSize) { $length=$virtualSize-1 }
                    if ($length -le 0) { throw 'virtual disk is too small for an RCT query' }
                    $result=$svc.GetVirtualDiskChanges($path,$rct,'',$offset,$length)
                    if ($result.ReturnValue -eq 4096) {
                        throw 'GetVirtualDiskChanges returned an asynchronous job. LayerSentry does not replay the query because output parameters from the original job must be recovered authoritatively; this host requires RCT async-result qualification.'
                    }
                    if ($result.ReturnValue -ne 0) { throw "GetVirtualDiskChanges failed code=$($result.ReturnValue) offset=$offset length=$length" }
                    $changedOffsets=@($result.ChangedByteOffsets)
                    $changedLengths=@($result.ChangedByteLengths)
                    if ($changedOffsets.Count -ne $changedLengths.Count) { throw 'GetVirtualDiskChanges returned mismatched offset/length arrays' }
                    for ($i=0;$i -lt $changedOffsets.Count;$i++) {
                        $co=[int64]$changedOffsets[$i]; $cl=[int64]$changedLengths[$i]
                        if ($co -lt 0 -or $cl -le 0 -or ($co+$cl) -gt $virtualSize) { throw 'RCT returned an invalid changed range' }
                        $ranges.Add([pscustomobject]@{Offset=$co;Length=$cl})
                    }
                    $processed=[int64]$result.ProcessedByteLength
                    if ($processed -le 0 -or $processed -gt $length -or ($offset+$processed) -gt $virtualSize) { throw 'GetVirtualDiskChanges returned an invalid ProcessedByteLength' }
                    $offset += $processed
                }
                $ranges=@($ranges | Sort-Object Offset,Length)
                $mount=Mount-VHD -Path $path -ReadOnly -NoDriveLetter -Passthru -ErrorAction Stop
                try {
                    $diskObj=$mount | Get-Disk -ErrorAction Stop
                    $slash=[string][char]92
                    $rawPath=$slash+$slash+'.'+$slash+'PhysicalDrive'+$diskObj.Number
                    if (-not ('LayerSentry.RawDiskNative' -as [type])) {
                        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace LayerSentry {
    public static class RawDiskNative {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);
    }
}
"@
                    }
                    $handle=[LayerSentry.RawDiskNative]::CreateFileW(
                        $rawPath,
                        [uint32]2147483648,
                        [uint32]3,
                        [IntPtr]::Zero,
                        [uint32]3,
                        [uint32]0,
                        [IntPtr]::Zero)
                    if ($handle.IsInvalid) {
                        $win32=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        $handle.Dispose()
                        throw "CreateFileW failed for physical disk $rawPath win32=$win32"
                    }
                    $source=[IO.FileStream]::new($handle,[IO.FileAccess]::Read)
                    try {
                        $bundle=Join-Path $dir ('delta-#{index.to_i}-'+($op -replace '[^A-Za-z0-9_.-]','_')+'.lshv')
                        $out=[IO.File]::Open($bundle,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
                        $writer=New-Object IO.BinaryWriter($out)
                        try {
                            $writer.Write([Text.Encoding]::ASCII.GetBytes('LSHVDEL1'))
                            $writer.Write([int64]$virtualSize)
                            $writer.Write([int32]$ranges.Count)
                            $buffer=New-Object byte[] (1024*1024)
                            foreach ($range in $ranges) {
                                $writer.Write([int64]$range.Offset)
                                $writer.Write([int64]$range.Length)
                                $source.Seek([int64]$range.Offset,[IO.SeekOrigin]::Begin) | Out-Null
                                $remaining=[int64]$range.Length
                                while ($remaining -gt 0) {
                                    $want=[int][Math]::Min($buffer.Length,$remaining)
                                    $read=$source.Read($buffer,0,$want)
                                    if ($read -le 0) { throw 'unexpected EOF reading mounted VHDX changed range' }
                                    $writer.Write($buffer,0,$read)
                                    $remaining-=$read
                                }
                            }
                        } finally { $writer.Dispose(); $out.Dispose() }
                    } finally { $source.Dispose() }
                } finally { Dismount-VHD -Path $path -ErrorAction SilentlyContinue }
                $item=Get-Item -LiteralPath $bundle
                $hash=Get-FileHash -LiteralPath $bundle -Algorithm SHA256
                [pscustomobject]@{Path=$bundle;FileSize=[int64]$item.Length;SHA256=$hash.Hash.ToLowerInvariant();RangeCount=$ranges.Count;VirtualSize=$virtualSize}|ConvertTo-Json -Compress
            POWERSHELL
            @transport.powershell_json(script, timeout: (@options[:hyperv_delta_timeout] || 7200).to_i)
        end

        private

        def vlan_identity(nic)
            "#{nic['Name']}\u0000#{nic['MacAddress'].to_s.gsub(/[^0-9A-Fa-f]/, '').downcase}"
        end

        def inspect_full_vlan_topology(vm_name)
            name64 = Base64.strict_encode64(Util.require_text(vm_name, 'Hyper-V VM name').encode(Encoding::UTF_8))
            script = <<~POWERSHELL
                $ErrorActionPreference='Stop'
                [Console]::OutputEncoding=[Text.Encoding]::UTF8
                $name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{name64}'))
                $vm=Get-VM -Name $name -ErrorAction Stop
                @(Get-VMNetworkAdapter -VM $vm | Sort-Object Name | ForEach-Object {
                    $vlan=Get-VMNetworkAdapterVlan -VMNetworkAdapter $_ -ErrorAction Stop
                    [pscustomobject]@{
                        Name=$_.Name
                        MacAddress=$_.MacAddress
                        VlanMode=[string]$vlan.OperationMode
                        AccessVlanId=[int]$vlan.AccessVlanId
                        NativeVlanId=[int]$vlan.NativeVlanId
                        AllowedVlanIdList=[string]$vlan.AllowedVlanIdList
                        PrimaryVlanId=[int]$vlan.PrimaryVlanId
                        SecondaryVlanId=[int]$vlan.SecondaryVlanId
                        SecondaryVlanIdList=[string]$vlan.SecondaryVlanIdList
                    }
                }) | ConvertTo-Json -Depth 5 -Compress
            POWERSHELL
            parsed = @transport.powershell_json(script, timeout: 120)
            parsed.is_a?(Array) ? parsed : [parsed]
        end
    end

    class HotCoordinator
        unless method_defined?(:layersentry_hot_validate_local_before_hardening)
            alias_method :layersentry_hot_validate_local_before_hardening, :validate_local_prerequisites!
            alias_method :layersentry_hot_stable_metadata_before_hardening, :stable_metadata
        end

        def prepare
            validate_local_prerequisites!
            existing = HotUtil.load_state(@state_path)
            if existing
                validate_state_identity!(existing)
                return existing if existing['phase'] == 'PREPARED'
                raise Error, "cannot prepare Hyper-V hot migration from phase #{existing['phase']}"
            end

            metadata = @source.inspect(@vm_name, require_state: 'Running')
            validate_target_mapping!(metadata)
            validate_local_capacity!(metadata)
            validate_opennebula_targets!(metadata)
            reference = @source.create_and_export_reference(@vm_name, @operation_id, metadata, consistency: 1)
            FileUtils.mkdir_p(@dir, mode: 0o700)
            exports = @source.download_exports(
                reference,
                metadata,
                File.join(@dir, 'exports'),
                timeout: positive_timeout(:hyperv_transfer_timeout)
            )

            prepared = exports.each_with_index.map do |source_path, index|
                expected = Integer(metadata.fetch('Disks').fetch(index).fetch('VirtualSize'))
                destination = File.join(@dir, format('prepared-%02d.raw', index))
                convert_vhdx_baseline_to_raw!(source_path, destination, expected)
                { 'path' => destination, 'virtual_size' => expected }
            end
            # The exported VHDX copies are no longer needed once the exact RAW
            # baseline mirror exists. The RCT reference/source export remains
            # authoritative until final validation/finalize-success.
            exports.each { |path| FileUtils.rm_f(path) }

            rct_by_path = Array(reference['RCT']).each_with_object({}) do |rct, out|
                out[File.expand_path(rct['Path'].to_s).downcase] = rct
            end
            disks = Array(metadata['Disks']).each_with_index.map do |disk, index|
                rct = rct_by_path[File.expand_path(disk['Path'].to_s).downcase]
                raise Error, "missing RCT id for source disk #{disk['Path']}" unless rct
                {
                    'index' => index,
                    'source_path' => disk['Path'],
                    'virtual_disk_id' => disk['VirtualDiskId'],
                    'virtual_size' => Integer(disk['VirtualSize']),
                    'controller_type' => disk['ControllerType'],
                    'controller_number' => Integer(disk['ControllerNumber']),
                    'controller_location' => Integer(disk['ControllerLocation']),
                    'rct_id' => rct['RCTId'],
                    'virtual_disk_identifier' => rct['VirtualDiskIdentifier'],
                    'prepared_raw_path' => prepared[index]['path']
                }
            end
            state = {
                'version' => HOT_STATE_VERSION,
                'operation_id' => @operation_id,
                'vm_name' => @vm_name,
                'source_vm_id' => metadata['VMId'],
                'source_host' => @profile.host,
                'phase' => 'PREPARED',
                'created_at' => Time.now.utc.iso8601,
                'metadata_digest' => HotUtil.digest(stable_metadata(metadata)),
                'metadata' => metadata,
                'reference_point_id' => reference['ReferencePointId'],
                'reference_consistency_level' => reference['ConsistencyLevel'],
                'remote_export_dir' => reference['RemoteExportDir'],
                'disks' => disks,
                'target_digest' => target_digest
            }
            HotUtil.write_json_atomic(@state_path, state)
            state
        end

        # Explicit ambiguity barriers make the standalone OneSwap command obey
        # the same no-blind-replay rule as LayerSentry. MORPHING or IMPORTING
        # means the previous command may have partially mutated target state.
        def commit
            validate_local_prerequisites!
            state, = HotUtil.require_state!(
                @options,
                phase: %w[PREPARED CUTOVER_STARTED SOURCE_OFF MORPHING DELTA_APPLIED IMPORTING IMPORTED]
            )
            validate_state_identity!(state)
            return state if state['phase'] == 'IMPORTED'
            if %w[MORPHING IMPORTING].include?(state['phase'])
                raise Error, "Hyper-V hot migration is in ambiguous #{state['phase']} state; automatic replay is prohibited and target/source state must be reconciled"
            end

            if state['phase'] == 'PREPARED'
                metadata = @source.inspect(@vm_name, require_state: 'Running')
                validate_target_mapping!(metadata)
                validate_opennebula_targets!(metadata)
                verify_prepared_drift!(state, metadata)
                @source.assert_reference_exists!(state)
                state['phase'] = 'CUTOVER_STARTED'
                state['cutover_started_at'] = Time.now.utc.iso8601
                HotUtil.write_json_atomic(@state_path, state)
            end
            if state['phase'] == 'CUTOVER_STARTED'
                @source.power_off!(@vm_name, timeout: (@options[:shutdown_timeout] || 300).to_i)
                metadata = @source.inspect(@vm_name, require_state: 'Off')
                verify_prepared_drift!(state, metadata)
                state['phase'] = 'SOURCE_OFF'
                state['source_off_at'] = Time.now.utc.iso8601
                HotUtil.write_json_atomic(@state_path, state)
            end
            if state['phase'] == 'SOURCE_OFF'
                bundles = @source.create_delta_bundles!(
                    state,
                    File.join(@dir, 'deltas'),
                    timeout: positive_timeout(:hyperv_transfer_timeout)
                )
                state['disks'].each_with_index do |disk, index|
                    DeltaApplier.apply!(bundles[index], disk['prepared_raw_path'], Integer(disk['virtual_size']))
                end
                state['phase'] = 'MORPHING'
                state['morph_started_at'] = Time.now.utc.iso8601
                HotUtil.write_json_atomic(@state_path, state)
                rerun_v2v_in_place!(state)
                state['phase'] = 'DELTA_APPLIED'
                state['delta_applied_at'] = Time.now.utc.iso8601
                HotUtil.write_json_atomic(@state_path, state)
            end
            if state['phase'] == 'DELTA_APPLIED'
                state['phase'] = 'IMPORTING'
                state['import_started_at'] = Time.now.utc.iso8601
                HotUtil.write_json_atomic(@state_path, state)
                images = @helper.create_one_images(state['disks'].map { |disk| disk['prepared_raw_path'] })
                template = @helper.hyperv_vm_template(state['metadata'], images)
                rc = template.allocate(template.to_xml)
                raise Error, "failed to allocate OpenNebula hot-migration template #{@vm_name.inspect}: #{rc.message}" if OpenNebula.is_error?(rc)
                if @helper.respond_to?(:chown_one_object, true) && @helper.respond_to?(:resolve_one_ownership, true)
                    @helper.send(:chown_one_object, template, *@helper.send(:resolve_one_ownership))
                end
                state['template_id'] = template.id.to_i
                state['phase'] = 'IMPORTED'
                state['imported_at'] = Time.now.utc.iso8601
                HotUtil.write_json_atomic(@state_path, state)
            end
            state
        end

        def cleanup
            state, = HotUtil.require_state!(@options)
            validate_state_identity!(state)
            unless state['phase'] == 'PREPARED'
                raise Error, "refusing hot-migration cleanup outside PREPARED phase (current #{state['phase']}); preserve evidence and reconcile target/source state"
            end
            @source.destroy_reference!(state)
            FileUtils.rm_rf(@dir)
            { 'status' => 'CLEANED', 'operation_id' => @operation_id }
        end

        def finalize_success
            state, = HotUtil.require_state!(@options, phase: %w[IMPORTED DONE])
            validate_state_identity!(state)
            return state if state['phase'] == 'DONE'
            @source.destroy_reference!(state)
            state['phase'] = 'DONE'
            state['completed_at'] = Time.now.utc.iso8601
            HotUtil.write_json_atomic(@state_path, state)
            state
        end

        private

        def validate_local_prerequisites!
            layersentry_hot_validate_local_before_hardening
            @options[:qemu_img_path] ||= 'qemu-img'
            HotUtil.executable!(@options[:qemu_img_path], 'qemu-img')
            FileUtils.chmod(0o700, @dir) if File.directory?(@dir)
        end

        def stable_metadata(metadata)
            stable = layersentry_hot_stable_metadata_before_hardening(metadata)
            stable['NICs'] = Array(metadata['NICs']).map do |nic|
                {
                    'Name' => nic['Name'],
                    'SwitchName' => nic['SwitchName'],
                    'MacAddress' => nic['MacAddress'],
                    'VlanMode' => nic['VlanMode'],
                    'AccessVlanId' => nic['AccessVlanId'],
                    'NativeVlanId' => nic['NativeVlanId'],
                    'AllowedVlanIdList' => nic['AllowedVlanIdList'],
                    'PrimaryVlanId' => nic['PrimaryVlanId'],
                    'SecondaryVlanId' => nic['SecondaryVlanId'],
                    'SecondaryVlanIdList' => nic['SecondaryVlanIdList']
                }
            end
            stable
        end

        def convert_vhdx_baseline_to_raw!(source, destination, expected_size)
            binary = @options[:qemu_img_path] || 'qemu-img'
            stdout, stderr, status = Open3.capture3(
                binary, 'convert', '-p', '-f', 'vhdx', '-O', 'raw', source, destination
            )
            $stdout.write(stdout) unless stdout.empty?
            $stderr.write(stderr) unless stderr.empty?
            unless status.success?
                FileUtils.rm_f(destination)
                raise Error, "qemu-img baseline conversion failed for #{source.inspect} with exit #{status.exitstatus}"
            end
            actual_size = File.size(destination)
            unless actual_size == expected_size
                FileUtils.rm_f(destination)
                raise Error, "prepared RAW baseline size #{actual_size} does not match Hyper-V virtual size #{expected_size}"
            end
            destination
        end

        def rerun_v2v_in_place!(state)
            xml = File.join(@dir, 'final-libvirt.xml')
            raw_paths = state['disks'].map { |disk| disk['prepared_raw_path'] }
            content = Converter.new(@options.merge(:format => 'raw')).libvirt_xml(@vm_name, state['metadata'], raw_paths)
            content = content.gsub("<driver name='qemu' type='vhdx'/>", "<driver name='qemu' type='raw'/>")
            unless content.scan("<driver name='qemu' type='raw'/>").length == raw_paths.length
                raise Error, 'final libvirt XML did not describe every prepared disk as RAW'
            end
            File.open(xml, 'w', 0o600) { |file| file.write(content) }
            env = {}
            libguestfs = @options[:libguestfs_path].to_s.strip
            env['LIBGUESTFS_PATH'] = libguestfs unless libguestfs.empty?
            libguestfs_memsize = @options[:libguestfs_memsize].to_i
            env['LIBGUESTFS_MEMSIZE'] = libguestfs_memsize.to_s if libguestfs_memsize.positive?
            binary = @options[:v2v_in_place_path] || 'virt-v2v-in-place'
            stdout, stderr, status = Open3.capture3(
                env, binary, '-v', '--machine-readable', '-i', 'libvirtxml', xml,
                '--root', (@options[:root] || 'first').to_s
            )
            $stdout.write(stdout) unless stdout.empty?
            $stderr.write(stderr) unless stderr.empty?
            unless status.success?
                raise Error, 'virt-v2v-in-place failed after source shutdown; prepared target disks are now UNKNOWN and source must remain OFF'
            end
        end
    end
end
