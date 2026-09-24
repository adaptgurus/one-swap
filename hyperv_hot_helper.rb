# -------------------------------------------------------------------------- #
# Copyright 2002-2026, OpenNebula Project / LayerSentry downstream           #
#                                                                            #
# Licensed under the Apache License, Version 2.0.                             #
# -------------------------------------------------------------------------- #

require 'digest'
require 'fileutils'
require 'json'
require 'open3'
require 'securerandom'
require 'time'
require_relative 'hyperv_helper'

module OneSwapHyperV
    HOT_STATE_VERSION = 1
    HOT_PHASES = %w[PREPARED CUTOVER_STARTED SOURCE_OFF DELTA_APPLIED IMPORTED DONE].freeze
    HOT_OPERATION_ID = /\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z/
    HOT_QUERY_CHUNK = 512 * 1024 * 1024
    DELTA_MAGIC = 'LSHVDEL1'.b.freeze

    class SSHTransport
        def stream_powershell(script, local_path, timeout: nil)
            argv, stdin_data = send(:powershell_invocation, script)
            FileUtils.mkdir_p(File.dirname(local_path))
            stderr_text = +''
            status = nil
            runner = proc do
                Open3.popen3(*argv) do |stdin, stdout, stderr, wait_thr|
                    stdin.write(stdin_data) if stdin_data
                    stdin.close
                    stderr_thread = Thread.new { stderr.read.to_s }
                    File.open(local_path, 'wb', 0o600) { |file| IO.copy_stream(stdout, file) }
                    stdout.close
                    stderr_text = stderr_thread.value
                    status = wait_thr.value
                end
            end
            timeout && timeout.to_i > 0 ? Timeout.timeout(timeout.to_i, &runner) : runner.call
            unless status&.success?
                FileUtils.rm_f(local_path)
                raise Error, "Hyper-V streamed PowerShell operation failed#{status ? " (exit #{status.exitstatus})" : ''}: #{stderr_text.strip}"
            end
            local_path
        rescue Timeout::Error
            FileUtils.rm_f(local_path)
            raise Error, 'Hyper-V streamed PowerShell operation timed out'
        end
    end

    module HotUtil
        module_function

        def operation_id!(options)
            id = Util.require_text(options[:operation_id], 'Hyper-V hot migration operation id')
            raise Error, 'Hyper-V hot migration operation id is invalid' unless id.match?(HOT_OPERATION_ID)
            id
        end

        def executable!(value, label)
            value = Util.require_text(value, label)
            if value.include?(File::SEPARATOR)
                path = File.expand_path(value)
                raise Error, "#{label} is not executable: #{path}" unless File.file?(path) && File.executable?(path)
                return path
            end
            ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).each do |dir|
                candidate = File.join(dir, value)
                return candidate if File.file?(candidate) && File.executable?(candidate)
            end
            raise Error, "#{label} was not found in PATH: #{value}"
        end

        def canonical_json(value)
            case value
            when Hash
                '{' + value.keys.map(&:to_s).sort.map { |key| JSON.generate(key) + ':' + canonical_json(value[key] || value[key.to_sym]) }.join(',') + '}'
            when Array
                '[' + value.map { |item| canonical_json(item) }.join(',') + ']'
            else
                JSON.generate(value)
            end
        end

        def digest(value)
            Digest::SHA256.hexdigest(canonical_json(value))
        end

        def write_json_atomic(path, value)
            FileUtils.mkdir_p(File.dirname(path), mode: 0o700)
            tmp = "#{path}.#{Process.pid}.#{SecureRandom.hex(4)}.tmp"
            File.open(tmp, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
                file.write(JSON.pretty_generate(value))
                file.write("\n")
                file.flush
                file.fsync
            end
            File.rename(tmp, path)
            File.chmod(0o600, path)
        ensure
            FileUtils.rm_f(tmp) if defined?(tmp) && tmp && File.exist?(tmp)
        end

        def load_state(path)
            JSON.parse(File.read(path))
        rescue Errno::ENOENT
            nil
        rescue JSON::ParserError => e
            raise Error, "Hyper-V hot migration state is corrupt: #{e.message}"
        end

        def state_dir(options, operation_id)
            base = File.expand_path((options[:work_dir] || '/var/tmp').to_s)
            File.join(base, 'oneswap-hyperv-hot', Util.safe_file_component(operation_id))
        end

        def state_path(options, operation_id)
            File.join(state_dir(options, operation_id), 'state.json')
        end

        def require_state!(options, phase: nil)
            opid = operation_id!(options)
            path = state_path(options, opid)
            state = load_state(path)
            raise Error, "Hyper-V hot migration #{opid} has no prepared state" unless state
            raise Error, 'Hyper-V hot migration state version mismatch' unless state['version'] == HOT_STATE_VERSION
            raise Error, 'Hyper-V hot migration operation id mismatch' unless state['operation_id'] == opid
            if phase && !Array(phase).include?(state['phase'])
                raise Error, "Hyper-V hot migration state #{state['phase'].inspect} is not valid for this operation; expected #{Array(phase).join(' or ')}"
            end
            [state, path]
        end
    end

    class HotSource
        def initialize(transport, options)
            @transport = transport
            @options = options
        end

        def inspect(vm_name, require_state: 'Running')
            name64 = Base64.strict_encode64(Util.require_text(vm_name, 'Hyper-V VM name').encode(Encoding::UTF_8))
            staging64 = Base64.strict_encode64(Util.require_text(@options[:hyperv_staging_dir], 'Hyper-V staging directory').encode(Encoding::UTF_8))
            script = <<~POWERSHELL
                $ErrorActionPreference = 'Stop'
                $ProgressPreference = 'SilentlyContinue'
                $WarningPreference = 'SilentlyContinue'
                [Console]::OutputEncoding = [Text.Encoding]::UTF8
                $name = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{name64}'))
                $staging = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{staging64}'))
                $vm = Get-VM -Name $name -ErrorAction Stop
                $os = Get-CimInstance Win32_OperatingSystem
                $build = [int]$os.BuildNumber
                $rctService = Get-CimClass -Namespace root/virtualization/v2 -ClassName Msvm_VirtualSystemReferencePointService -ErrorAction SilentlyContinue
                $rctMethod = Get-CimClass -Namespace root/virtualization/v2 -ClassName Msvm_ImageManagementService -ErrorAction SilentlyContinue
                $gpu = @(Get-VMGpuPartitionAdapter -VMName $name -ErrorAction SilentlyContinue)
                $fc = @(Get-VMFibreChannelHba -VMName $name -ErrorAction SilentlyContinue)
                $processor = Get-VMProcessor -VMName $name -ErrorAction Stop
                $checkpoints = @(Get-VMSnapshot -VM $vm -ErrorAction SilentlyContinue)
                $dda = @(Get-VMAssignableDevice -VM $vm -ErrorAction SilentlyContinue)
                $security = Get-VMSecurity -VM $vm -ErrorAction SilentlyContinue
                $firmware = $null
                if ($vm.Generation -eq 2) { $firmware = Get-VMFirmware -VM $vm -ErrorAction Stop }
                $disks = @(Get-VMHardDiskDrive -VM $vm | Sort-Object ControllerNumber,ControllerLocation | ForEach-Object {
                    $vhd = Get-VHD -Path $_.Path -ErrorAction Stop
                    $file = Get-Item -LiteralPath $_.Path -ErrorAction Stop
                    [pscustomobject]@{
                        Path = $_.Path
                        ControllerType = [string]$_.ControllerType
                        ControllerNumber = [int]$_.ControllerNumber
                        ControllerLocation = [int]$_.ControllerLocation
                        VhdFormat = [string]$vhd.VhdFormat
                        VhdType = [string]$vhd.VhdType
                        ParentPath = [string]$vhd.ParentPath
                        VirtualDiskId = [string]$vhd.DiskIdentifier
                        VirtualSize = [int64]$vhd.Size
                        FileSize = [int64]$file.Length
                    }
                })
                $nics = @(Get-VMNetworkAdapter -VM $vm | Sort-Object Name | ForEach-Object {
                    $vlan = Get-VMNetworkAdapterVlan -VMNetworkAdapter $_ -ErrorAction SilentlyContinue
                    [pscustomobject]@{
                        Name = $_.Name
                        SwitchName = $_.SwitchName
                        MacAddress = $_.MacAddress
                        Status = [string]$_.Status
                        VlanMode = if ($vlan) { [string]$vlan.OperationMode } else { 'Untagged' }
                        AccessVlanId = if ($vlan) { [int]$vlan.AccessVlanId } else { 0 }
                        NativeVlanId = if ($vlan) { [int]$vlan.NativeVlanId } else { 0 }
                    }
                })
                if (-not (Test-Path -LiteralPath $staging -PathType Container)) { throw "Hyper-V staging directory does not exist: $staging" }
                $root = [IO.Path]::GetPathRoot($staging)
                $free = $null
                if ($root -match '^[A-Za-z]:\\$') { $free = (Get-PSDrive -Name $root.Substring(0,1)).Free }
                [pscustomobject]@{
                    Name = $vm.Name
                    VMId = $vm.VMId.Guid
                    State = [string]$vm.State
                    Generation = [int]$vm.Generation
                    ProcessorCount = [int]$vm.ProcessorCount
                    MemoryStartupBytes = [int64]$vm.MemoryStartup
                    DynamicMemoryEnabled = [bool]$vm.DynamicMemoryEnabled
                    MemoryMinimumBytes = [int64]$vm.MemoryMinimum
                    MemoryMaximumBytes = [int64]$vm.MemoryMaximum
                    AutomaticCheckpointsEnabled = [bool]$vm.AutomaticCheckpointsEnabled
                    ExposeVirtualizationExtensions = [bool]$processor.ExposeVirtualizationExtensions
                    HostOSVersion = [string]$os.Version
                    HostBuildNumber = $build
                    RCTReferencePointClass = [bool]($null -ne $rctService)
                    RCTImageManagementClass = [bool]($null -ne $rctMethod)
                    StagingDirectory = $staging
                    StagingFreeBytes = if ($null -eq $free) { -1 } else { [int64]$free }
                    Checkpoints = @($checkpoints | ForEach-Object { [pscustomobject]@{ Name=$_.Name; Id=$_.Id.Guid } })
                    AssignableDevices = @($dda | ForEach-Object { [pscustomobject]@{ InstancePath=$_.InstancePath; LocationPath=$_.LocationPath } })
                    GpuPartitionAdapters = @($gpu | ForEach-Object { [pscustomobject]@{ Name=$_.Name; InstancePath=$_.InstancePath } })
                    FibreChannelAdapters = @($fc | ForEach-Object { [pscustomobject]@{ SanName=$_.SanName; WorldWideNodeNameSetA=$_.WorldWideNodeNameSetA } })
                    TpmEnabled = if ($security) { [bool]$security.TpmEnabled } else { $false }
                    Shielded = if ($security) { [bool]$security.Shielded } else { $false }
                    SecureBoot = if ($firmware) { ([string]$firmware.SecureBoot) -eq 'On' } else { $false }
                    Disks = $disks
                    NICs = $nics
                } | ConvertTo-Json -Depth 10 -Compress
            POWERSHELL
            metadata = @transport.powershell_json(script, timeout: 600)
            validate!(metadata, require_state: require_state)
            metadata
        end

        def validate!(metadata, require_state: 'Running')
            state = metadata.fetch('State').to_s
            raise Error, "Hyper-V source VM must be #{require_state} for this phase; current state is #{state}" unless state.casecmp(require_state).zero?
            build = Integer(metadata.fetch('HostBuildNumber'))
            raise Error, "Hyper-V RCT hot migration requires Windows Server 2016+ (build 14393+); source build is #{build}" if build < 14_393
            raise Error, 'Hyper-V RCT reference-point service is unavailable' unless Util.bool(metadata['RCTReferencePointClass'])
            raise Error, 'Hyper-V image-management/RCT service is unavailable' unless Util.bool(metadata['RCTImageManagementClass'])
            generation = Integer(metadata.fetch('Generation'))
            raise Error, "unsupported Hyper-V generation #{generation}" unless [1, 2].include?(generation)
            raise Error, 'disable Hyper-V automatic checkpoints before hot migration' if Util.bool(metadata['AutomaticCheckpointsEnabled'])
            raise Error, 'remove existing Hyper-V checkpoints before hot migration' unless Array(metadata['Checkpoints']).empty?
            raise Error, 'Hyper-V DDA devices are not portable to OpenNebula' unless Array(metadata['AssignableDevices']).empty?
            raise Error, 'Hyper-V GPU-P devices are not qualified for cross-hypervisor migration' unless Array(metadata['GpuPartitionAdapters']).empty?
            raise Error, 'Hyper-V virtual Fibre Channel is not qualified for cross-hypervisor migration' unless Array(metadata['FibreChannelAdapters']).empty?
            raise Error, 'nested virtualization is not qualified for Hyper-V to OpenNebula migration' if Util.bool(metadata['ExposeVirtualizationExtensions'])
            raise Error, 'shielded Hyper-V VMs are not supported' if Util.bool(metadata['Shielded'])
            raise Error, 'Hyper-V vTPM state is not portable to OpenNebula' if Util.bool(metadata['TpmEnabled'])
            disks = Array(metadata['Disks'])
            raise Error, 'Hyper-V VM has no virtual disks' if disks.empty?
            disks.each_with_index do |disk, index|
                path = Util.require_text(disk['Path'], "Hyper-V disk #{index} path")
                raise Error, "Hyper-V hot migration currently requires VHDX; disk #{index} is #{File.extname(path)}" unless File.extname(path).casecmp('.vhdx').zero?
                raise Error, "Hyper-V disk #{index} has a differencing parent" unless disk['ParentPath'].to_s.strip.empty?
                raise Error, "Hyper-V disk #{index} must be fixed/dynamic VHDX, not #{disk['VhdType']}" if disk['VhdType'].to_s.casecmp('Differencing').zero?
                raise Error, "Hyper-V disk #{index} has invalid virtual size" unless Integer(disk['VirtualSize']) > 0
            end
            free = Integer(metadata['StagingFreeBytes'] || -1)
            required = disks.sum { |disk| Integer(disk['VirtualSize']) }
            raise Error, "Hyper-V staging free space #{free} is below required provisioned size #{required}" if free >= 0 && free < required
            true
        rescue KeyError, ArgumentError, TypeError => e
            raise Error, "incomplete Hyper-V hot-migration metadata: #{e.message}"
        end

        def create_and_export_reference(vm_name, operation_id, metadata, consistency: 1)
            name64 = Base64.strict_encode64(vm_name.encode(Encoding::UTF_8))
            staging64 = Base64.strict_encode64(@options[:hyperv_staging_dir].to_s.encode(Encoding::UTF_8))
            op64 = Base64.strict_encode64(operation_id.encode(Encoding::UTF_8))
            result = @transport.powershell_json(reference_prepare_script(name64, staging64, op64, consistency), timeout: (@options[:hyperv_prepare_timeout] || 7200).to_i)
            raise Error, 'reference-point export returned no disks' if Array(result['ExportedDisks']).empty?
            if Integer(result['ConsistencyLevel']) != 1
                raise Error, "reference point is not application-consistent (level #{result['ConsistencyLevel']})"
            end
            if Array(result['RCT']).length != Array(metadata['Disks']).length
                raise Error, 'RCT identifier count does not match Hyper-V source disk count'
            end
            result
        end

        def download_exports(reference, metadata, local_dir, timeout: nil)
            export_by_id = Array(reference.fetch('ExportedDisks')).each_with_object({}) { |disk, out| out[disk.fetch('VirtualDiskId').to_s.downcase] = disk }
            Array(metadata.fetch('Disks')).each_with_index.map do |source, index|
                disk_id = source.fetch('VirtualDiskId').to_s.downcase
                exported = export_by_id[disk_id]
                raise Error, "unable to map exported reference disk #{index} by VirtualDiskId #{disk_id}" unless exported
                local = File.join(local_dir, format('export-%02d.vhdx', index))
                @transport.stream_file(exported.fetch('Path'), local, timeout: timeout)
                expected_size = Integer(exported.fetch('FileSize'))
                expected_hash = exported.fetch('SHA256').to_s.downcase
                raise Error, "exported disk #{index} size mismatch" unless File.size(local) == expected_size
                raise Error, "exported disk #{index} SHA-256 mismatch" unless Digest::SHA256.file(local).hexdigest == expected_hash
                local
            end
        end

        def assert_reference_exists!(state)
            id64 = Base64.strict_encode64(state.fetch('reference_point_id').encode(Encoding::UTF_8))
            script = <<~POWERSHELL
                $ErrorActionPreference='Stop'
                $id=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{id64}'))
                $escaped=$id.Replace("'", "''")
                $ref=Get-WmiObject -Namespace root/virtualization/v2 -Class Msvm_VirtualSystemReferencePoint -Filter "InstanceID='$escaped'"
                if ($null -eq $ref) { throw 'prepared RCT reference point is no longer present' }
                [pscustomobject]@{InstanceID=$ref.InstanceID; ConsistencyLevel=[int]$ref.ConsistencyLevel}|ConvertTo-Json -Compress
            POWERSHELL
            @transport.powershell_json(script, timeout: 120)
        end

        def power_off!(vm_name, timeout: 300)
            name64 = Base64.strict_encode64(vm_name.encode(Encoding::UTF_8))
            script = <<~POWERSHELL
                $ErrorActionPreference='Stop'
                $name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{name64}'))
                $vm=Get-VM -Name $name -ErrorAction Stop
                if ([string]$vm.State -eq 'Off') { [pscustomobject]@{State='Off';AlreadyOff=$true}|ConvertTo-Json -Compress; exit 0 }
                if ([string]$vm.State -ne 'Running') { throw "source VM must be Running immediately before cutover; state=$($vm.State)" }
                Stop-VM -VM $vm -Shutdown -ErrorAction Stop
                $deadline=(Get-Date).AddSeconds(#{timeout.to_i})
                do {
                    Start-Sleep -Seconds 2
                    $vm=Get-VM -Name $name -ErrorAction Stop
                    if ([string]$vm.State -eq 'Off') { break }
                } while ((Get-Date) -lt $deadline)
                if ([string]$vm.State -ne 'Off') { throw 'graceful Hyper-V shutdown timed out; source was NOT forcibly powered off' }
                [pscustomobject]@{State='Off';AlreadyOff=$false}|ConvertTo-Json -Compress
            POWERSHELL
            @transport.powershell_json(script, timeout: timeout.to_i + 60)
        end

        def create_delta_bundles!(state, local_dir, timeout: nil)
            FileUtils.mkdir_p(local_dir, mode: 0o700)
            state.fetch('disks').each_with_index.map do |disk, index|
                remote = create_remote_delta_bundle!(state, disk, index)
                local = File.join(local_dir, format('delta-%02d.lshv', index))
                @transport.stream_file(remote.fetch('Path'), local, timeout: timeout)
                raise Error, "delta bundle #{index} size mismatch" unless File.size(local) == Integer(remote.fetch('FileSize'))
                raise Error, "delta bundle #{index} SHA-256 mismatch" unless Digest::SHA256.file(local).hexdigest == remote.fetch('SHA256').to_s.downcase
                local
            end
        end

        def destroy_reference!(state)
            id64 = Base64.strict_encode64(state.fetch('reference_point_id').encode(Encoding::UTF_8))
            export64 = Base64.strict_encode64(state.fetch('remote_export_dir').encode(Encoding::UTF_8))
            script = <<~POWERSHELL
                $ErrorActionPreference='Stop'
                $id=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{id64}'))
                $exportDir=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{export64}'))
                $escaped=$id.Replace("'", "''")
                $ref=Get-WmiObject -Namespace root/virtualization/v2 -Class Msvm_VirtualSystemReferencePoint -Filter "InstanceID='$escaped'"
                if ($null -ne $ref) {
                    $svc=Get-WmiObject -Namespace root/virtualization/v2 -Class Msvm_VirtualSystemReferencePointService
                    $r=$svc.DestroyReferencePoint($ref)
                    if ($r.ReturnValue -eq 4096) {
                        $job=[wmi]$r.Job
                        while ($job.JobState -eq 3 -or $job.JobState -eq 4) { Start-Sleep 1; $job.Get() }
                        if ($job.JobState -ne 7) { throw "DestroyReferencePoint failed state=$($job.JobState) error=$($job.ErrorDescription)" }
                    } elseif ($r.ReturnValue -ne 0) { throw "DestroyReferencePoint failed code=$($r.ReturnValue)" }
                }
                if (Test-Path -LiteralPath $exportDir) { Remove-Item -LiteralPath $exportDir -Recurse -Force }
                [pscustomobject]@{Destroyed=$true}|ConvertTo-Json -Compress
            POWERSHELL
            @transport.powershell_json(script, timeout: 1800)
        end

        private

        def reference_prepare_script(name64, staging64, op64, consistency)
            <<~POWERSHELL
                $ErrorActionPreference='Stop'
                $ProgressPreference='SilentlyContinue'
                [Console]::OutputEncoding=[Text.Encoding]::UTF8

                function Wait-CimResult($result, [string]$label) {
                    $rv=[int]$result.ReturnValue
                    if ($rv -ne 0 -and $rv -ne 4096) { throw "$label failed return=$rv" }
                    if ($rv -eq 4096) {
                        if ($null -eq $result.Job) { throw "$label returned 4096 without a job" }
                        $job=$result.Job | Get-CimInstance
                        $deadline=(Get-Date).AddMinutes(30)
                        while (($job.JobState -eq 3 -or $job.JobState -eq 4) -and (Get-Date) -lt $deadline) {
                            Start-Sleep 1
                            $job=$job | Get-CimInstance
                        }
                        if ($job.JobState -ne 7) {
                            throw "$label job failed state=$($job.JobState) code=$($job.ErrorCode) error=$($job.ErrorDescription)"
                        }
                    }
                    return $result
                }

                function ConvertTo-CimEmbeddedString {
                    param([Parameter(ValueFromPipeline=$true)][Microsoft.Management.Infrastructure.CimInstance]$CimInstance)
                    process {
                        $serializer=[Microsoft.Management.Infrastructure.Serialization.CimSerializer]::Create()
                        $bytes=$serializer.Serialize($CimInstance,[Microsoft.Management.Infrastructure.Serialization.InstanceSerializationOptions]::None)
                        [Text.Encoding]::Unicode.GetString($bytes)
                    }
                }

                function Get-CimInstancePath([Microsoft.Management.Infrastructure.CimInstance]$CimInstance) {
                    $keys=@($CimInstance.CimClass.CimClassProperties | Where-Object {$_.Qualifiers.Name -contains 'key'} | Select-Object -ExpandProperty Name)
                    $server=$CimInstance.CimSystemProperties.ServerName
                    if ([string]::IsNullOrWhiteSpace($server)) { $server=$env:COMPUTERNAME }
                    $prefix='\\'+$server.ToUpper()+'\'+$CimInstance.CimSystemProperties.Namespace.Replace('/','\')+':'+$CimInstance.CimSystemProperties.ClassName
                    if ($keys.Count -eq 0) { return $prefix+'=@' }
                    $pairs=@()
                    $slash=[string][char]92
                    foreach ($key in $keys) {
                        $value=[string]$CimInstance.$key
                        $escapedValue=$value.Replace($slash,$slash+$slash).Replace('"',$slash+'"')
                        $pairs += ($key+'="'+$escapedValue+'"')
                    }
                    return $prefix+'.'+($pairs -join ',')
                }

                function Recovery-Snapshots($computerSystem) {
                    @($computerSystem |
                        Get-CimAssociatedInstance -Association Msvm_SnapshotOfVirtualSystem -ResultClassName Msvm_VirtualSystemSettingData |
                        Where-Object {$_.VirtualSystemType -eq 'Microsoft:Hyper-V:Snapshot:Recovery'})
                }

                function Resolve-DiskPath([string]$instanceId, $sourceDisks) {
                    $escaped=$instanceId.Replace("'", "''")
                    $sad=Get-WmiObject -Namespace root/virtualization/v2 -Class Msvm_StorageAllocationSettingData -Filter "InstanceID='$escaped'" -ErrorAction SilentlyContinue
                    if ($null -ne $sad -and $sad.HostResource -and $sad.HostResource.Count -gt 0) {
                        try {
                            $hr=[wmi]$sad.HostResource[0]
                            foreach ($prop in @('Path','Name','DeviceID')) {
                                $value=[string]$hr.$prop
                                if ($value -match '\.vhdx$') { return $value }
                            }
                        } catch {}
                    }
                    foreach ($disk in $sourceDisks) {
                        if ($instanceId -like "*$($disk.VirtualDiskId)*") { return [string]$disk.Path }
                    }
                    # The reference identifier commonly ends with controller/location/L.
                    if ($instanceId -match '\\\\([0-9]+)\\\\([0-9]+)\\\\L
                        $controller=[int]$Matches[1]
                        $location=[int]$Matches[2]
                        foreach ($disk in $sourceDisks) {
                            if ([int]$disk.ControllerNumber -eq $controller -and [int]$disk.ControllerLocation -eq $location) {
                                return [string]$disk.Path
                            }
                        }
                    }
                    return $null
                }

                $name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{name64}'))
                $staging=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{staging64}'))
                $op=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{op64}'))
                $vm=Get-VM -Name $name -ErrorAction Stop
                if ([string]$vm.State -ne 'Running') { throw "source VM must be Running during hot prepare; state=$($vm.State)" }

                $sourceDisks=@(Get-VMHardDiskDrive -VM $vm | Sort-Object ControllerNumber,ControllerLocation | ForEach-Object {
                    $vhd=Get-VHD -Path $_.Path -ErrorAction Stop
                    [pscustomobject]@{
                        Path=$_.Path
                        VirtualDiskId=[string]$vhd.DiskIdentifier
                        VirtualSize=[int64]$vhd.Size
                        ControllerNumber=[int]$_.ControllerNumber
                        ControllerLocation=[int]$_.ControllerLocation
                    }
                })

                $ns='root\\virtualization\\v2'
                $cs=Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "Name='$($vm.VMId.Guid)'"
                if ($null -eq $cs) { throw 'Hyper-V computer system was not found' }
                $snapshotSvc=Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemSnapshotService
                $managementSvc=Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemManagementService
                $referenceSvc=Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemReferencePointService

                $beforeSnapshots=@(Recovery-Snapshots $cs | ForEach-Object {$_.InstanceID})
                $beforeRefs=@(Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemReferencePoint -Filter "VirtualSystemIdentifier='$($vm.VMId.Guid)'" | ForEach-Object {$_.InstanceID})
                $exportDir=Join-Path $staging ('layersentry-hot-'+($op -replace '[^A-Za-z0-9_.-]','_'))
                $snapshot=$null
                $ref=$null
                $snapshotConverted=$false
                $prepareComplete=$false

                try {
                    if (Test-Path -LiteralPath $exportDir) {
                        if ((Get-ChildItem -LiteralPath $exportDir -Force | Measure-Object).Count -gt 0) { throw "staging directory already contains data: $exportDir" }
                    } else {
                        New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
                    }

                    # Microsoft Hyper-V backup sequence:
                    # 1. Create a recovery/backup snapshot (32768).
                    # 2. Export that recovery snapshot with ExportSystemDefinition.
                    # 3. Convert the recovery snapshot to an RCT reference point.
                    $snapshotSettings=Get-CimClass -Namespace $ns -ClassName Msvm_VirtualSystemSnapshotSettingData |
                        New-CimInstance -ClientOnly -Property @{
                            ConsistencyLevel=[uint16]#{consistency.to_i}
                            IgnoreNonSnapshottableDisks=$true
                        }
                    $create=$snapshotSvc | Invoke-CimMethod -MethodName CreateSnapshot -Arguments @{
                        AffectedSystem=$cs
                        SnapshotSettings=($snapshotSettings | ConvertTo-CimEmbeddedString)
                        SnapshotType=[uint16]32768
                    }
                    Wait-CimResult $create 'Create recovery backup checkpoint' | Out-Null
                    $newSnapshots=@(Recovery-Snapshots $cs | Where-Object {$beforeSnapshots -notcontains $_.InstanceID})
                    if ($newSnapshots.Count -ne 1) { throw "expected exactly one new recovery checkpoint; found $($newSnapshots.Count)" }
                    $snapshot=$newSnapshots[0]

                    $exportSettings=@($cs |
                        Get-CimAssociatedInstance -Association Msvm_SystemExportSettingData -ResultClassName Msvm_VirtualSystemExportSettingData)
                    if ($exportSettings.Count -lt 1) { throw 'Msvm_VirtualSystemExportSettingData unavailable' }
                    $exportSetting=$exportSettings[0]
                    $exportSetting.CopySnapshotConfiguration=[uint16]3
                    $exportSetting.CopyVmRuntimeInformation=$false
                    $exportSetting.CopyVmStorage=$true
                    $exportSetting.CreateVmExportSubdirectory=$false
                    $exportSetting.SnapshotVirtualSystem=Get-CimInstancePath $snapshot
                    $exportSetting.DifferentialBackupBase=$null
                    $exportSetting.BackupIntent=[uint16]0

                    $export=$managementSvc | Invoke-CimMethod -MethodName ExportSystemDefinition -Arguments @{
                        ComputerSystem=$cs
                        ExportDirectory=$exportDir
                        ExportSettingData=($exportSetting | ConvertTo-CimEmbeddedString)
                    }
                    Wait-CimResult $export 'Export recovery backup checkpoint' | Out-Null

                    $paths=@(Get-ChildItem -LiteralPath $exportDir -Recurse -File -Filter '*.vhdx' | ForEach-Object {$_.FullName})
                    $exports=@($paths | ForEach-Object {
                        $vhd=Get-VHD -Path $_ -ErrorAction Stop
                        $item=Get-Item -LiteralPath $_ -ErrorAction Stop
                        $hash=Get-FileHash -LiteralPath $_ -Algorithm SHA256 -ErrorAction Stop
                        [pscustomobject]@{
                            Path=$_
                            VirtualDiskId=[string]$vhd.DiskIdentifier
                            VirtualSize=[int64]$vhd.Size
                            FileSize=[int64]$item.Length
                            SHA256=$hash.Hash.ToLowerInvariant()
                        }
                    })
                    if ($exports.Count -ne $sourceDisks.Count) { throw "backup export produced $($exports.Count) VHDX disks; expected $($sourceDisks.Count)" }

                    $convert=$snapshotSvc | Invoke-CimMethod -MethodName ConvertToReferencePoint -Arguments @{
                        AffectedSnapshot=$snapshot
                    }
                    Wait-CimResult $convert 'Convert recovery checkpoint to reference point' | Out-Null
                    $snapshotConverted=$true

                    $refs=@(Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemReferencePoint -Filter "VirtualSystemIdentifier='$($vm.VMId.Guid)'" |
                        Where-Object {$beforeRefs -notcontains $_.InstanceID})
                    if ($refs.Count -ne 1) { throw "expected exactly one new RCT reference point after conversion; found $($refs.Count)" }
                    $ref=$refs[0]

                    $virtualDiskIds=@($ref.VirtualDiskIdentifiers)
                    $rctIds=@($ref.ResilientChangeTrackingIdentifiers)
                    if ([int]$ref.ReferencePointType -ne 2) {
                        throw "converted recovery checkpoint produced non-RCT reference type $($ref.ReferencePointType)"
                    }
                    if ([bool]$ref.HasAssociatedData) {
                        throw 'converted RCT reference point unexpectedly has associated log data'
                    }
                    if ($virtualDiskIds.Count -ne $sourceDisks.Count) {
                        throw "RCT reference point has $($virtualDiskIds.Count) disk identifiers; expected $($sourceDisks.Count)"
                    }
                    if ($rctIds.Count -ne $virtualDiskIds.Count) {
                        throw "RCT reference point disk/id arrays differ after conversion: disks=$($virtualDiskIds.Count) rct=$($rctIds.Count)"
                    }

                    $rct=@()
                    for ($i=0;$i -lt $virtualDiskIds.Count;$i++) {
                        $rctId=[string]$rctIds[$i]
                        if ([string]::IsNullOrWhiteSpace($rctId)) { throw "converted RCT identifier is empty for disk index $i" }
                        $path=Resolve-DiskPath ([string]$virtualDiskIds[$i]) $sourceDisks
                        if ([string]::IsNullOrWhiteSpace($path)) { throw "unable to map converted RCT disk identifier $($virtualDiskIds[$i]) to a source VHDX" }
                        $rct += [pscustomobject]@{
                            Path=$path
                            VirtualDiskIdentifier=[string]$virtualDiskIds[$i]
                            RCTId=$rctId
                        }
                    }

                    $prepareComplete=$true
                    [pscustomobject]@{
                        ReferencePointId=$ref.InstanceID
                        ConsistencyLevel=[int]$ref.ConsistencyLevel
                        RemoteExportDir=$exportDir
                        RCT=$rct
                        ExportedDisks=$exports
                    } | ConvertTo-Json -Depth 8 -Compress
                } finally {
                    if (-not $prepareComplete) {
                        if ($null -ne $ref) {
                            try {
                                $destroy=$referenceSvc | Invoke-CimMethod -MethodName DestroyReferencePoint -Arguments @{AffectedReferencePoint=$ref}
                                Wait-CimResult $destroy 'Rollback reference point' | Out-Null
                            } catch {}
                        } elseif ($null -ne $snapshot -and -not $snapshotConverted) {
                            try {
                                $destroySnapshot=$snapshotSvc | Invoke-CimMethod -MethodName DestroySnapshot -Arguments @{AffectedSnapshot=$snapshot}
                                Wait-CimResult $destroySnapshot 'Rollback recovery checkpoint' | Out-Null
                            } catch {}
                        }
                        if ($exportDir -and (Test-Path -LiteralPath $exportDir)) {
                            Remove-Item -LiteralPath $exportDir -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            POWERSHELL
        end

        def create_remote_delta_bundle!(state, disk, index)
            path64 = Base64.strict_encode64(disk.fetch('source_path').encode(Encoding::UTF_8))
            rct64 = Base64.strict_encode64(disk.fetch('rct_id').encode(Encoding::UTF_8))
            dir64 = Base64.strict_encode64(state.fetch('remote_export_dir').encode(Encoding::UTF_8))
            op64 = Base64.strict_encode64(state.fetch('operation_id').encode(Encoding::UTF_8))
            virtual_size = Integer(disk.fetch('virtual_size'))
            script = <<~POWERSHELL
                $ErrorActionPreference='Stop'
                $ProgressPreference='SilentlyContinue'
                [Console]::OutputEncoding=[Text.Encoding]::UTF8
                function Wait-WmiJob([string]$jobPath) {
                    $job=[wmi]$jobPath
                    while ($job.JobState -eq 3 -or $job.JobState -eq 4) { Start-Sleep 1; $job.Get() }
                    if ($job.JobState -ne 7) { throw "Hyper-V WMI job failed state=$($job.JobState) error=$($job.ErrorDescription)" }
                }
                $path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{path64}'))
                $rct=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{rct64}'))
                $dir=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{dir64}'))
                $op=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{op64}'))
                $virtualSize=[int64]#{virtual_size}
                $svc=Get-WmiObject -Namespace root/virtualization/v2 -Class Msvm_ImageManagementService
                $ranges=New-Object System.Collections.Generic.List[object]
                $offset=[int64]0
                $chunk=[int64]#{HOT_QUERY_CHUNK}
                while ($offset -lt $virtualSize) {
                    $remaining=$virtualSize-$offset
                    $length=[Math]::Min($chunk,$remaining)
                    if ($offset -eq 0 -and $length -eq $virtualSize -and $virtualSize -gt 1) { $length=$virtualSize-1 }
                    $result=$svc.GetVirtualDiskChanges($path,$rct,'',$offset,$length)
                    if ($result.ReturnValue -eq 4096) { Wait-WmiJob $result.Job; $result=$svc.GetVirtualDiskChanges($path,$rct,'',$offset,$length) }
                    if ($result.ReturnValue -ne 0) { throw "GetVirtualDiskChanges failed code=$($result.ReturnValue) offset=$offset length=$length" }
                    for ($i=0;$i -lt @($result.ChangedByteOffsets).Count;$i++) { $ranges.Add([pscustomobject]@{Offset=[int64]$result.ChangedByteOffsets[$i];Length=[int64]$result.ChangedByteLengths[$i]}) }
                    $processed=[int64]$result.ProcessedByteLength
                    if ($processed -le 0) { throw 'GetVirtualDiskChanges returned zero processed bytes' }
                    $offset += $processed
                }
                $mount=Mount-VHD -Path $path -ReadOnly -NoDriveLetter -Passthru -ErrorAction Stop
                try {
                    $diskObj=$mount | Get-Disk -ErrorAction Stop
                    $rawPath='\\.\\PhysicalDrive'+$diskObj.Number
                    $source=[IO.File]::Open($rawPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
                    try {
                        $bundle=Join-Path $dir ('delta-#{index.to_i}-'+($op -replace '[^A-Za-z0-9_.-]','_')+'.lshv')
                        $out=[IO.File]::Open($bundle,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
                        $writer=New-Object IO.BinaryWriter($out)
                        try {
                            $writer.Write([Text.Encoding]::ASCII.GetBytes('LSHVDEL1')); $writer.Write([int64]$virtualSize); $writer.Write([int32]$ranges.Count)
                            $buffer=New-Object byte[] (1024*1024)
                            foreach ($range in $ranges) {
                                if ($range.Offset -lt 0 -or $range.Length -lt 0 -or ($range.Offset+$range.Length) -gt $virtualSize) { throw 'RCT returned an out-of-bounds changed range' }
                                $writer.Write([int64]$range.Offset); $writer.Write([int64]$range.Length)
                                $source.Seek([int64]$range.Offset,[IO.SeekOrigin]::Begin) | Out-Null
                                $remaining=[int64]$range.Length
                                while ($remaining -gt 0) {
                                    $want=[int][Math]::Min($buffer.Length,$remaining); $read=$source.Read($buffer,0,$want)
                                    if ($read -le 0) { throw 'unexpected EOF reading mounted VHDX changed range' }
                                    $writer.Write($buffer,0,$read); $remaining-=$read
                                }
                            }
                        } finally { $writer.Dispose(); $out.Dispose() }
                    } finally { $source.Dispose() }
                } finally { Dismount-VHD -Path $path -ErrorAction SilentlyContinue }
                $item=Get-Item -LiteralPath $bundle; $hash=Get-FileHash -LiteralPath $bundle -Algorithm SHA256
                [pscustomobject]@{Path=$bundle;FileSize=[int64]$item.Length;SHA256=$hash.Hash.ToLowerInvariant();RangeCount=$ranges.Count;VirtualSize=$virtualSize}|ConvertTo-Json -Compress
            POWERSHELL
            @transport.powershell_json(script, timeout: (@options[:hyperv_delta_timeout] || 7200).to_i)
        end
    end

    class DeltaApplier
        def self.apply!(bundle_path, raw_path, expected_virtual_size)
            File.open(bundle_path, 'rb') do |bundle|
                raise Error, "invalid Hyper-V delta bundle magic in #{bundle_path}" unless bundle.read(8) == DELTA_MAGIC
                virtual_size = bundle.read(8)&.unpack1('q<'); count = bundle.read(4)&.unpack1('l<')
                raise Error, 'truncated Hyper-V delta bundle header' unless virtual_size && count
                raise Error, "delta virtual size #{virtual_size} does not match prepared disk #{expected_virtual_size}" unless virtual_size == expected_virtual_size
                raise Error, 'delta range count is invalid' if count.negative? || count > 10_000_000
                raise Error, "prepared RAW disk size #{File.size(raw_path)} does not match virtual size #{virtual_size}" unless File.size(raw_path) == virtual_size
                File.open(raw_path, 'r+b') do |raw|
                    count.times do
                        offset = bundle.read(8)&.unpack1('q<'); length = bundle.read(8)&.unpack1('q<')
                        raise Error, 'truncated Hyper-V delta range header' unless offset && length
                        raise Error, 'Hyper-V delta range is out of bounds' if offset.negative? || length.negative? || offset + length > virtual_size
                        raw.seek(offset, IO::SEEK_SET); remaining = length
                        while remaining > 0
                            chunk = bundle.read([remaining, 1024 * 1024].min)
                            raise Error, 'truncated Hyper-V delta payload' if chunk.nil? || chunk.empty?
                            raw.write(chunk); remaining -= chunk.bytesize
                        end
                    end
                    raw.flush; raw.fsync
                end
                raise Error, 'Hyper-V delta bundle contains trailing bytes' unless bundle.read(1).nil?
            end
            true
        end
    end

    class HotCoordinator
        def initialize(helper, options)
            @helper = helper
            @profile = ConnectionProfile.from_options(options)
            @options = resolve_hot_options(options)
            @operation_id = HotUtil.operation_id!(@options)
            @vm_name = Util.require_text(@options[:name], 'Hyper-V VM name')
            @transport = SSHTransport.new(@profile)
            @source = HotSource.new(@transport, @options)
            @dir = HotUtil.state_dir(@options, @operation_id)
            @state_path = HotUtil.state_path(@options, @operation_id)
        end

        def preflight
            validate_local_prerequisites!
            metadata = @source.inspect(@vm_name, require_state: 'Running')
            validate_target_mapping!(metadata); validate_local_capacity!(metadata); validate_opennebula_targets!(metadata)
            { 'status' => 'ELIGIBLE', 'operation_id' => @operation_id, 'source_vm_id' => metadata['VMId'], 'metadata_digest' => HotUtil.digest(stable_metadata(metadata)) }.merge(source_inventory(metadata))
        end

        def source_inventory(metadata)
            disks = Array(metadata['Disks'])
            {
                'source_disk_bytes' => disks.sum { |disk| Integer(disk['VirtualSize']) },
                'source_nic_count' => Array(metadata['NICs']).length,
                'source_state' => metadata['State'].to_s,
                'generation' => Integer(metadata['Generation']),
                'secure_boot' => Util.bool(metadata['SecureBoot'])
            }
        rescue ArgumentError, TypeError => e
            raise Error, "invalid Hyper-V source inventory: #{e.message}"
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
            validate_target_mapping!(metadata); validate_local_capacity!(metadata); validate_opennebula_targets!(metadata)
            reference = @source.create_and_export_reference(@vm_name, @operation_id, metadata, consistency: 1)
            FileUtils.mkdir_p(@dir, mode: 0o700)
            exports = @source.download_exports(reference, metadata, File.join(@dir, 'exports'), timeout: positive_timeout(:hyperv_transfer_timeout))
            converted = Converter.new(@options.merge(:format => 'raw')).convert(@vm_name, metadata, exports, @dir)
            raise Error, "virt-v2v produced #{converted.length} disks; expected #{Array(metadata['Disks']).length}" unless converted.length == Array(metadata['Disks']).length
            prepared = converted.sort.each_with_index.map do |path, index|
                expected = Integer(metadata['Disks'][index]['VirtualSize'])
                raise Error, "prepared RAW disk #{index} size #{File.size(path)} does not match source virtual size #{expected}" unless File.size(path) == expected
                dest = File.join(@dir, format('prepared-%02d.raw', index)); FileUtils.mv(path, dest) unless File.expand_path(path) == File.expand_path(dest)
                { 'path' => dest, 'virtual_size' => expected }
            end
            rct_by_path = Array(reference['RCT']).each_with_object({}) { |r, out| out[File.expand_path(r['Path'].to_s).downcase] = r }
            disks = Array(metadata['Disks']).each_with_index.map do |disk, index|
                rct = rct_by_path[File.expand_path(disk['Path'].to_s).downcase]
                raise Error, "missing RCT id for source disk #{disk['Path']}" unless rct
                { 'index'=>index,'source_path'=>disk['Path'],'virtual_disk_id'=>disk['VirtualDiskId'],'virtual_size'=>Integer(disk['VirtualSize']),'controller_type'=>disk['ControllerType'],'controller_number'=>Integer(disk['ControllerNumber']),'controller_location'=>Integer(disk['ControllerLocation']),'rct_id'=>rct['RCTId'],'virtual_disk_identifier'=>rct['VirtualDiskIdentifier'],'prepared_raw_path'=>prepared[index]['path'] }
            end
            state = { 'version'=>HOT_STATE_VERSION,'operation_id'=>@operation_id,'vm_name'=>@vm_name,'source_vm_id'=>metadata['VMId'],'source_host'=>@profile.host,'phase'=>'PREPARED','created_at'=>Time.now.utc.iso8601,'metadata_digest'=>HotUtil.digest(stable_metadata(metadata)),'metadata'=>metadata,'reference_point_id'=>reference['ReferencePointId'],'reference_consistency_level'=>reference['ConsistencyLevel'],'remote_export_dir'=>reference['RemoteExportDir'],'disks'=>disks,'target_digest'=>target_digest }
            HotUtil.write_json_atomic(@state_path, state); state
        end

        def commit
            validate_local_prerequisites!
            state, = HotUtil.require_state!(@options, phase: %w[PREPARED CUTOVER_STARTED SOURCE_OFF DELTA_APPLIED IMPORTED])
            validate_state_identity!(state); return state if state['phase'] == 'IMPORTED'
            if state['phase'] == 'PREPARED'
                metadata = @source.inspect(@vm_name, require_state: 'Running')
                validate_target_mapping!(metadata); validate_opennebula_targets!(metadata); verify_prepared_drift!(state, metadata); @source.assert_reference_exists!(state)
                state['phase']='CUTOVER_STARTED'; state['cutover_started_at']=Time.now.utc.iso8601; HotUtil.write_json_atomic(@state_path,state)
            end
            if state['phase'] == 'CUTOVER_STARTED'
                @source.power_off!(@vm_name, timeout: (@options[:shutdown_timeout] || 300).to_i)
                metadata=@source.inspect(@vm_name, require_state:'Off'); verify_prepared_drift!(state,metadata)
                state['phase']='SOURCE_OFF'; state['source_off_at']=Time.now.utc.iso8601; HotUtil.write_json_atomic(@state_path,state)
            end
            if state['phase'] == 'SOURCE_OFF'
                bundles=@source.create_delta_bundles!(state,File.join(@dir,'deltas'),timeout:positive_timeout(:hyperv_transfer_timeout))
                state['disks'].each_with_index{|disk,index| DeltaApplier.apply!(bundles[index],disk['prepared_raw_path'],Integer(disk['virtual_size']))}
                rerun_v2v_in_place!(state)
                state['phase']='DELTA_APPLIED'; state['delta_applied_at']=Time.now.utc.iso8601; HotUtil.write_json_atomic(@state_path,state)
            end
            if state['phase'] == 'DELTA_APPLIED'
                images=@helper.create_one_images(state['disks'].map{|disk| disk['prepared_raw_path']})
                template=@helper.hyperv_vm_template(state['metadata'],images); rc=template.allocate(template.to_xml)
                raise Error, "failed to allocate OpenNebula hot-migration template #{@vm_name.inspect}: #{rc.message}" if OpenNebula.is_error?(rc)
                if @helper.respond_to?(:chown_one_object,true) && @helper.respond_to?(:resolve_one_ownership,true); @helper.send(:chown_one_object,template,*@helper.send(:resolve_one_ownership)); end
                state['template_id']=template.id.to_i; state['phase']='IMPORTED'; state['imported_at']=Time.now.utc.iso8601; HotUtil.write_json_atomic(@state_path,state)
            end
            state
        end

        def cleanup
            state,=HotUtil.require_state!(@options); validate_state_identity!(state)
            raise Error, "refusing hot-migration cleanup after cutover phase #{state['phase']}; preserve evidence and reconcile target/source state" if %w[CUTOVER_STARTED SOURCE_OFF DELTA_APPLIED IMPORTED].include?(state['phase'])
            @source.destroy_reference!(state); FileUtils.rm_rf(@dir); { 'status'=>'CLEANED','operation_id'=>@operation_id }
        end

        def finalize_success
            state,=HotUtil.require_state!(@options,phase:'IMPORTED'); validate_state_identity!(state); @source.destroy_reference!(state)
            state['phase']='DONE'; state['completed_at']=Time.now.utc.iso8601; HotUtil.write_json_atomic(@state_path,state); state
        end

        private

        def resolve_hot_options(options)
            connection_id=options[:hyperv_connection].to_s.strip; profiles=Util.fetch(options,:hyperv_connections)||{}; profile=connection_id.empty? ? {} : (Util.fetch(profiles,connection_id)||{})
            merged=options.dup; merged[:hyperv_staging_dir]=Util.fetch(profile,:staging_dir)||options[:hyperv_staging_dir]; merged[:shutdown_timeout]||=Util.fetch(profile,:shutdown_timeout); merged[:hyperv_transfer_timeout]||=Util.fetch(profile,:transfer_timeout); merged[:hyperv_prepare_timeout]||=Util.fetch(profile,:prepare_timeout); merged[:hyperv_delta_timeout]||=Util.fetch(profile,:delta_timeout); merged
        end

        def validate_local_prerequisites!
            raise Error, 'Hyper-V hot migration requires an explicit OpenNebula Image Datastore' if @options[:datastore].to_s.strip.empty?
            HotUtil.executable!(@options[:v2v_path]||'virt-v2v','virt-v2v'); @options[:v2v_in_place_path]||='virt-v2v-in-place'; HotUtil.executable!(@options[:v2v_in_place_path],'virt-v2v-in-place')
            raise Error, 'Hyper-V hot migration uses RAW prepared disks so RCT byte ranges can be applied safely' if @options[:format] && @options[:format].to_s!='' && @options[:format].to_s!='raw'
            FileUtils.mkdir_p(@dir,mode:0o700); free=local_free_bytes(@dir); raise Error, 'unable to determine free space on local hot-migration workspace' unless free&&free>0
        end

        def validate_target_mapping!(metadata)
            networks=@options[:network].to_s.split(',').map(&:strip).reject(&:empty?); nics=Array(metadata['NICs'])
            if nics.any?; raise Error, 'target OpenNebula network mapping is required for every Hyper-V NIC' if networks.empty?; raise Error, "target network count #{networks.length} must be 1 or equal source NIC count #{nics.length}" unless networks.length==1||networks.length==nics.length; networks.each{|id| raise Error,"invalid target OpenNebula network id #{id.inspect}" unless id.match?(/\A\d+\z/)}; end
            raise Error, 'Generation 2 hot migration requires a configured UEFI firmware path' if Integer(metadata['Generation'])==2 && firmware_path(metadata).to_s.strip.empty?; true
        end

        def firmware_path(metadata); secure=Util.bool(metadata['SecureBoot']); @options[secure ? :uefi_sec_path : :uefi_path]||(secure ? '/usr/share/OVMF/OVMF_CODE_4M.secboot.fd':'/usr/share/OVMF/OVMF_CODE_4M.fd'); end

        def stable_metadata(metadata)
            {'Name'=>metadata['Name'],'VMId'=>metadata['VMId'],'Generation'=>metadata['Generation'],'ProcessorCount'=>metadata['ProcessorCount'],'MemoryStartupBytes'=>metadata['MemoryStartupBytes'],'DynamicMemoryEnabled'=>metadata['DynamicMemoryEnabled'],'MemoryMinimumBytes'=>metadata['MemoryMinimumBytes'],'MemoryMaximumBytes'=>metadata['MemoryMaximumBytes'],'AutomaticCheckpointsEnabled'=>metadata['AutomaticCheckpointsEnabled'],'ExposeVirtualizationExtensions'=>metadata['ExposeVirtualizationExtensions'],'HostBuildNumber'=>metadata['HostBuildNumber'],'AssignableDevices'=>Array(metadata['AssignableDevices']),'GpuPartitionAdapters'=>Array(metadata['GpuPartitionAdapters']),'FibreChannelAdapters'=>Array(metadata['FibreChannelAdapters']),'TpmEnabled'=>metadata['TpmEnabled'],'Shielded'=>metadata['Shielded'],'SecureBoot'=>metadata['SecureBoot'],'Disks'=>Array(metadata['Disks']).map{|d| {'Path'=>d['Path'],'ControllerType'=>d['ControllerType'],'ControllerNumber'=>d['ControllerNumber'],'ControllerLocation'=>d['ControllerLocation'],'VhdFormat'=>d['VhdFormat'],'VhdType'=>d['VhdType'],'ParentPath'=>d['ParentPath'],'VirtualDiskId'=>d['VirtualDiskId'],'VirtualSize'=>d['VirtualSize']}},'NICs'=>Array(metadata['NICs']).map{|n| {'Name'=>n['Name'],'SwitchName'=>n['SwitchName'],'MacAddress'=>n['MacAddress'],'VlanMode'=>n['VlanMode'],'AccessVlanId'=>n['AccessVlanId'],'NativeVlanId'=>n['NativeVlanId']}}}
        end

        def validate_local_capacity!(metadata)
            required=Array(metadata['Disks']).sum{|disk| Integer(disk['VirtualSize'])}; minimum=(required*2.1).ceil; free=local_free_bytes(@dir)
            raise Error,'unable to determine free space on local hot-migration workspace' unless free&&free>0; raise Error,"local hot-migration workspace free space #{free} is below conservative requirement #{minimum}" if free<minimum
        end

        def validate_opennebula_targets!(metadata)
            client=@helper.instance_variable_get(:@client); raise Error,'OpenNebula client is unavailable for target preflight' unless client
            datastore_ids=@options[:datastore].to_s.split(',').map(&:strip).reject(&:empty?); disk_count=Array(metadata['Disks']).length; raise Error,"Image Datastore count #{datastore_ids.length} must be 1 or equal disk count #{disk_count}" unless datastore_ids.length==1||datastore_ids.length==disk_count
            datastore_ids.uniq.each{|raw| id=Integer(raw); raise Error,"invalid OpenNebula Image Datastore id #{raw.inspect}" if id.negative?; ds=OpenNebula::Datastore.new(OpenNebula::Datastore.build_xml(id),client); rc=ds.info; raise Error,"OpenNebula Image Datastore #{id} is unavailable: #{rc.message}" if OpenNebula.is_error?(rc)}
            @options[:network].to_s.split(',').map(&:strip).reject(&:empty?).uniq.each{|raw| id=Integer(raw); raise Error,"invalid OpenNebula VNet id #{raw.inspect}" if id.negative?; vn=OpenNebula::VirtualNetwork.new(OpenNebula::VirtualNetwork.build_xml(id),client); rc=vn.info; raise Error,"OpenNebula VNet #{id} is unavailable: #{rc.message}" if OpenNebula.is_error?(rc)}
        rescue ArgumentError
            raise Error,'OpenNebula target datastore/network ids must be non-negative integers'
        end

        def target_digest; HotUtil.digest({'datastore'=>@options[:datastore].to_s,'network'=>@options[:network].to_s,'cluster'=>@options[:one_cluster],'host'=>@options[:one_host],'sys_ds'=>@options[:one_datastore],'ds_cluster'=>@options[:one_datastore_cluster],'uefi'=>@options[:uefi_path],'uefi_secure'=>@options[:uefi_sec_path]}); end

        def verify_prepared_drift!(state,metadata)
            raise Error,'source VM identity changed since hot prepare' unless metadata['VMId'].to_s.casecmp(state['source_vm_id'].to_s).zero?; raise Error,'target migration parameters changed since hot prepare' unless target_digest==state['target_digest']; raise Error,'Hyper-V source topology/capability changed since hot prepare; cutover is blocked' unless HotUtil.digest(stable_metadata(metadata))==state['metadata_digest']
            state['disks'].each{|disk| path=disk['prepared_raw_path']; raise Error,"prepared RAW disk is missing: #{path}" unless File.file?(path); raise Error,"prepared RAW disk size drifted: #{path}" unless File.size(path)==Integer(disk['virtual_size'])}; true
        end

        def rerun_v2v_in_place!(state)
            xml=File.join(@dir,'final-libvirt.xml'); raw_paths=state['disks'].map{|disk| disk['prepared_raw_path']}; File.open(xml,'w',0o600){|file| file.write(Converter.new(@options.merge(:format=>'raw')).libvirt_xml(@vm_name,state['metadata'],raw_paths))}
            env={}; libguestfs=@options[:libguestfs_path].to_s.strip; env['LIBGUESTFS_PATH']=libguestfs unless libguestfs.empty?; binary=@options[:v2v_in_place_path]||'virt-v2v-in-place'; stdout,stderr,status=Open3.capture3(env,binary,'-v','--machine-readable','-i','libvirtxml',xml,'--root',(@options[:root]||'first').to_s); $stdout.write(stdout) unless stdout.empty?; $stderr.write(stderr) unless stderr.empty?; raise Error,'virt-v2v-in-place failed after source shutdown; prepared target disks are now UNKNOWN and source must remain OFF' unless status.success?
        end

        def local_free_bytes(path); stdout,_stderr,status=Open3.capture3('df','-Pk',path); return nil unless status.success?; fields=stdout.lines.last.to_s.split; return nil if fields.length<4; Integer(fields[3])*1024 rescue nil; end
        def positive_timeout(name); value=@options[name].to_i; value>0 ? value : nil; end
        def validate_state_identity!(state); raise Error,'prepared Hyper-V hot state belongs to a different VM' unless state['vm_name']==@vm_name; raise Error,'prepared Hyper-V hot state belongs to a different source host' unless state['source_host'].to_s.casecmp(@profile.host).zero?; end
    end
end

class OneSwapHelper
    def hyperv_hot_preflight(vm_name, options); OneSwapHyperV::HotCoordinator.new(self,options.merge(:name=>vm_name)).preflight; end
    def hyperv_hot_prepare(vm_name, options); OneSwapHyperV::HotCoordinator.new(self,options.merge(:name=>vm_name,:format=>'raw')).prepare; end
    def hyperv_hot_commit(vm_name, options)
        options=options.merge(:name=>vm_name,:format=>'raw'); @options=options; @options[:name]=vm_name; @options[:context]||='/usr/share/one/context'; @options[:virt_tools]||='/usr/local/share/virt-tools'; @options[:img_wait]||=120; @options[:context_min_free]||=1024; @options[:context_timeout]||=600; @hyperv_source_host=OneSwapHyperV::ConnectionProfile.from_options(options).host; OneSwapHyperV::HotCoordinator.new(self,options).commit
    end
    def hyperv_hot_cleanup(vm_name, options); OneSwapHyperV::HotCoordinator.new(self,options.merge(:name=>vm_name)).cleanup; end
    def hyperv_hot_finalize_success(vm_name, options); OneSwapHyperV::HotCoordinator.new(self,options.merge(:name=>vm_name)).finalize_success; end
end
) {
                        $controller=[int]$Matches[1]
                        $location=[int]$Matches[2]
                        foreach ($disk in $sourceDisks) {
                            if ([int]$disk.ControllerNumber -eq $controller -and [int]$disk.ControllerLocation -eq $location) {
                                return [string]$disk.Path
                            }
                        }
                    }
                    return $null
                }

                $name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{name64}'))
                $staging=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{staging64}'))
                $op=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{op64}'))
                $vm=Get-VM -Name $name -ErrorAction Stop
                if ([string]$vm.State -ne 'Running') { throw "source VM must be Running during hot prepare; state=$($vm.State)" }

                $sourceDisks=@(Get-VMHardDiskDrive -VM $vm | Sort-Object ControllerNumber,ControllerLocation | ForEach-Object {
                    $vhd=Get-VHD -Path $_.Path -ErrorAction Stop
                    [pscustomobject]@{
                        Path=$_.Path
                        VirtualDiskId=[string]$vhd.DiskIdentifier
                        VirtualSize=[int64]$vhd.Size
                        ControllerNumber=[int]$_.ControllerNumber
                        ControllerLocation=[int]$_.ControllerLocation
                    }
                })

                $ns='root\\virtualization\\v2'
                $cs=Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "Name='$($vm.VMId.Guid)'"
                if ($null -eq $cs) { throw 'Hyper-V computer system was not found' }
                $snapshotSvc=Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemSnapshotService
                $managementSvc=Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemManagementService
                $referenceSvc=Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemReferencePointService

                $beforeSnapshots=@(Recovery-Snapshots $cs | ForEach-Object {$_.InstanceID})
                $beforeRefs=@(Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemReferencePoint -Filter "VirtualSystemIdentifier='$($vm.VMId.Guid)'" | ForEach-Object {$_.InstanceID})
                $exportDir=Join-Path $staging ('layersentry-hot-'+($op -replace '[^A-Za-z0-9_.-]','_'))
                $snapshot=$null
                $ref=$null
                $snapshotConverted=$false
                $prepareComplete=$false

                try {
                    if (Test-Path -LiteralPath $exportDir) {
                        if ((Get-ChildItem -LiteralPath $exportDir -Force | Measure-Object).Count -gt 0) { throw "staging directory already contains data: $exportDir" }
                    } else {
                        New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
                    }

                    # Microsoft Hyper-V backup sequence:
                    # 1. Create a recovery/backup snapshot (32768).
                    # 2. Export that recovery snapshot with ExportSystemDefinition.
                    # 3. Convert the recovery snapshot to an RCT reference point.
                    $snapshotSettings=Get-CimClass -Namespace $ns -ClassName Msvm_VirtualSystemSnapshotSettingData |
                        New-CimInstance -ClientOnly -Property @{
                            ConsistencyLevel=[uint16]#{consistency.to_i}
                            IgnoreNonSnapshottableDisks=$true
                        }
                    $create=$snapshotSvc | Invoke-CimMethod -MethodName CreateSnapshot -Arguments @{
                        AffectedSystem=$cs
                        SnapshotSettings=($snapshotSettings | ConvertTo-CimEmbeddedString)
                        SnapshotType=[uint16]32768
                    }
                    Wait-CimResult $create 'Create recovery backup checkpoint' | Out-Null
                    $newSnapshots=@(Recovery-Snapshots $cs | Where-Object {$beforeSnapshots -notcontains $_.InstanceID})
                    if ($newSnapshots.Count -ne 1) { throw "expected exactly one new recovery checkpoint; found $($newSnapshots.Count)" }
                    $snapshot=$newSnapshots[0]

                    $exportSettings=@($cs |
                        Get-CimAssociatedInstance -Association Msvm_SystemExportSettingData -ResultClassName Msvm_VirtualSystemExportSettingData)
                    if ($exportSettings.Count -lt 1) { throw 'Msvm_VirtualSystemExportSettingData unavailable' }
                    $exportSetting=$exportSettings[0]
                    $exportSetting.CopySnapshotConfiguration=[uint16]3
                    $exportSetting.CopyVmRuntimeInformation=$false
                    $exportSetting.CopyVmStorage=$true
                    $exportSetting.CreateVmExportSubdirectory=$false
                    $exportSetting.SnapshotVirtualSystem=Get-CimInstancePath $snapshot
                    $exportSetting.DifferentialBackupBase=$null
                    $exportSetting.BackupIntent=[uint16]0

                    $export=$managementSvc | Invoke-CimMethod -MethodName ExportSystemDefinition -Arguments @{
                        ComputerSystem=$cs
                        ExportDirectory=$exportDir
                        ExportSettingData=($exportSetting | ConvertTo-CimEmbeddedString)
                    }
                    Wait-CimResult $export 'Export recovery backup checkpoint' | Out-Null

                    $paths=@(Get-ChildItem -LiteralPath $exportDir -Recurse -File -Filter '*.vhdx' | ForEach-Object {$_.FullName})
                    $exports=@($paths | ForEach-Object {
                        $vhd=Get-VHD -Path $_ -ErrorAction Stop
                        $item=Get-Item -LiteralPath $_ -ErrorAction Stop
                        $hash=Get-FileHash -LiteralPath $_ -Algorithm SHA256 -ErrorAction Stop
                        [pscustomobject]@{
                            Path=$_
                            VirtualDiskId=[string]$vhd.DiskIdentifier
                            VirtualSize=[int64]$vhd.Size
                            FileSize=[int64]$item.Length
                            SHA256=$hash.Hash.ToLowerInvariant()
                        }
                    })
                    if ($exports.Count -ne $sourceDisks.Count) { throw "backup export produced $($exports.Count) VHDX disks; expected $($sourceDisks.Count)" }

                    $convert=$snapshotSvc | Invoke-CimMethod -MethodName ConvertToReferencePoint -Arguments @{
                        AffectedSnapshot=$snapshot
                    }
                    Wait-CimResult $convert 'Convert recovery checkpoint to reference point' | Out-Null
                    $snapshotConverted=$true

                    $refs=@(Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemReferencePoint -Filter "VirtualSystemIdentifier='$($vm.VMId.Guid)'" |
                        Where-Object {$beforeRefs -notcontains $_.InstanceID})
                    if ($refs.Count -ne 1) { throw "expected exactly one new RCT reference point after conversion; found $($refs.Count)" }
                    $ref=$refs[0]

                    $virtualDiskIds=@($ref.VirtualDiskIdentifiers)
                    $rctIds=@($ref.ResilientChangeTrackingIdentifiers)
                    if ([int]$ref.ReferencePointType -ne 2) {
                        throw "converted recovery checkpoint produced non-RCT reference type $($ref.ReferencePointType)"
                    }
                    if ([bool]$ref.HasAssociatedData) {
                        throw 'converted RCT reference point unexpectedly has associated log data'
                    }
                    if ($virtualDiskIds.Count -ne $sourceDisks.Count) {
                        throw "RCT reference point has $($virtualDiskIds.Count) disk identifiers; expected $($sourceDisks.Count)"
                    }
                    if ($rctIds.Count -ne $virtualDiskIds.Count) {
                        throw "RCT reference point disk/id arrays differ after conversion: disks=$($virtualDiskIds.Count) rct=$($rctIds.Count)"
                    }

                    $rct=@()
                    for ($i=0;$i -lt $virtualDiskIds.Count;$i++) {
                        $rctId=[string]$rctIds[$i]
                        if ([string]::IsNullOrWhiteSpace($rctId)) { throw "converted RCT identifier is empty for disk index $i" }
                        $path=Resolve-DiskPath ([string]$virtualDiskIds[$i]) $sourceDisks
                        if ([string]::IsNullOrWhiteSpace($path)) { throw "unable to map converted RCT disk identifier $($virtualDiskIds[$i]) to a source VHDX" }
                        $rct += [pscustomobject]@{
                            Path=$path
                            VirtualDiskIdentifier=[string]$virtualDiskIds[$i]
                            RCTId=$rctId
                        }
                    }

                    $prepareComplete=$true
                    [pscustomobject]@{
                        ReferencePointId=$ref.InstanceID
                        ConsistencyLevel=[int]$ref.ConsistencyLevel
                        RemoteExportDir=$exportDir
                        RCT=$rct
                        ExportedDisks=$exports
                    } | ConvertTo-Json -Depth 8 -Compress
                } finally {
                    if (-not $prepareComplete) {
                        if ($null -ne $ref) {
                            try {
                                $destroy=$referenceSvc | Invoke-CimMethod -MethodName DestroyReferencePoint -Arguments @{AffectedReferencePoint=$ref}
                                Wait-CimResult $destroy 'Rollback reference point' | Out-Null
                            } catch {}
                        } elseif ($null -ne $snapshot -and -not $snapshotConverted) {
                            try {
                                $destroySnapshot=$snapshotSvc | Invoke-CimMethod -MethodName DestroySnapshot -Arguments @{AffectedSnapshot=$snapshot}
                                Wait-CimResult $destroySnapshot 'Rollback recovery checkpoint' | Out-Null
                            } catch {}
                        }
                        if ($exportDir -and (Test-Path -LiteralPath $exportDir)) {
                            Remove-Item -LiteralPath $exportDir -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            POWERSHELL
        end

        def create_remote_delta_bundle!(state, disk, index)
            path64 = Base64.strict_encode64(disk.fetch('source_path').encode(Encoding::UTF_8))
            rct64 = Base64.strict_encode64(disk.fetch('rct_id').encode(Encoding::UTF_8))
            dir64 = Base64.strict_encode64(state.fetch('remote_export_dir').encode(Encoding::UTF_8))
            op64 = Base64.strict_encode64(state.fetch('operation_id').encode(Encoding::UTF_8))
            virtual_size = Integer(disk.fetch('virtual_size'))
            script = <<~POWERSHELL
                $ErrorActionPreference='Stop'
                $ProgressPreference='SilentlyContinue'
                [Console]::OutputEncoding=[Text.Encoding]::UTF8
                function Wait-WmiJob([string]$jobPath) {
                    $job=[wmi]$jobPath
                    while ($job.JobState -eq 3 -or $job.JobState -eq 4) { Start-Sleep 1; $job.Get() }
                    if ($job.JobState -ne 7) { throw "Hyper-V WMI job failed state=$($job.JobState) error=$($job.ErrorDescription)" }
                }
                $path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{path64}'))
                $rct=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{rct64}'))
                $dir=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{dir64}'))
                $op=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{op64}'))
                $virtualSize=[int64]#{virtual_size}
                $svc=Get-WmiObject -Namespace root/virtualization/v2 -Class Msvm_ImageManagementService
                $ranges=New-Object System.Collections.Generic.List[object]
                $offset=[int64]0
                $chunk=[int64]#{HOT_QUERY_CHUNK}
                while ($offset -lt $virtualSize) {
                    $remaining=$virtualSize-$offset
                    $length=[Math]::Min($chunk,$remaining)
                    if ($offset -eq 0 -and $length -eq $virtualSize -and $virtualSize -gt 1) { $length=$virtualSize-1 }
                    $result=$svc.GetVirtualDiskChanges($path,$rct,'',$offset,$length)
                    if ($result.ReturnValue -eq 4096) { Wait-WmiJob $result.Job; $result=$svc.GetVirtualDiskChanges($path,$rct,'',$offset,$length) }
                    if ($result.ReturnValue -ne 0) { throw "GetVirtualDiskChanges failed code=$($result.ReturnValue) offset=$offset length=$length" }
                    for ($i=0;$i -lt @($result.ChangedByteOffsets).Count;$i++) { $ranges.Add([pscustomobject]@{Offset=[int64]$result.ChangedByteOffsets[$i];Length=[int64]$result.ChangedByteLengths[$i]}) }
                    $processed=[int64]$result.ProcessedByteLength
                    if ($processed -le 0) { throw 'GetVirtualDiskChanges returned zero processed bytes' }
                    $offset += $processed
                }
                $mount=Mount-VHD -Path $path -ReadOnly -NoDriveLetter -Passthru -ErrorAction Stop
                try {
                    $diskObj=$mount | Get-Disk -ErrorAction Stop
                    $rawPath='\\.\\PhysicalDrive'+$diskObj.Number
                    $source=[IO.File]::Open($rawPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
                    try {
                        $bundle=Join-Path $dir ('delta-#{index.to_i}-'+($op -replace '[^A-Za-z0-9_.-]','_')+'.lshv')
                        $out=[IO.File]::Open($bundle,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
                        $writer=New-Object IO.BinaryWriter($out)
                        try {
                            $writer.Write([Text.Encoding]::ASCII.GetBytes('LSHVDEL1')); $writer.Write([int64]$virtualSize); $writer.Write([int32]$ranges.Count)
                            $buffer=New-Object byte[] (1024*1024)
                            foreach ($range in $ranges) {
                                if ($range.Offset -lt 0 -or $range.Length -lt 0 -or ($range.Offset+$range.Length) -gt $virtualSize) { throw 'RCT returned an out-of-bounds changed range' }
                                $writer.Write([int64]$range.Offset); $writer.Write([int64]$range.Length)
                                $source.Seek([int64]$range.Offset,[IO.SeekOrigin]::Begin) | Out-Null
                                $remaining=[int64]$range.Length
                                while ($remaining -gt 0) {
                                    $want=[int][Math]::Min($buffer.Length,$remaining); $read=$source.Read($buffer,0,$want)
                                    if ($read -le 0) { throw 'unexpected EOF reading mounted VHDX changed range' }
                                    $writer.Write($buffer,0,$read); $remaining-=$read
                                }
                            }
                        } finally { $writer.Dispose(); $out.Dispose() }
                    } finally { $source.Dispose() }
                } finally { Dismount-VHD -Path $path -ErrorAction SilentlyContinue }
                $item=Get-Item -LiteralPath $bundle; $hash=Get-FileHash -LiteralPath $bundle -Algorithm SHA256
                [pscustomobject]@{Path=$bundle;FileSize=[int64]$item.Length;SHA256=$hash.Hash.ToLowerInvariant();RangeCount=$ranges.Count;VirtualSize=$virtualSize}|ConvertTo-Json -Compress
            POWERSHELL
            @transport.powershell_json(script, timeout: (@options[:hyperv_delta_timeout] || 7200).to_i)
        end
    end

    class DeltaApplier
        def self.apply!(bundle_path, raw_path, expected_virtual_size)
            File.open(bundle_path, 'rb') do |bundle|
                raise Error, "invalid Hyper-V delta bundle magic in #{bundle_path}" unless bundle.read(8) == DELTA_MAGIC
                virtual_size = bundle.read(8)&.unpack1('q<'); count = bundle.read(4)&.unpack1('l<')
                raise Error, 'truncated Hyper-V delta bundle header' unless virtual_size && count
                raise Error, "delta virtual size #{virtual_size} does not match prepared disk #{expected_virtual_size}" unless virtual_size == expected_virtual_size
                raise Error, 'delta range count is invalid' if count.negative? || count > 10_000_000
                raise Error, "prepared RAW disk size #{File.size(raw_path)} does not match virtual size #{virtual_size}" unless File.size(raw_path) == virtual_size
                File.open(raw_path, 'r+b') do |raw|
                    count.times do
                        offset = bundle.read(8)&.unpack1('q<'); length = bundle.read(8)&.unpack1('q<')
                        raise Error, 'truncated Hyper-V delta range header' unless offset && length
                        raise Error, 'Hyper-V delta range is out of bounds' if offset.negative? || length.negative? || offset + length > virtual_size
                        raw.seek(offset, IO::SEEK_SET); remaining = length
                        while remaining > 0
                            chunk = bundle.read([remaining, 1024 * 1024].min)
                            raise Error, 'truncated Hyper-V delta payload' if chunk.nil? || chunk.empty?
                            raw.write(chunk); remaining -= chunk.bytesize
                        end
                    end
                    raw.flush; raw.fsync
                end
                raise Error, 'Hyper-V delta bundle contains trailing bytes' unless bundle.read(1).nil?
            end
            true
        end
    end

    class HotCoordinator
        def initialize(helper, options)
            @helper = helper
            @profile = ConnectionProfile.from_options(options)
            @options = resolve_hot_options(options)
            @operation_id = HotUtil.operation_id!(@options)
            @vm_name = Util.require_text(@options[:name], 'Hyper-V VM name')
            @transport = SSHTransport.new(@profile)
            @source = HotSource.new(@transport, @options)
            @dir = HotUtil.state_dir(@options, @operation_id)
            @state_path = HotUtil.state_path(@options, @operation_id)
        end

        def preflight
            validate_local_prerequisites!
            metadata = @source.inspect(@vm_name, require_state: 'Running')
            validate_target_mapping!(metadata); validate_local_capacity!(metadata); validate_opennebula_targets!(metadata)
            { 'status' => 'ELIGIBLE', 'operation_id' => @operation_id, 'source_vm_id' => metadata['VMId'], 'metadata_digest' => HotUtil.digest(stable_metadata(metadata)) }.merge(source_inventory(metadata))
        end

        def source_inventory(metadata)
            disks = Array(metadata['Disks'])
            {
                'source_disk_bytes' => disks.sum { |disk| Integer(disk['VirtualSize']) },
                'source_nic_count' => Array(metadata['NICs']).length,
                'source_state' => metadata['State'].to_s,
                'generation' => Integer(metadata['Generation']),
                'secure_boot' => Util.bool(metadata['SecureBoot'])
            }
        rescue ArgumentError, TypeError => e
            raise Error, "invalid Hyper-V source inventory: #{e.message}"
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
            validate_target_mapping!(metadata); validate_local_capacity!(metadata); validate_opennebula_targets!(metadata)
            reference = @source.create_and_export_reference(@vm_name, @operation_id, metadata, consistency: 1)
            FileUtils.mkdir_p(@dir, mode: 0o700)
            exports = @source.download_exports(reference, metadata, File.join(@dir, 'exports'), timeout: positive_timeout(:hyperv_transfer_timeout))
            converted = Converter.new(@options.merge(:format => 'raw')).convert(@vm_name, metadata, exports, @dir)
            raise Error, "virt-v2v produced #{converted.length} disks; expected #{Array(metadata['Disks']).length}" unless converted.length == Array(metadata['Disks']).length
            prepared = converted.sort.each_with_index.map do |path, index|
                expected = Integer(metadata['Disks'][index]['VirtualSize'])
                raise Error, "prepared RAW disk #{index} size #{File.size(path)} does not match source virtual size #{expected}" unless File.size(path) == expected
                dest = File.join(@dir, format('prepared-%02d.raw', index)); FileUtils.mv(path, dest) unless File.expand_path(path) == File.expand_path(dest)
                { 'path' => dest, 'virtual_size' => expected }
            end
            rct_by_path = Array(reference['RCT']).each_with_object({}) { |r, out| out[File.expand_path(r['Path'].to_s).downcase] = r }
            disks = Array(metadata['Disks']).each_with_index.map do |disk, index|
                rct = rct_by_path[File.expand_path(disk['Path'].to_s).downcase]
                raise Error, "missing RCT id for source disk #{disk['Path']}" unless rct
                { 'index'=>index,'source_path'=>disk['Path'],'virtual_disk_id'=>disk['VirtualDiskId'],'virtual_size'=>Integer(disk['VirtualSize']),'controller_type'=>disk['ControllerType'],'controller_number'=>Integer(disk['ControllerNumber']),'controller_location'=>Integer(disk['ControllerLocation']),'rct_id'=>rct['RCTId'],'virtual_disk_identifier'=>rct['VirtualDiskIdentifier'],'prepared_raw_path'=>prepared[index]['path'] }
            end
            state = { 'version'=>HOT_STATE_VERSION,'operation_id'=>@operation_id,'vm_name'=>@vm_name,'source_vm_id'=>metadata['VMId'],'source_host'=>@profile.host,'phase'=>'PREPARED','created_at'=>Time.now.utc.iso8601,'metadata_digest'=>HotUtil.digest(stable_metadata(metadata)),'metadata'=>metadata,'reference_point_id'=>reference['ReferencePointId'],'reference_consistency_level'=>reference['ConsistencyLevel'],'remote_export_dir'=>reference['RemoteExportDir'],'disks'=>disks,'target_digest'=>target_digest }
            HotUtil.write_json_atomic(@state_path, state); state
        end

        def commit
            validate_local_prerequisites!
            state, = HotUtil.require_state!(@options, phase: %w[PREPARED CUTOVER_STARTED SOURCE_OFF DELTA_APPLIED IMPORTED])
            validate_state_identity!(state); return state if state['phase'] == 'IMPORTED'
            if state['phase'] == 'PREPARED'
                metadata = @source.inspect(@vm_name, require_state: 'Running')
                validate_target_mapping!(metadata); validate_opennebula_targets!(metadata); verify_prepared_drift!(state, metadata); @source.assert_reference_exists!(state)
                state['phase']='CUTOVER_STARTED'; state['cutover_started_at']=Time.now.utc.iso8601; HotUtil.write_json_atomic(@state_path,state)
            end
            if state['phase'] == 'CUTOVER_STARTED'
                @source.power_off!(@vm_name, timeout: (@options[:shutdown_timeout] || 300).to_i)
                metadata=@source.inspect(@vm_name, require_state:'Off'); verify_prepared_drift!(state,metadata)
                state['phase']='SOURCE_OFF'; state['source_off_at']=Time.now.utc.iso8601; HotUtil.write_json_atomic(@state_path,state)
            end
            if state['phase'] == 'SOURCE_OFF'
                bundles=@source.create_delta_bundles!(state,File.join(@dir,'deltas'),timeout:positive_timeout(:hyperv_transfer_timeout))
                state['disks'].each_with_index{|disk,index| DeltaApplier.apply!(bundles[index],disk['prepared_raw_path'],Integer(disk['virtual_size']))}
                rerun_v2v_in_place!(state)
                state['phase']='DELTA_APPLIED'; state['delta_applied_at']=Time.now.utc.iso8601; HotUtil.write_json_atomic(@state_path,state)
            end
            if state['phase'] == 'DELTA_APPLIED'
                images=@helper.create_one_images(state['disks'].map{|disk| disk['prepared_raw_path']})
                template=@helper.hyperv_vm_template(state['metadata'],images); rc=template.allocate(template.to_xml)
                raise Error, "failed to allocate OpenNebula hot-migration template #{@vm_name.inspect}: #{rc.message}" if OpenNebula.is_error?(rc)
                if @helper.respond_to?(:chown_one_object,true) && @helper.respond_to?(:resolve_one_ownership,true); @helper.send(:chown_one_object,template,*@helper.send(:resolve_one_ownership)); end
                state['template_id']=template.id.to_i; state['phase']='IMPORTED'; state['imported_at']=Time.now.utc.iso8601; HotUtil.write_json_atomic(@state_path,state)
            end
            state
        end

        def cleanup
            state,=HotUtil.require_state!(@options); validate_state_identity!(state)
            raise Error, "refusing hot-migration cleanup after cutover phase #{state['phase']}; preserve evidence and reconcile target/source state" if %w[CUTOVER_STARTED SOURCE_OFF DELTA_APPLIED IMPORTED].include?(state['phase'])
            @source.destroy_reference!(state); FileUtils.rm_rf(@dir); { 'status'=>'CLEANED','operation_id'=>@operation_id }
        end

        def finalize_success
            state,=HotUtil.require_state!(@options,phase:'IMPORTED'); validate_state_identity!(state); @source.destroy_reference!(state)
            state['phase']='DONE'; state['completed_at']=Time.now.utc.iso8601; HotUtil.write_json_atomic(@state_path,state); state
        end

        private

        def resolve_hot_options(options)
            connection_id=options[:hyperv_connection].to_s.strip; profiles=Util.fetch(options,:hyperv_connections)||{}; profile=connection_id.empty? ? {} : (Util.fetch(profiles,connection_id)||{})
            merged=options.dup; merged[:hyperv_staging_dir]=Util.fetch(profile,:staging_dir)||options[:hyperv_staging_dir]; merged[:shutdown_timeout]||=Util.fetch(profile,:shutdown_timeout); merged[:hyperv_transfer_timeout]||=Util.fetch(profile,:transfer_timeout); merged[:hyperv_prepare_timeout]||=Util.fetch(profile,:prepare_timeout); merged[:hyperv_delta_timeout]||=Util.fetch(profile,:delta_timeout); merged
        end

        def validate_local_prerequisites!
            raise Error, 'Hyper-V hot migration requires an explicit OpenNebula Image Datastore' if @options[:datastore].to_s.strip.empty?
            HotUtil.executable!(@options[:v2v_path]||'virt-v2v','virt-v2v'); @options[:v2v_in_place_path]||='virt-v2v-in-place'; HotUtil.executable!(@options[:v2v_in_place_path],'virt-v2v-in-place')
            raise Error, 'Hyper-V hot migration uses RAW prepared disks so RCT byte ranges can be applied safely' if @options[:format] && @options[:format].to_s!='' && @options[:format].to_s!='raw'
            FileUtils.mkdir_p(@dir,mode:0o700); free=local_free_bytes(@dir); raise Error, 'unable to determine free space on local hot-migration workspace' unless free&&free>0
        end

        def validate_target_mapping!(metadata)
            networks=@options[:network].to_s.split(',').map(&:strip).reject(&:empty?); nics=Array(metadata['NICs'])
            if nics.any?; raise Error, 'target OpenNebula network mapping is required for every Hyper-V NIC' if networks.empty?; raise Error, "target network count #{networks.length} must be 1 or equal source NIC count #{nics.length}" unless networks.length==1||networks.length==nics.length; networks.each{|id| raise Error,"invalid target OpenNebula network id #{id.inspect}" unless id.match?(/\A\d+\z/)}; end
            raise Error, 'Generation 2 hot migration requires a configured UEFI firmware path' if Integer(metadata['Generation'])==2 && firmware_path(metadata).to_s.strip.empty?; true
        end

        def firmware_path(metadata); secure=Util.bool(metadata['SecureBoot']); @options[secure ? :uefi_sec_path : :uefi_path]||(secure ? '/usr/share/OVMF/OVMF_CODE_4M.secboot.fd':'/usr/share/OVMF/OVMF_CODE_4M.fd'); end

        def stable_metadata(metadata)
            {'Name'=>metadata['Name'],'VMId'=>metadata['VMId'],'Generation'=>metadata['Generation'],'ProcessorCount'=>metadata['ProcessorCount'],'MemoryStartupBytes'=>metadata['MemoryStartupBytes'],'DynamicMemoryEnabled'=>metadata['DynamicMemoryEnabled'],'MemoryMinimumBytes'=>metadata['MemoryMinimumBytes'],'MemoryMaximumBytes'=>metadata['MemoryMaximumBytes'],'AutomaticCheckpointsEnabled'=>metadata['AutomaticCheckpointsEnabled'],'ExposeVirtualizationExtensions'=>metadata['ExposeVirtualizationExtensions'],'HostBuildNumber'=>metadata['HostBuildNumber'],'AssignableDevices'=>Array(metadata['AssignableDevices']),'GpuPartitionAdapters'=>Array(metadata['GpuPartitionAdapters']),'FibreChannelAdapters'=>Array(metadata['FibreChannelAdapters']),'TpmEnabled'=>metadata['TpmEnabled'],'Shielded'=>metadata['Shielded'],'SecureBoot'=>metadata['SecureBoot'],'Disks'=>Array(metadata['Disks']).map{|d| {'Path'=>d['Path'],'ControllerType'=>d['ControllerType'],'ControllerNumber'=>d['ControllerNumber'],'ControllerLocation'=>d['ControllerLocation'],'VhdFormat'=>d['VhdFormat'],'VhdType'=>d['VhdType'],'ParentPath'=>d['ParentPath'],'VirtualDiskId'=>d['VirtualDiskId'],'VirtualSize'=>d['VirtualSize']}},'NICs'=>Array(metadata['NICs']).map{|n| {'Name'=>n['Name'],'SwitchName'=>n['SwitchName'],'MacAddress'=>n['MacAddress'],'VlanMode'=>n['VlanMode'],'AccessVlanId'=>n['AccessVlanId'],'NativeVlanId'=>n['NativeVlanId']}}}
        end

        def validate_local_capacity!(metadata)
            required=Array(metadata['Disks']).sum{|disk| Integer(disk['VirtualSize'])}; minimum=(required*2.1).ceil; free=local_free_bytes(@dir)
            raise Error,'unable to determine free space on local hot-migration workspace' unless free&&free>0; raise Error,"local hot-migration workspace free space #{free} is below conservative requirement #{minimum}" if free<minimum
        end

        def validate_opennebula_targets!(metadata)
            client=@helper.instance_variable_get(:@client); raise Error,'OpenNebula client is unavailable for target preflight' unless client
            datastore_ids=@options[:datastore].to_s.split(',').map(&:strip).reject(&:empty?); disk_count=Array(metadata['Disks']).length; raise Error,"Image Datastore count #{datastore_ids.length} must be 1 or equal disk count #{disk_count}" unless datastore_ids.length==1||datastore_ids.length==disk_count
            datastore_ids.uniq.each{|raw| id=Integer(raw); raise Error,"invalid OpenNebula Image Datastore id #{raw.inspect}" if id.negative?; ds=OpenNebula::Datastore.new(OpenNebula::Datastore.build_xml(id),client); rc=ds.info; raise Error,"OpenNebula Image Datastore #{id} is unavailable: #{rc.message}" if OpenNebula.is_error?(rc)}
            @options[:network].to_s.split(',').map(&:strip).reject(&:empty?).uniq.each{|raw| id=Integer(raw); raise Error,"invalid OpenNebula VNet id #{raw.inspect}" if id.negative?; vn=OpenNebula::VirtualNetwork.new(OpenNebula::VirtualNetwork.build_xml(id),client); rc=vn.info; raise Error,"OpenNebula VNet #{id} is unavailable: #{rc.message}" if OpenNebula.is_error?(rc)}
        rescue ArgumentError
            raise Error,'OpenNebula target datastore/network ids must be non-negative integers'
        end

        def target_digest; HotUtil.digest({'datastore'=>@options[:datastore].to_s,'network'=>@options[:network].to_s,'cluster'=>@options[:one_cluster],'host'=>@options[:one_host],'sys_ds'=>@options[:one_datastore],'ds_cluster'=>@options[:one_datastore_cluster],'uefi'=>@options[:uefi_path],'uefi_secure'=>@options[:uefi_sec_path]}); end

        def verify_prepared_drift!(state,metadata)
            raise Error,'source VM identity changed since hot prepare' unless metadata['VMId'].to_s.casecmp(state['source_vm_id'].to_s).zero?; raise Error,'target migration parameters changed since hot prepare' unless target_digest==state['target_digest']; raise Error,'Hyper-V source topology/capability changed since hot prepare; cutover is blocked' unless HotUtil.digest(stable_metadata(metadata))==state['metadata_digest']
            state['disks'].each{|disk| path=disk['prepared_raw_path']; raise Error,"prepared RAW disk is missing: #{path}" unless File.file?(path); raise Error,"prepared RAW disk size drifted: #{path}" unless File.size(path)==Integer(disk['virtual_size'])}; true
        end

        def rerun_v2v_in_place!(state)
            xml=File.join(@dir,'final-libvirt.xml'); raw_paths=state['disks'].map{|disk| disk['prepared_raw_path']}; File.open(xml,'w',0o600){|file| file.write(Converter.new(@options.merge(:format=>'raw')).libvirt_xml(@vm_name,state['metadata'],raw_paths))}
            env={}; libguestfs=@options[:libguestfs_path].to_s.strip; env['LIBGUESTFS_PATH']=libguestfs unless libguestfs.empty?; binary=@options[:v2v_in_place_path]||'virt-v2v-in-place'; stdout,stderr,status=Open3.capture3(env,binary,'-v','--machine-readable','-i','libvirtxml',xml,'--root',(@options[:root]||'first').to_s); $stdout.write(stdout) unless stdout.empty?; $stderr.write(stderr) unless stderr.empty?; raise Error,'virt-v2v-in-place failed after source shutdown; prepared target disks are now UNKNOWN and source must remain OFF' unless status.success?
        end

        def local_free_bytes(path); stdout,_stderr,status=Open3.capture3('df','-Pk',path); return nil unless status.success?; fields=stdout.lines.last.to_s.split; return nil if fields.length<4; Integer(fields[3])*1024 rescue nil; end
        def positive_timeout(name); value=@options[name].to_i; value>0 ? value : nil; end
        def validate_state_identity!(state); raise Error,'prepared Hyper-V hot state belongs to a different VM' unless state['vm_name']==@vm_name; raise Error,'prepared Hyper-V hot state belongs to a different source host' unless state['source_host'].to_s.casecmp(@profile.host).zero?; end
    end
end

class OneSwapHelper
    def hyperv_hot_preflight(vm_name, options); OneSwapHyperV::HotCoordinator.new(self,options.merge(:name=>vm_name)).preflight; end
    def hyperv_hot_prepare(vm_name, options); OneSwapHyperV::HotCoordinator.new(self,options.merge(:name=>vm_name,:format=>'raw')).prepare; end
    def hyperv_hot_commit(vm_name, options)
        options=options.merge(:name=>vm_name,:format=>'raw'); @options=options; @options[:name]=vm_name; @options[:context]||='/usr/share/one/context'; @options[:virt_tools]||='/usr/local/share/virt-tools'; @options[:img_wait]||=120; @options[:context_min_free]||=1024; @options[:context_timeout]||=600; @hyperv_source_host=OneSwapHyperV::ConnectionProfile.from_options(options).host; OneSwapHyperV::HotCoordinator.new(self,options).commit
    end
    def hyperv_hot_cleanup(vm_name, options); OneSwapHyperV::HotCoordinator.new(self,options.merge(:name=>vm_name)).cleanup; end
    def hyperv_hot_finalize_success(vm_name, options); OneSwapHyperV::HotCoordinator.new(self,options.merge(:name=>vm_name)).finalize_success; end
end
