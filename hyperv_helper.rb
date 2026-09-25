# -------------------------------------------------------------------------- #
# Copyright 2002-2026, OpenNebula Project / LayerSentry downstream           #
#                                                                            #
# Licensed under the Apache License, Version 2.0.                             #
# -------------------------------------------------------------------------- #

require 'base64'
require 'cgi'
require 'digest'
require 'fileutils'
require 'json'
require 'open3'
require 'rexml/document'
require 'securerandom'
require 'shellwords'
require 'timeout'

module OneSwapHyperV
    class Error < StandardError; end

    SAFE_HOST = /\A[a-zA-Z0-9][a-zA-Z0-9_.:-]*\z/
    SAFE_USER = /\A[a-zA-Z0-9_.@\\-]+\z/
    SAFE_CONNECTION = /\A[a-zA-Z0-9_.:-]+\z/

    module Util
        module_function

        def fetch(hash, key)
            return nil unless hash.respond_to?(:[])

            hash[key] || hash[key.to_s] || hash[key.to_sym] || hash[":#{key}"]
        end

        def require_text(value, label)
            value = value.to_s.strip
            raise Error, "#{label} is required" if value.empty?
            raise Error, "#{label} contains a control character" if value.match?(/[\r\n\x00]/)

            value
        end

        def positive_integer(value, label, min: 1, max: nil)
            parsed = Integer(value)
            raise Error, "#{label} must be >= #{min}" if parsed < min
            raise Error, "#{label} must be <= #{max}" if max && parsed > max

            parsed
        rescue ArgumentError, TypeError
            raise Error, "#{label} must be an integer"
        end

        def bool(value)
            value == true || value.to_s.casecmp('true').zero? || value.to_s.casecmp('yes').zero?
        end

        def safe_local_file!(path, label, private: false)
            path = File.expand_path(require_text(path, label))
            raise Error, "#{label} must be an absolute path" unless path.start_with?('/')
            raise Error, "#{label} does not exist: #{path}" unless File.file?(path)
            raise Error, "#{label} is not readable: #{path}" unless File.readable?(path)
            if private
                mode = File.stat(path).mode & 0o777
                raise Error, "#{label} permissions are too broad (#{format('%o', mode)}); require 0600/0400 style permissions" if (mode & 0o077) != 0
            end

            path
        end

        def powershell_encoded(script)
            Base64.strict_encode64(script.encode(Encoding::UTF_16LE))
        end

        def escape_xml(value)
            CGI.escapeHTML(value.to_s)
        end

        def safe_file_component(value)
            component = value.to_s.gsub(/[^A-Za-z0-9_.-]+/, '_').sub(/\A[.]+/, '')
            component = 'vm' if component.empty?
            component[0, 80]
        end
    end

    class ConnectionProfile
        attr_reader :id, :host, :user, :port, :identity_file, :known_hosts

        def self.from_options(options)
            connection_id = options[:hyperv_connection].to_s.strip
            profile = {}
            unless connection_id.empty?
                raise Error, 'Hyper-V connection id is invalid' unless connection_id.match?(SAFE_CONNECTION)

                profiles = Util.fetch(options, :hyperv_connections) || {}
                profile = Util.fetch(profiles, connection_id)
                raise Error, "Hyper-V connection #{connection_id.inspect} was not found in the server-side OneSwap configuration" unless profile
            end

            merged = {
                :host => Util.fetch(profile, :host) || options[:hyperv_host],
                :user => Util.fetch(profile, :user) || options[:hyperv_user] || 'Administrator',
                :port => Util.fetch(profile, :port) || options[:hyperv_port] || 22,
                :identity_file => Util.fetch(profile, :identity_file) || options[:hyperv_identity],
                :known_hosts => Util.fetch(profile, :known_hosts) || options[:hyperv_known_hosts]
            }
            new(connection_id.empty? ? 'direct' : connection_id, merged)
        end

        def initialize(id, raw)
            @id = id
            @host = Util.require_text(Util.fetch(raw, :host), 'Hyper-V host')
            @user = Util.require_text(Util.fetch(raw, :user), 'Hyper-V SSH user')
            @port = Util.positive_integer(Util.fetch(raw, :port) || 22, 'Hyper-V SSH port', min: 1, max: 65_535)
            raise Error, "invalid Hyper-V host #{@host.inspect}" unless @host.match?(SAFE_HOST)
            raise Error, "invalid Hyper-V SSH user #{@user.inspect}" unless @user.match?(SAFE_USER)

            @identity_file = Util.safe_local_file!(Util.fetch(raw, :identity_file), 'Hyper-V SSH identity file', private: true)
            @known_hosts = Util.safe_local_file!(Util.fetch(raw, :known_hosts), 'Hyper-V known_hosts file')
        end

        def destination
            "#{@user}@#{@host}"
        end
    end

    class SSHTransport
        POWERSHELL_ENCODED_COMMAND_MAX_BYTES = 6_000

        def initialize(profile)
            @profile = profile
        end

        def powershell(script, timeout: 120)
            argv, stdin_data = powershell_invocation(script)
            stdout, stderr, status = run_capture(argv, timeout, stdin_data)
            unless status.success?
                detail = stderr.to_s.strip
                detail = stdout.to_s.strip if detail.empty?
                raise Error, "Hyper-V PowerShell command failed (exit #{status.exitstatus}): #{detail}"
            end
            stdout
        end

        def powershell_json(script, timeout: 300)
            output = powershell(script, timeout: timeout)
            JSON.parse(output)
        rescue JSON::ParserError => e
            raise Error, "Hyper-V returned malformed JSON: #{e.message}"
        end

        def stream_file(remote_path, local_path, timeout: nil)
            encoded_path = Base64.strict_encode64(remote_path.encode(Encoding::UTF_8))
            script = <<~POWERSHELL
                $ErrorActionPreference = 'Stop'
                $ProgressPreference = 'SilentlyContinue'
                $path = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{encoded_path}'))
                $source = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                try {
                    $source.CopyTo([Console]::OpenStandardOutput())
                } finally {
                    $source.Dispose()
                }
            POWERSHELL
            argv, stdin_data = powershell_invocation(script)
            FileUtils.mkdir_p(File.dirname(local_path))
            stderr_text = +''
            status = nil
            Timeout.timeout(timeout) do
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
            unless status&.success?
                FileUtils.rm_f(local_path)
                raise Error, "Hyper-V disk transfer failed#{status ? " (exit #{status.exitstatus})" : ''}: #{stderr_text.strip}"
            end
            local_path
        rescue Timeout::Error
            FileUtils.rm_f(local_path)
            raise Error, "Hyper-V disk transfer timed out for #{remote_path}"
        end

        private

        def run_capture(argv, timeout, stdin_data = nil)
            stdout_text = +''
            stderr_text = +''
            status = nil
            pid = nil
            runner = proc do
                Open3.popen3(*argv) do |stdin, stdout, stderr, wait_thr|
                    pid = wait_thr.pid
                    writer = Thread.new do
                        begin
                            stdin.write(stdin_data) if stdin_data
                        ensure
                            stdin.close unless stdin.closed?
                        end
                    end
                    out_reader = Thread.new { stdout.read.to_s }
                    err_reader = Thread.new { stderr.read.to_s }
                    writer.value
                    stdout_text = out_reader.value
                    stderr_text = err_reader.value
                    status = wait_thr.value
                end
            end

            if timeout && timeout.to_i.positive?
                Timeout.timeout(timeout.to_i, &runner)
            else
                runner.call
            end
            [stdout_text, stderr_text, status]
        rescue Timeout::Error
            begin
                Process.kill('TERM', pid) if pid
            rescue Errno::ESRCH, Errno::EPERM
                nil
            end
            raise Error, "Hyper-V SSH/PowerShell operation timed out after #{timeout}s"
        end

        def powershell_invocation(script)
            common = [
                'ssh', '-T',
                '-o', 'BatchMode=yes',
                '-o', 'IdentitiesOnly=yes',
                '-o', 'StrictHostKeyChecking=yes',
                '-o', "UserKnownHostsFile=#{@profile.known_hosts}",
                '-o', 'PasswordAuthentication=no',
                '-o', 'ServerAliveInterval=15',
                '-o', 'ServerAliveCountMax=4',
                '-o', 'TCPKeepAlive=yes',
                '-p', @profile.port.to_s,
                '-i', @profile.identity_file,
                @profile.destination,
                'powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
                '-ExecutionPolicy', 'Bypass'
            ]
            encoded = Util.powershell_encoded(script)
            if encoded.bytesize <= POWERSHELL_ENCODED_COMMAND_MAX_BYTES
                [common + ['-EncodedCommand', encoded], nil]
            else
                # Windows PowerShell 5.1 natively supports reading command text
                # from redirected stdin with "-Command -". Avoid a custom
                # ReadToEnd/ScriptBlock bootstrap here: Windows OpenSSH versions
                # have exhibited broken-pipe behavior with that nested stdin
                # pattern on large multi-line payloads.
                [common + ['-Command', '-'], script.encode(Encoding::UTF_8)]
            end
        end
    end

    class Source
        attr_reader :metadata

        def initialize(transport)
            @transport = transport
        end

        def inventory(vm_name)
            name64 = Base64.strict_encode64(Util.require_text(vm_name, 'Hyper-V VM name').encode(Encoding::UTF_8))
            script = <<~POWERSHELL
                $ErrorActionPreference = 'Stop'
                $ProgressPreference = 'SilentlyContinue'
                $WarningPreference = 'SilentlyContinue'
                [Console]::OutputEncoding = [Text.Encoding]::UTF8
                $name = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{name64}'))
                $vm = Get-VM -Name $name -ErrorAction Stop
                $disks = @(Get-VMHardDiskDrive -VM $vm | Sort-Object ControllerNumber,ControllerLocation | ForEach-Object {
                    $vhd = Get-VHD -Path $_.Path -ErrorAction Stop
                    [pscustomobject]@{ VirtualSize = [int64]$vhd.Size }
                })
                [pscustomobject]@{
                    SourceVMId = $vm.VMId.Guid
                    State = [string]$vm.State
                    Generation = [int]$vm.Generation
                    ProcessorCount = [int]$vm.ProcessorCount
                    MemoryStartupBytes = [int64]$vm.MemoryStartup
                    Disks = $disks
                } | ConvertTo-Json -Depth 5 -Compress
            POWERSHELL
            value = @transport.powershell_json(script, timeout: 300)
            disks = Array(value['Disks'])
            raise Error, 'Hyper-V VM has no virtual hard disks' if disks.empty?
            source_disk_bytes = disks.each_with_index.sum do |disk, index|
                bytes = Integer(disk['VirtualSize'])
                raise Error, "Hyper-V disk #{index} has invalid virtual size" unless bytes.positive?
                bytes
            end
            {
                'source_vm_id' => Util.require_text(value['SourceVMId'], 'Hyper-V source VM id'),
                'source_vm_state' => Util.require_text(value['State'], 'Hyper-V source VM state'),
                'source_disk_bytes' => source_disk_bytes,
                'disk_count' => disks.length,
                'generation' => Integer(value['Generation']),
                'processor_count' => Integer(value['ProcessorCount']),
                'memory_startup_bytes' => Integer(value['MemoryStartupBytes'])
            }
        rescue KeyError, ArgumentError, TypeError => e
            raise Error, "incomplete Hyper-V inventory: #{e.message}"
        end

        def inspect(vm_name)
            name64 = Base64.strict_encode64(Util.require_text(vm_name, 'Hyper-V VM name').encode(Encoding::UTF_8))
            script = <<~POWERSHELL
                $ErrorActionPreference = 'Stop'
                $ProgressPreference = 'SilentlyContinue'
                $WarningPreference = 'SilentlyContinue'
                [Console]::OutputEncoding = [Text.Encoding]::UTF8
                $name = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{name64}'))
                $vm = Get-VM -Name $name -ErrorAction Stop
                $checkpoints = @(Get-VMSnapshot -VM $vm -ErrorAction SilentlyContinue | ForEach-Object {
                    [pscustomobject]@{ Name = $_.Name; Id = $_.Id.Guid; CreationTime = $_.CreationTime }
                })
                $dda = @(Get-VMAssignableDevice -VM $vm -ErrorAction SilentlyContinue | ForEach-Object {
                    [pscustomobject]@{ InstancePath = $_.InstancePath; LocationPath = $_.LocationPath }
                })
                $security = Get-VMSecurity -VM $vm -ErrorAction SilentlyContinue
                $firmware = $null
                if ($vm.Generation -eq 2) { $firmware = Get-VMFirmware -VM $vm -ErrorAction Stop }
                $disks = @(Get-VMHardDiskDrive -VM $vm | Sort-Object ControllerNumber,ControllerLocation | ForEach-Object {
                    $vhd = Get-VHD -Path $_.Path -ErrorAction Stop
                    $file = Get-Item -LiteralPath $_.Path -ErrorAction Stop
                    $hash = Get-FileHash -LiteralPath $_.Path -Algorithm SHA256 -ErrorAction Stop
                    [pscustomobject]@{
                        Path = $_.Path
                        ControllerType = [string]$_.ControllerType
                        ControllerNumber = $_.ControllerNumber
                        ControllerLocation = $_.ControllerLocation
                        VhdFormat = [string]$vhd.VhdFormat
                        VhdType = [string]$vhd.VhdType
                        ParentPath = [string]$vhd.ParentPath
                        VirtualSize = [int64]$vhd.Size
                        FileSize = [int64]$file.Length
                        SHA256 = $hash.Hash.ToLowerInvariant()
                    }
                })
                $nics = @(Get-VMNetworkAdapter -VM $vm | Sort-Object Name | ForEach-Object {
                    [pscustomobject]@{
                        Name = $_.Name
                        SwitchName = $_.SwitchName
                        MacAddress = $_.MacAddress
                        Status = [string]$_.Status
                        IPAddresses = @($_.IPAddresses)
                    }
                })
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
                    Checkpoints = $checkpoints
                    AssignableDevices = $dda
                    TpmEnabled = if ($security) { [bool]$security.TpmEnabled } else { $false }
                    Shielded = if ($security) { [bool]$security.Shielded } else { $false }
                    SecureBoot = if ($firmware) { ([string]$firmware.SecureBoot) -eq 'On' } else { $false }
                    Disks = $disks
                    NICs = $nics
                } | ConvertTo-Json -Depth 8 -Compress
            POWERSHELL
            @metadata = @transport.powershell_json(script, timeout: 3600)
            validate_metadata!(@metadata)
            @metadata
        end

        def download_disks(work_dir, timeout: nil)
            raise Error, 'Hyper-V metadata has not been inspected' unless @metadata

            transfer_dir = File.join(work_dir, 'hyperv-source')
            FileUtils.mkdir_p(transfer_dir)
            @metadata.fetch('Disks').each_with_index.map do |disk, index|
                ext = File.extname(disk.fetch('Path').to_s).downcase
                ext = '.vhdx' unless ['.vhd', '.vhdx'].include?(ext)
                local_path = File.join(transfer_dir, format('disk-%02d%s', index, ext))
                @transport.stream_file(disk.fetch('Path'), local_path, timeout: timeout)
                expected_size = Integer(disk.fetch('FileSize'))
                actual_size = File.size(local_path)
                raise Error, "Hyper-V disk #{index} transfer size mismatch: expected #{expected_size}, got #{actual_size}" unless expected_size == actual_size

                expected_hash = disk.fetch('SHA256').to_s.downcase
                actual_hash = Digest::SHA256.file(local_path).hexdigest
                raise Error, "Hyper-V disk #{index} SHA-256 mismatch after transfer" unless expected_hash == actual_hash

                local_path
            end
        end

        def validate_metadata!(metadata)
            state = metadata.fetch('State').to_s
            raise Error, "Hyper-V source VM must be Off for production cold migration; current state is #{state}" unless state.casecmp('Off').zero?

            generation = Integer(metadata.fetch('Generation'))
            raise Error, "unsupported Hyper-V VM generation #{generation}" unless [1, 2].include?(generation)

            checkpoints = Array(metadata['Checkpoints'])
            raise Error, 'Hyper-V VM has checkpoints; merge/remove checkpoints before cold migration' unless checkpoints.empty?

            devices = Array(metadata['AssignableDevices'])
            raise Error, 'Hyper-V VM has Discrete Device Assignment devices; automatic cross-hypervisor device migration is not supported' unless devices.empty?

            raise Error, 'shielded Hyper-V VMs are not supported for cross-hypervisor migration' if Util.bool(metadata['Shielded'])
            raise Error, 'Hyper-V vTPM state is not portable; disable/decrypt vTPM-bound protection before migration' if Util.bool(metadata['TpmEnabled'])

            disks = Array(metadata['Disks'])
            raise Error, 'Hyper-V VM has no virtual hard disks' if disks.empty?
            disks.each_with_index do |disk, index|
                path = Util.require_text(disk['Path'], "Hyper-V disk #{index} path")
                extension = File.extname(path).downcase
                raise Error, "Hyper-V disk #{index} uses unsupported format #{extension.inspect}" unless ['.vhd', '.vhdx'].include?(extension)
                parent = disk['ParentPath'].to_s.strip
                raise Error, "Hyper-V disk #{index} is a differencing disk (parent #{parent}); merge it before migration" unless parent.empty?
                raise Error, "Hyper-V disk #{index} has invalid source hash" unless disk['SHA256'].to_s.match?(/\A[0-9a-fA-F]{64}\z/)
                raise Error, "Hyper-V disk #{index} has invalid file size" unless Integer(disk['FileSize']) > 0
                raise Error, "Hyper-V disk #{index} has invalid virtual size" unless Integer(disk['VirtualSize']) > 0
            end
            true
        rescue KeyError, ArgumentError, TypeError => e
            raise Error, "incomplete Hyper-V VM metadata: #{e.message}"
        end
    end

    class Converter
        def initialize(options)
            @options = options
        end

        def convert(vm_name, metadata, source_disks, work_dir)
            output_dir = File.join(work_dir, 'conversions')
            FileUtils.mkdir_p(output_dir)
            xml_path = File.join(work_dir, 'hyperv-source.xml')
            File.open(xml_path, 'w', 0o600) { |file| file.write(libvirt_xml(vm_name, metadata, source_disks)) }

            v2v = @options[:v2v_path].to_s.strip
            v2v = 'virt-v2v' if v2v.empty?
            format = @options[:format].to_s.strip
            format = 'qcow2' if format.empty?
            raise Error, "unsupported target disk format #{format.inspect}" unless %w[qcow2 raw].include?(format)

            argv = [v2v, '-v', '--machine-readable', '-i', 'libvirtxml', xml_path,
                    '-o', 'local', '-os', output_dir, '-of', format, '--root', (@options[:root] || 'first').to_s]
            env = {}
            libguestfs = @options[:libguestfs_path].to_s.strip
            env['LIBGUESTFS_PATH'] = libguestfs unless libguestfs.empty?

            stdout, stderr, status = Open3.capture3(env, *argv)
            $stdout.write(stdout) unless stdout.empty?
            $stderr.write(stderr) unless stderr.empty?
            raise Error, "virt-v2v failed for Hyper-V VM #{vm_name.inspect} with exit #{status.exitstatus}" unless status.success?

            disks = Dir.glob(File.join(output_dir, '*')).reject { |path| path.end_with?('.xml') || !File.file?(path) }.sort
            raise Error, 'virt-v2v completed but produced no converted disks' if disks.empty?

            disks
        end

        def libvirt_xml(vm_name, metadata, source_disks)
            memory_kib = Integer(metadata.fetch('MemoryStartupBytes')) / 1024
            vcpu = Integer(metadata.fetch('ProcessorCount'))
            raise Error, 'Hyper-V VM startup memory is invalid' if memory_kib <= 0
            raise Error, 'Hyper-V VM processor count is invalid' if vcpu <= 0

            generation = Integer(metadata.fetch('Generation'))
            os = if generation == 2
                     "<os firmware='efi'><type arch='x86_64' machine='q35'>hvm</type><boot dev='hd'/></os>"
                 else
                     "<os><type arch='x86_64'>hvm</type><boot dev='hd'/></os>"
                 end
            disk_xml = source_disks.each_with_index.map do |path, index|
                source = metadata.fetch('Disks').fetch(index)
                controller = source.fetch('ControllerType').to_s.upcase
                bus = controller == 'IDE' ? 'ide' : 'scsi'
                prefix = bus == 'ide' ? 'hd' : 'sd'
                suffix = disk_suffix(index)
                driver_type = File.extname(path).downcase == '.vhd' ? 'vpc' : 'vhdx'
                <<~XML
                    <disk type='file' device='disk'>
                      <driver name='qemu' type='#{driver_type}'/>
                      <source file='#{Util.escape_xml(path)}'/>
                      <target dev='#{prefix}#{suffix}' bus='#{bus}'/>
                    </disk>
                XML
            end.join

            <<~XML
                <domain type='kvm'>
                  <name>#{Util.escape_xml(vm_name)}</name>
                  <memory unit='KiB'>#{memory_kib}</memory>
                  <vcpu>#{vcpu}</vcpu>
                  #{os}
                  <features><acpi/><apic/></features>
                  <devices>
                    #{disk_xml}
                  </devices>
                </domain>
            XML
        rescue KeyError, ArgumentError, TypeError => e
            raise Error, "unable to build Hyper-V conversion domain: #{e.message}"
        end

        private

        def disk_suffix(index)
            n = index
            out = +''
            loop do
                out.prepend((97 + (n % 26)).chr)
                n = (n / 26) - 1
                break if n.negative?
            end
            out
        end
    end
end

class OneSwapHelper
    def hyperv_inventory(vm_name, options)
        send(:apply_verbosity, options) if respond_to?(:apply_verbosity, true)
        @options = options
        @options[:name] = OneSwapHyperV::Util.require_text(vm_name, 'Hyper-V VM name')
        profile = OneSwapHyperV::ConnectionProfile.from_options(@options)
        source = OneSwapHyperV::Source.new(OneSwapHyperV::SSHTransport.new(profile))
        source.inventory(@options[:name])
    end

    def hyperv_convert(vm_name, options)
        send(:apply_verbosity, options) if respond_to?(:apply_verbosity, true)
        @options = options
        @options[:name] = OneSwapHyperV::Util.require_text(vm_name, 'Hyper-V VM name')
        @options[:format] ||= 'qcow2'
        @options[:work_dir] ||= '/var/tmp'
        @options[:context] ||= '/usr/share/one/context'
        @options[:datastore] ||= 1
        @options[:v2v_path] ||= 'virt-v2v'
        @options[:virt_tools] ||= '/usr/local/share/virt-tools'
        @options[:root] ||= 'first'
        @options[:img_wait] ||= 120
        @options[:context_min_free] ||= 1024
        @options[:context_timeout] ||= 600

        safe_name = OneSwapHyperV::Util.safe_file_component(@options[:name])
        base_work_dir = File.expand_path(@options[:work_dir].to_s)
        @options[:work_dir] = File.join(base_work_dir, "oneswap-hyperv-#{safe_name}-#{SecureRandom.hex(6)}")
        FileUtils.mkdir_p(@options[:work_dir], mode: 0o700)

        profile = OneSwapHyperV::ConnectionProfile.from_options(@options)
        @hyperv_source_host = profile.host
        source = OneSwapHyperV::Source.new(OneSwapHyperV::SSHTransport.new(profile))

        puts "Inspecting Hyper-V VM #{@options[:name]} on #{profile.host}..."
        metadata = source.inspect(@options[:name])
        puts "Source is OFF and eligible for cold migration: #{metadata['ProcessorCount']} vCPU, " \
             "#{Integer(metadata['MemoryStartupBytes']) / (1024 * 1024)} MiB RAM, " \
             "#{Array(metadata['Disks']).length} disk(s), #{Array(metadata['NICs']).length} NIC(s)."

        transfer_timeout = @options[:hyperv_transfer_timeout].to_i
        transfer_timeout = nil if transfer_timeout <= 0
        source_disks = source.download_disks(@options[:work_dir], timeout: transfer_timeout)

        converted_disks = OneSwapHyperV::Converter.new(@options).convert(
            @options[:name], metadata, source_disks, @options[:work_dir]
        )

        # Reuse OneSwap's existing guest inspection/context/VirtIO/QEMU-GA and
        # OpenNebula Image import path. It returns tenant-owned Image IDs.
        local_path_image_allocation_preflight! if !@options[:http_transfer] && respond_to?(:local_path_image_allocation_preflight!, true)
        image_ids = create_one_images(converted_disks)
        template = hyperv_vm_template(metadata, image_ids)
        rc = template.allocate(template.to_xml)
        if OpenNebula.is_error?(rc)
            raise OneSwapHyperV::Error, "failed to allocate OpenNebula template #{@options[:name].inspect}: #{rc.message}"
        end
        send(:chown_one_object, template, *send(:resolve_one_ownership)) if respond_to?(:chown_one_object, true) && respond_to?(:resolve_one_ownership, true)
        puts "Created OpenNebula VM Template #{@options[:name]} (ID #{template.id}) from Hyper-V source #{metadata['VMId']}."

        FileUtils.rm_rf(@options[:work_dir]) if @options[:delete]
        template.id
    rescue OneSwapHyperV::Error => e
        raise ConversionError, e.message
    ensure
        # Do not delete failed work directories automatically. They are useful
        # for forensic reconciliation and prevent pretending a partial import
        # never happened. Successful cleanup is opt-in via --delete-after.
    end

    def hyperv_vm_template(metadata, image_ids)
        source_memory_mb = Integer(metadata.fetch('MemoryStartupBytes')) / (1024 * 1024)
        memory_mb = @options[:memory_mb] ? Integer(@options[:memory_mb]) : source_memory_mb
        cpu = Integer(metadata.fetch('ProcessorCount'))
        cpu_weight = @options[:cpu] || cpu
        vcpu = @options[:vcpu] || cpu
        raise OneSwapHyperV::Error, 'target memory must be greater than zero' unless memory_mb.positive?
        raise OneSwapHyperV::Error, 'target CPU scheduling weight must be greater than zero' unless cpu_weight.to_f.positive?
        raise OneSwapHyperV::Error, 'target VCPU count must be greater than zero' unless vcpu.to_i.positive?
        config = {
            'NAME' => @options[:name],
            'CPU' => cpu_weight.to_s,
            'VCPU' => vcpu.to_s,
            'MEMORY' => memory_mb.to_s,
            'HYPERVISOR' => 'kvm',
            'GRAPHICS' => {
                'TYPE' => (@options[:graphics_type] || 'VNC').to_s.upcase,
                'LISTEN' => (@options[:graphics_listen] || '0.0.0.0').to_s
            },
            'HYPERV_SOURCE_VM_ID' => metadata.fetch('VMId').to_s,
            'HYPERV_SOURCE_HOST' => @hyperv_source_host.to_s,
            'ONESWAP_SOURCE_PLATFORM' => 'HYPERV'
        }
        if @options[:qemu_ga_linux] || !@options[:qemu_ga_win].to_s.strip.empty?
            config['FEATURES'] = { 'GUEST_AGENT' => 'YES' }
        end
        unless @options[:disable_contextualization]
            config['CONTEXT'] = {
                'NETWORK' => 'YES',
                'SSH_PUBLIC_KEY' => '$USER[SSH_PUBLIC_KEY]'
            }
        end
        if OneSwapHyperV::Util.bool(metadata['DynamicMemoryEnabled'])
            maximum = Integer(metadata['MemoryMaximumBytes']) / (1024 * 1024)
            if maximum > memory_mb
                config['MEMORY_RESIZE_MODE'] = 'HOTPLUG'
                config['MEMORY_MAX'] = maximum.to_s
                config['HOT_RESIZE'] = { 'MEMORY_HOT_ADD_ENABLED' => 'YES' }
            end
        end
        config['CPU_MODEL'] = { 'MODEL' => @options[:cpu_model].to_s } if @options[:cpu_model]

        template = OpenNebula::Template.new(OpenNebula::Template.build_xml, @client)
        template.add_element('//VMTEMPLATE', config)

        image_ids.each_with_index do |image, index|
            disk = { 'IMAGE_ID' => image[:id].to_s }
            disk['DEV_PREFIX'] = (@options[:dev_prefix] || 'vd').to_s
            disk['TARGET'] = "vd#{hyperv_disk_suffix(index)}"
            template.add_element('//VMTEMPLATE', { 'DISK' => disk })
        end

        network_ids = @options[:network].to_s.split(',').map(&:strip).reject(&:empty?)
        nics = Array(metadata['NICs'])
        if nics.any?
            raise OneSwapHyperV::Error, 'Hyper-V import requires --network (or :network in OneSwap server config) when the source VM has NICs' if network_ids.empty?
            if network_ids.length != 1 && network_ids.length != nics.length
                raise OneSwapHyperV::Error, "number of OpenNebula networks (#{network_ids.length}) must be 1 or match Hyper-V NIC count (#{nics.length})"
            end
            network_ids = Array.new(nics.length, network_ids.first) if network_ids.length == 1
            nics.each_with_index do |nic, index|
                network_id = Integer(network_ids[index])
                raise OneSwapHyperV::Error, "invalid OpenNebula network ID #{network_ids[index].inspect}" if network_id.negative?
                entry = { 'NETWORK_ID' => network_id.to_s }
                mac = nic['MacAddress'].to_s.gsub(/[^0-9A-Fa-f]/, '')
                if !@options[:skip_mac] && mac.match?(/\A[0-9A-Fa-f]{12}\z/)
                    entry['MAC'] = mac.scan(/../).join(':').downcase
                end
                template.add_element('//VMTEMPLATE', { 'NIC' => entry })
            end
        end

        generation = Integer(metadata.fetch('Generation'))
        if generation == 2
            secure = OneSwapHyperV::Util.bool(metadata['SecureBoot'])
            path = secure ? @options[:uefi_sec_path] : @options[:uefi_path]
            path = secure ? '/usr/share/OVMF/OVMF_CODE_4M.secboot.fd' : '/usr/share/OVMF/OVMF_CODE_4M.fd' if path.to_s.strip.empty?
            os = { 'ARCH' => 'x86_64', 'MACHINE' => 'q35', 'FIRMWARE' => path.to_s }
            os['FIRMWARE_SECURE'] = 'YES' if secure
            template.add_element('//VMTEMPLATE', { 'OS' => os })
        else
            template.add_element('//VMTEMPLATE', { 'OS' => { 'ARCH' => 'x86_64', 'FIRMWARE' => 'BIOS' } })
        end

        send(:template_scheduling, template) if respond_to?(:template_scheduling, true)
        template
    rescue KeyError, ArgumentError, TypeError => e
        raise OneSwapHyperV::Error, "unable to build OpenNebula Hyper-V template: #{e.message}"
    end

    def hyperv_disk_suffix(index)
        n = index
        out = +''
        loop do
            out.prepend((97 + (n % 26)).chr)
            n = (n / 26) - 1
            break if n.negative?
        end
        out
    end
end
