# -------------------------------------------------------------------------- #
# LayerSentry Hyper-V source security/device authority hardening              #
# -------------------------------------------------------------------------- #

require_relative 'hyperv_hot_hardening'

module OneSwapHyperV
    class HotSource
        unless method_defined?(:layersentry_inspect_before_source_security_hardening)
            alias_method :layersentry_inspect_before_source_security_hardening, :inspect
        end

        def inspect(vm_name, require_state: 'Running')
            metadata = layersentry_inspect_before_source_security_hardening(vm_name, require_state: require_state)
            authoritative = authoritative_security_and_device_probe(vm_name)
            metadata['Checkpoints'] = authoritative.fetch('Checkpoints')
            metadata['AssignableDevices'] = authoritative.fetch('AssignableDevices')
            metadata['GpuPartitionAdapters'] = authoritative.fetch('GpuPartitionAdapters')
            metadata['FibreChannelAdapters'] = authoritative.fetch('FibreChannelAdapters')
            metadata['TpmEnabled'] = authoritative.fetch('TpmEnabled')
            metadata['Shielded'] = authoritative.fetch('Shielded')
            metadata['SecureBoot'] = authoritative.fetch('SecureBoot')
            metadata['SecureBootTemplate'] = authoritative['SecureBootTemplate'].to_s
            metadata['SecureBootTemplateId'] = authoritative['SecureBootTemplateId'].to_s
            metadata['SecurityProbeAuthoritative'] = true
            validate!(metadata, require_state: require_state)
            if Util.bool(metadata['SecureBoot']) && metadata['SecureBootTemplate'].to_s.strip.empty?
                raise Error, 'Hyper-V Secure Boot is enabled but its Secure Boot template could not be determined authoritatively'
            end
            metadata
        end

        private

        def authoritative_security_and_device_probe(vm_name)
            name64 = Base64.strict_encode64(Util.require_text(vm_name, 'Hyper-V VM name').encode(Encoding::UTF_8))
            script = <<~POWERSHELL
                $ErrorActionPreference = 'Stop'
                $ProgressPreference = 'SilentlyContinue'
                $name = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{name64}'))
                $vm = Get-VM -Name $name -ErrorAction Stop
                $security = Get-VMSecurity -VM $vm -ErrorAction Stop
                $checkpoints = @(Get-VMSnapshot -VM $vm -ErrorAction Stop)
                $dda = if (Get-Command Get-VMAssignableDevice -ErrorAction SilentlyContinue) {
                    @(Get-VMAssignableDevice -VM $vm -ErrorAction Stop)
                } else { @() }
                $gpu = if (Get-Command Get-VMGpuPartitionAdapter -ErrorAction SilentlyContinue) {
                    @(Get-VMGpuPartitionAdapter -VMName $name -ErrorAction Stop)
                } else { @() }
                $fc = if (Get-Command Get-VMFibreChannelHba -ErrorAction SilentlyContinue) {
                    @(Get-VMFibreChannelHba -VMName $name -ErrorAction Stop)
                } else { @() }
                $firmware = $null
                if ([int]$vm.Generation -eq 2) {
                    $firmware = Get-VMFirmware -VM $vm -ErrorAction Stop
                }
                [pscustomobject]@{
                    Checkpoints = @($checkpoints | ForEach-Object { [pscustomobject]@{ Name=$_.Name; Id=$_.Id.Guid } })
                    AssignableDevices = @($dda | ForEach-Object { [pscustomobject]@{ InstancePath=$_.InstancePath; LocationPath=$_.LocationPath } })
                    GpuPartitionAdapters = @($gpu | ForEach-Object { [pscustomobject]@{ Name=$_.Name; InstancePath=$_.InstancePath } })
                    FibreChannelAdapters = @($fc | ForEach-Object { [pscustomobject]@{ SanName=$_.SanName; WorldWideNodeNameSetA=$_.WorldWideNodeNameSetA } })
                    TpmEnabled = [bool]$security.TpmEnabled
                    Shielded = [bool]$security.Shielded
                    SecureBoot = if ($firmware) { ([string]$firmware.SecureBoot) -eq 'On' } else { $false }
                    SecureBootTemplate = if ($firmware) { [string]$firmware.SecureBootTemplate } else { '' }
                    SecureBootTemplateId = if ($firmware) { [string]$firmware.SecureBootTemplateId } else { '' }
                } | ConvertTo-Json -Depth 8 -Compress
            POWERSHELL
            @transport.powershell_json(script, timeout: 300)
        rescue StandardError => e
            raise Error, "authoritative Hyper-V security/device discovery failed; migration is blocked: #{e.message}"
        end
    end

    class HotCoordinator
        unless method_defined?(:layersentry_stable_metadata_before_source_security_hardening)
            alias_method :layersentry_stable_metadata_before_source_security_hardening, :stable_metadata
        end

        private

        def stable_metadata(metadata)
            stable = layersentry_stable_metadata_before_source_security_hardening(metadata)
            stable['SecureBootTemplate'] = metadata['SecureBootTemplate'].to_s
            stable['SecureBootTemplateId'] = metadata['SecureBootTemplateId'].to_s
            stable['SecurityProbeAuthoritative'] = Util.bool(metadata['SecurityProbeAuthoritative'])
            stable
        end
    end
end
