# -------------------------------------------------------------------------- #
# Copyright 2002-2026, OpenNebula Project / LayerSentry downstream           #
# Licensed under the Apache License, Version 2.0.                             #
# -------------------------------------------------------------------------- #

# Edge hardening loaded after hyperv_hot_hardening.rb. PowerShell pipelines
# enumerate arrays, so piping @() to ConvertTo-Json can produce no output for a
# VM with zero NICs. Use -InputObject to preserve [] and keep networkless VMs
# valid while still capturing the complete VLAN topology for VMs with NICs.

require 'base64'
require_relative 'hyperv_hot_hardening'

module OneSwapHyperV
    class HotSource
        private

        def inspect_full_vlan_topology(vm_name)
            name64 = Base64.strict_encode64(Util.require_text(vm_name, 'Hyper-V VM name').encode(Encoding::UTF_8))
            script = <<~POWERSHELL
                $ErrorActionPreference='Stop'
                [Console]::OutputEncoding=[Text.Encoding]::UTF8
                $name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('#{name64}'))
                $vm=Get-VM -Name $name -ErrorAction Stop
                $nics=@(Get-VMNetworkAdapter -VM $vm | Sort-Object Name | ForEach-Object {
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
                })
                ConvertTo-Json -InputObject $nics -Depth 5 -Compress
            POWERSHELL
            parsed = @transport.powershell_json(script, timeout: 120)
            raise Error, 'Hyper-V VLAN topology response is not an array' unless parsed.is_a?(Array)

            parsed
        end
    end
end
