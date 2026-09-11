require 'minitest/autorun'
require 'tmpdir'

class ConversionError < StandardError; end
class OneSwapHelper; end

require_relative '../hyperv_hot_helper'
require_relative '../hyperv_hot_hardening'

class HyperVHotHardeningTest < Minitest::Test
  def test_state_directory_is_collision_resistant
    Dir.mktmpdir do |dir|
      first = OneSwapHyperV::HotUtil.state_dir({ :work_dir => dir }, 'tenant:a_b')
      second = OneSwapHyperV::HotUtil.state_dir({ :work_dir => dir }, 'tenant_a:b')
      refute_equal first, second
      assert_match(/-[0-9a-f]{16}\z/, first)
      assert_match(/-[0-9a-f]{16}\z/, second)
    end
  end

  def test_stable_metadata_includes_full_vlan_topology
    coordinator = OneSwapHyperV::HotCoordinator.allocate
    metadata = {
      'Name' => 'vm', 'VMId' => 'id', 'Generation' => 2,
      'ProcessorCount' => 4, 'MemoryStartupBytes' => 4096,
      'DynamicMemoryEnabled' => false, 'MemoryMinimumBytes' => 4096,
      'MemoryMaximumBytes' => 4096, 'AutomaticCheckpointsEnabled' => false,
      'ExposeVirtualizationExtensions' => false, 'HostBuildNumber' => 20348,
      'AssignableDevices' => [], 'GpuPartitionAdapters' => [],
      'FibreChannelAdapters' => [], 'TpmEnabled' => false,
      'Shielded' => false, 'SecureBoot' => true,
      'Disks' => [],
      'NICs' => [{
        'Name' => 'nic0', 'SwitchName' => 'prod', 'MacAddress' => '00155D010203',
        'VlanMode' => 'Trunk', 'AccessVlanId' => 0, 'NativeVlanId' => 120,
        'AllowedVlanIdList' => '120-130', 'PrimaryVlanId' => 0,
        'SecondaryVlanId' => 0, 'SecondaryVlanIdList' => ''
      }]
    }

    stable = coordinator.send(:stable_metadata, metadata)
    nic = stable.fetch('NICs').first
    assert_equal '120-130', nic.fetch('AllowedVlanIdList')
    assert_equal 120, nic.fetch('NativeVlanId')
    assert nic.key?('PrimaryVlanId')
    assert nic.key?('SecondaryVlanId')
    assert nic.key?('SecondaryVlanIdList')
  end

  def test_hardening_uses_raw_baseline_before_guest_morph
    source = File.read(File.expand_path('../hyperv_hot_hardening.rb', __dir__))
    assert_includes source, "'qemu-img'"
    assert_includes source, "'-f', 'vhdx', '-O', 'raw'"
    assert_includes source, "state['phase'] = 'MORPHING'"
    assert_includes source, "state['phase'] = 'IMPORTING'"
    assert_includes source, "type='raw'"
    refute_match(/Wait-WmiJob\s+\$result\.Job.*GetVirtualDiskChanges/m, source)
  end
end
