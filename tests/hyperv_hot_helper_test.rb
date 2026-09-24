require 'minitest/autorun'
require 'tmpdir'
class ConversionError < StandardError; end unless defined?(ConversionError)
class OneSwapHelper; end unless defined?(OneSwapHelper)
require_relative '../hyperv_helper'
require_relative '../hyperv_hot_helper'

class HyperVHotHelperTest < Minitest::Test
  def eligible
    {
      'Name'=>'hv01','VMId'=>'11111111-1111-1111-1111-111111111111','State'=>'Running','Generation'=>2,
      'ProcessorCount'=>4,'MemoryStartupBytes'=>8*1024*1024*1024,'DynamicMemoryEnabled'=>false,
      'MemoryMinimumBytes'=>8*1024*1024*1024,'MemoryMaximumBytes'=>8*1024*1024*1024,
      'AutomaticCheckpointsEnabled'=>false,'ExposeVirtualizationExtensions'=>false,
      'HostBuildNumber'=>20348,'RCTReferencePointClass'=>true,'RCTImageManagementClass'=>true,
      'StagingFreeBytes'=>100*1024*1024*1024,'Checkpoints'=>[],'AssignableDevices'=>[],
      'GpuPartitionAdapters'=>[],'FibreChannelAdapters'=>[],'TpmEnabled'=>false,'Shielded'=>false,
      'SecureBoot'=>true,
      'Disks'=>[{'Path'=>'C:\\VMs\\disk.vhdx','ControllerType'=>'SCSI','ControllerNumber'=>0,
                 'ControllerLocation'=>0,'VhdFormat'=>'VHDX','VhdType'=>'Dynamic','ParentPath'=>'',
                 'VirtualDiskId'=>'22222222-2222-2222-2222-222222222222','VirtualSize'=>16*1024*1024,
                 'FileSize'=>1024}],
      'NICs'=>[{'Name'=>'Network Adapter','SwitchName'=>'Prod','MacAddress'=>'00155D010203',
                'Status'=>'Ok','VlanMode'=>'Access','AccessVlanId'=>120,'NativeVlanId'=>0}]
    }
  end

  def source
    OneSwapHyperV::HotSource.allocate
  end

  def test_hot_preflight_requires_running_rct_capable_safe_vm
    assert source.validate!(eligible, require_state: 'Running')
    m=eligible; m['State']='Off'
    assert_raises(OneSwapHyperV::Error){ source.validate!(m, require_state: 'Running') }
    m=eligible; m['HostBuildNumber']=9600
    assert_raises(OneSwapHyperV::Error){ source.validate!(m, require_state: 'Running') }
  end

  def test_hot_preflight_blocks_nonportable_devices_and_topology
    %w[AutomaticCheckpointsEnabled ExposeVirtualizationExtensions TpmEnabled Shielded].each do |field|
      m=eligible; m[field]=true
      assert_raises(OneSwapHyperV::Error, field){ source.validate!(m, require_state: 'Running') }
    end
    {'GpuPartitionAdapters'=>[{}], 'FibreChannelAdapters'=>[{}], 'AssignableDevices'=>[{}], 'Checkpoints'=>[{}]}.each do |field,value|
      m=eligible; m[field]=value
      assert_raises(OneSwapHyperV::Error, field){ source.validate!(m, require_state: 'Running') }
    end
  end

  def test_hot_preflight_requires_flat_vhdx
    m=eligible; m['Disks'][0]['Path']='C:\\VMs\\disk.vhd'; m['Disks'][0]['VhdFormat']='VHD'
    assert_raises(OneSwapHyperV::Error){ source.validate!(m, require_state: 'Running') }
    m=eligible; m['Disks'][0]['ParentPath']='C:\\VMs\\parent.vhdx'; m['Disks'][0]['VhdType']='Differencing'
    assert_raises(OneSwapHyperV::Error){ source.validate!(m, require_state: 'Running') }
  end

  def test_delta_applier_patches_only_declared_ranges
    Dir.mktmpdir do |dir|
      raw=File.join(dir,'disk.raw'); File.binwrite(raw, "\0"*32)
      bundle=File.join(dir,'delta.lshv')
      File.open(bundle,'wb') do |f|
        f.write(OneSwapHyperV::DELTA_MAGIC); f.write([32].pack('q<')); f.write([2].pack('l<'))
        f.write([4,3].pack('q<q<')); f.write('ABC'); f.write([20,4].pack('q<q<')); f.write('WXYZ')
      end
      assert OneSwapHyperV::DeltaApplier.apply!(bundle,raw,32)
      data=File.binread(raw)
      assert_equal 'ABC', data.byteslice(4,3)
      assert_equal 'WXYZ', data.byteslice(20,4)
      assert_equal "\0"*4, data.byteslice(0,4)
    end
  end

  def test_delta_applier_rejects_out_of_bounds_and_trailing_data
    Dir.mktmpdir do |dir|
      raw=File.join(dir,'disk.raw'); File.binwrite(raw,"\0"*16)
      bad=File.join(dir,'bad.lshv')
      File.open(bad,'wb'){|f| f.write(OneSwapHyperV::DELTA_MAGIC);f.write([16].pack('q<'));f.write([1].pack('l<'));f.write([15,2].pack('q<q<'));f.write('XX')}
      assert_raises(OneSwapHyperV::Error){ OneSwapHyperV::DeltaApplier.apply!(bad,raw,16) }
      trail=File.join(dir,'trail.lshv')
      File.open(trail,'wb'){|f| f.write(OneSwapHyperV::DELTA_MAGIC);f.write([16].pack('q<'));f.write([0].pack('l<'));f.write('x')}
      assert_raises(OneSwapHyperV::Error){ OneSwapHyperV::DeltaApplier.apply!(trail,raw,16) }
    end
  end

  def test_hot_operation_id_is_bounded_and_safe
    assert_equal 'op:123-abc', OneSwapHyperV::HotUtil.operation_id!({operation_id:'op:123-abc'})
    assert_raises(OneSwapHyperV::Error){ OneSwapHyperV::HotUtil.operation_id!({operation_id:"bad\nvalue"}) }
  end
  def test_preflight_inventory_reports_authoritative_disk_bytes_and_nic_count
    coordinator=OneSwapHyperV::HotCoordinator.allocate
    metadata=eligible
    metadata['Disks'] << metadata['Disks'][0].merge('Path'=>'C:\VMs\data.vhdx','VirtualSize'=>8*1024*1024)
    inventory=coordinator.source_inventory(metadata)
    assert_equal 24*1024*1024, inventory['source_disk_bytes']
    assert_equal 1, inventory['source_nic_count']
    assert_equal 'Running', inventory['source_state']
    assert_equal 2, inventory['generation']
    assert_equal true, inventory['secure_boot']
  end

  def test_reference_prepare_uses_backup_checkpoint_export_then_rct_conversion
    source = File.read(File.expand_path('../hyperv_hot_helper.rb', __dir__))
    create_pos = source.index("SnapshotType=[uint16]32768")
    export_pos = source.index("Invoke-CimMethod -MethodName ExportSystemDefinition")
    convert_pos = source.index("Invoke-CimMethod -MethodName ConvertToReferencePoint")
    rct_pos = source.index('$rctIds=@($ref.ResilientChangeTrackingIdentifiers)')
    refute_nil create_pos
    refute_nil export_pos
    refute_nil convert_pos
    refute_nil rct_pos
    assert_operator create_pos, :<, export_pos
    assert_operator export_pos, :<, convert_pos
    assert_operator convert_pos, :<, rct_pos
    assert_includes source, 'CopySnapshotConfiguration=[uint16]3'
    assert_includes source, 'CopyVmStorage=$true'
    assert_includes source, "VirtualSystemType -eq 'Microsoft:Hyper-V:Snapshot:Recovery'"
    assert_includes source, '$paths=@(Get-ChildItem -LiteralPath $exportDir -Recurse -File -Filter'
    assert_includes source, "Invoke-CimMethod -MethodName DestroySnapshot"
    assert_includes source, "Invoke-CimMethod -MethodName DestroyReferencePoint"
    assert_includes source, 'converted RCT identifier is empty for disk index'
    refute_includes source, '$svc.ExportReferencePoint'
  end

  def test_reference_prepare_generated_script_preserves_cim_namespace
    source = OneSwapHyperV::HotSource.allocate
    script = source.send(:reference_prepare_script, '', '', '', 1)
    assert_includes script, "$ns='root\\virtualization\\v2'"
    refute_includes script, "\v"
    assert_includes script, '$slash=[string][char]92'
    assert_includes script, '$escapedValue=$value.Replace($slash,$slash+$slash)'
    refute_includes script, ".Replace('','"
    assert_includes script, "if ($instanceId -match '\\\\([0-9]+)\\\\([0-9]+)\\\\L  end

end
) {"
    refute_includes script, "if ($instanceId -match '\\([0-9]+)\\([0-9]+)\\L  end

end
) {"
  end

end
