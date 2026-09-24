require 'minitest/autorun'
class ConversionError < StandardError; end
class OneSwapHelper; end
require_relative '../hyperv_helper'

class HyperVHelperTest < Minitest::Test
  def eligible
    {
      'State'=>'Off','Generation'=>2,'ProcessorCount'=>4,'MemoryStartupBytes'=>8*1024*1024*1024,
      'DynamicMemoryEnabled'=>false,'Checkpoints'=>[],'AssignableDevices'=>[],
      'TpmEnabled'=>false,'Shielded'=>false,'SecureBoot'=>true,
      'Disks'=>[{'Path'=>'C:\\VMs\\disk.vhdx','ControllerType'=>'SCSI','ControllerNumber'=>0,
                 'ControllerLocation'=>0,'ParentPath'=>'','VirtualSize'=>20*1024*1024*1024,
                 'FileSize'=>1024,'SHA256'=>'a'*64}],
      'NICs'=>[],'VMId'=>'11111111-1111-1111-1111-111111111111'
    }
  end

  def test_rejects_running_vm
    m=eligible; m['State']='Running'
    source=OneSwapHyperV::Source.allocate
    assert_raises(OneSwapHyperV::Error){ source.validate_metadata!(m) }
  end

  def test_rejects_checkpoint_and_vtpm
    source=OneSwapHyperV::Source.allocate
    m=eligible; m['Checkpoints']=[{'Name'=>'cp'}]
    assert_raises(OneSwapHyperV::Error){ source.validate_metadata!(m) }
    m=eligible; m['TpmEnabled']=true
    assert_raises(OneSwapHyperV::Error){ source.validate_metadata!(m) }
  end

  def test_libvirt_xml_keeps_uefi_and_disk_type
    c=OneSwapHyperV::Converter.new({})
    xml=c.libvirt_xml('vm<&', eligible, ['/tmp/disk.vhdx'])
    assert_includes xml, "firmware='efi'"
    assert_includes xml, "type='vhdx'"
    assert_includes xml, 'vm&lt;&amp;'
  end
end


class HyperVSSHTransportCommandLengthTest < Minitest::Test
  FakeProfile = Struct.new(:known_hosts, :port, :identity_file, :destination)

  def transport
    OneSwapHyperV::SSHTransport.new(
      FakeProfile.new('/tmp/known_hosts', 22, '/tmp/id_ed25519', 'user@host')
    )
  end

  def test_small_powershell_uses_encoded_command
    argv, stdin_data = transport.send(:powershell_invocation, "Write-Output 'ok'")
    assert_includes argv, '-EncodedCommand'
    refute_includes argv, '-Command'
    assert_nil stdin_data
  end

  def test_large_powershell_uses_stdin_command_transport
    script = "$x='a'\n" + ("Write-Output $x\n" * 2_000)
    argv, stdin_data = transport.send(:powershell_invocation, script)
    assert_includes argv, '-EncodedCommand'
    refute_includes argv, '-Command'
    refute_equal OneSwapHyperV::Util.powershell_encoded(script), argv.last
    assert_equal script, stdin_data
    assert_operator OneSwapHyperV::Util.powershell_encoded(script).bytesize,
                    :>,
                    OneSwapHyperV::SSHTransport::POWERSHELL_ENCODED_COMMAND_MAX_BYTES
  end
end
