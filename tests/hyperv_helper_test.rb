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
  def test_target_sizing_cli_and_template_contract
    cli=File.read(File.expand_path('../oneswap-hyperv', __dir__))
    helper=File.read(File.expand_path('../hyperv_helper.rb', __dir__))
    assert_includes cli, "opts.on('--cpu CPU', Float"
    assert_includes cli, "opts.on('--memory-mb MB', Integer"
    assert_includes helper, '@options[:memory_mb]'
    assert_includes helper, "'CPU' => cpu_weight.to_s"
    assert_includes helper, "'VCPU' => vcpu.to_s"
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

  def test_large_powershell_requires_remote_file_transport
    script = "$x='a'\n" + ("Write-Output $x\n" * 2_000)
    error = assert_raises(OneSwapHyperV::Error) do
      transport.send(:powershell_invocation, script)
    end
    assert_includes error.message, 'remote-file transport'
    assert_operator OneSwapHyperV::Util.powershell_encoded(script).bytesize,
                    :>,
                    OneSwapHyperV::SSHTransport::POWERSHELL_ENCODED_COMMAND_MAX_BYTES

    helper = File.read(File.expand_path('../hyperv_helper.rb', __dir__))
    assert_includes helper, 'run_remote_script_capture'
    assert_includes helper, "'scp', '-q'"
    assert_includes helper, "Join-Path $HOME"
    refute_includes helper, "['-Command', '-']"
  end
end

class HyperVSSHKeepaliveTest < Minitest::Test
  FakeProfile = Struct.new(:known_hosts, :port, :identity_file, :destination)

  def test_powershell_transport_sets_bounded_ssh_keepalives
    transport = OneSwapHyperV::SSHTransport.new(
      FakeProfile.new('/tmp/known_hosts', 22, '/tmp/id_ed25519', 'user@host')
    )
    argv, = transport.send(:powershell_invocation, "Write-Output 'ok'")
    joined = argv.join(' ')
    assert_includes joined, 'ServerAliveInterval=15'
    assert_includes joined, 'ServerAliveCountMax=4'
    assert_includes joined, 'TCPKeepAlive=yes'
  end
end
