require 'minitest/autorun'
require 'tmpdir'

# Source tests do not require an installed OpenNebula Ruby package. The actual
# oneswap-hyperv CLI loads `opennebula` before these helpers. Mark pool features
# as loaded here so recovery helpers can be source-tested with lightweight stubs.
$LOADED_FEATURES << 'opennebula/image_pool.rb' unless $LOADED_FEATURES.include?('opennebula/image_pool.rb')
$LOADED_FEATURES << 'opennebula/template_pool.rb' unless $LOADED_FEATURES.include?('opennebula/template_pool.rb')
module OpenNebula
  class ImagePool; end unless const_defined?(:ImagePool)
  class TemplatePool; end unless const_defined?(:TemplatePool)
end

class ConversionError < StandardError; end unless defined?(ConversionError)
class OneSwapHelper; end unless defined?(OneSwapHelper)
require_relative '../hyperv_virtio_hardening'

class HyperVVirtIOHardeningTest < Minitest::Test
  def test_explicit_readable_virtio_directory_is_selected
    Dir.mktmpdir do |dir|
      coordinator = OneSwapHyperV::HotCoordinator.allocate
      coordinator.instance_variable_set(:@options, { :virtio_path => dir })
      assert_equal File.expand_path(dir), coordinator.send(:resolve_virtio_win!)
    end
  end

  def test_missing_virtio_bundle_fails_closed_for_windows
    coordinator = OneSwapHyperV::HotCoordinator.allocate
    coordinator.instance_variable_set(:@options, { :virtio_path => '/definitely/not/a/virtio/bundle' })
    old = ENV.delete('VIRTIO_WIN')
    begin
      error = assert_raises(OneSwapHyperV::Error) { coordinator.send(:resolve_virtio_win!) }
      assert_match(/virtio-win bundle/, error.message)
    ensure
      ENV['VIRTIO_WIN'] = old if old
    end
  end

  def test_expected_guest_macs_are_canonical_and_sorted
    coordinator = OneSwapHyperV::HotCoordinator.allocate
    coordinator.instance_variable_set(:@options, {
      :expected_guest_macs => '00-15-5D-01-02-04,00:15:5d:01:02:03,00:15:5d:01:02:03'
    })
    assert_equal ['00:15:5d:01:02:03', '00:15:5d:01:02:04'],
                 coordinator.send(:normalized_expected_guest_macs)
  end

  def test_expected_guest_mac_parser_rejects_embedded_junk
    coordinator = OneSwapHyperV::HotCoordinator.allocate
    coordinator.instance_variable_set(:@options, {
      :expected_guest_macs => 'junk00:15:5d:01:02:03more'
    })
    assert_raises(OneSwapHyperV::Error) do
      coordinator.send(:normalized_expected_guest_macs)
    end
  end

  def test_guest_mac_binding_accepts_hyperv_source_macs_with_extra_guest_virtual_mac
    coordinator = OneSwapHyperV::HotCoordinator.allocate
    coordinator.instance_variable_set(:@options, {
      :guest_os => 'linux',
      :expected_guest_macs => '00:15:5d:01:02:03,02:42:ac:11:00:02'
    })
    metadata = { 'NICs' => [{ 'MacAddress' => '00155D010203' }] }
    assert coordinator.send(:validate_guest_mac_binding!, metadata)
  end

  def test_agent_driven_guest_mac_binding_rejects_missing_evidence_when_source_has_nics
    coordinator = OneSwapHyperV::HotCoordinator.allocate
    coordinator.instance_variable_set(:@options, {
      :guest_os => 'windows',
      :expected_guest_macs => ''
    })
    metadata = { 'NICs' => [{ 'MacAddress' => '00155D010203' }] }
    error = assert_raises(OneSwapHyperV::Error) do
      coordinator.send(:validate_guest_mac_binding!, metadata)
    end
    assert_match(/requires guest MAC evidence/, error.message)
  end

  def test_guest_mac_binding_rejects_duplicate_source_macs
    coordinator = OneSwapHyperV::HotCoordinator.allocate
    coordinator.instance_variable_set(:@options, {
      :guest_os => 'linux',
      :expected_guest_macs => '00:15:5d:01:02:03'
    })
    metadata = {
      'NICs' => [
        { 'MacAddress' => '00155D010203' },
        { 'MacAddress' => '00-15-5D-01-02-03' }
      ]
    }
    error = assert_raises(OneSwapHyperV::Error) do
      coordinator.send(:validate_guest_mac_binding!, metadata)
    end
    assert_match(/duplicate NIC MAC/, error.message)
  end

  def test_guest_mac_binding_rejects_wrong_agent_or_changed_source_mac
    coordinator = OneSwapHyperV::HotCoordinator.allocate
    coordinator.instance_variable_set(:@options, {
      :guest_os => 'windows',
      :expected_guest_macs => '00:15:5d:01:02:04'
    })
    metadata = { 'NICs' => [{ 'MacAddress' => '00-15-5D-01-02-03' }] }
    error = assert_raises(OneSwapHyperV::Error) do
      coordinator.send(:validate_guest_mac_binding!, metadata)
    end
    assert_match(/guest agent MAC inventory does not match/, error.message)
  end

  def test_windows_secure_boot_requires_qualified_windows_template_and_explicit_firmware
    Dir.mktmpdir do |dir|
      firmware = File.join(dir, 'OVMF_CODE.secboot.fd')
      File.write(firmware, 'test firmware')
      coordinator = OneSwapHyperV::HotCoordinator.allocate
      coordinator.instance_variable_set(:@options, { :guest_os => 'windows', :uefi_sec_path => firmware })
      metadata = { 'SecureBoot' => true, 'SecureBootTemplate' => 'MicrosoftWindows' }
      assert coordinator.send(:validate_secure_boot_target!, metadata)
    end
  end

  def test_linux_secure_boot_requires_microsoft_uefi_ca_template
    Dir.mktmpdir do |dir|
      firmware = File.join(dir, 'OVMF_CODE.secboot.fd')
      File.write(firmware, 'test firmware')
      coordinator = OneSwapHyperV::HotCoordinator.allocate
      coordinator.instance_variable_set(:@options, { :guest_os => 'linux', :uefi_sec_path => firmware })
      metadata = { 'SecureBoot' => true, 'SecureBootTemplate' => 'MicrosoftUEFICertificateAuthority' }
      assert coordinator.send(:validate_secure_boot_target!, metadata)
    end
  end

  def test_secure_boot_rejects_missing_explicit_target_firmware
    coordinator = OneSwapHyperV::HotCoordinator.allocate
    coordinator.instance_variable_set(:@options, { :guest_os => 'windows', :uefi_sec_path => '' })
    metadata = { 'SecureBoot' => true, 'SecureBootTemplate' => 'MicrosoftWindows' }
    error = assert_raises(OneSwapHyperV::Error) do
      coordinator.send(:validate_secure_boot_target!, metadata)
    end
    assert_match(/explicit qualified --uefi-sec-path/, error.message)
  end

  def test_secure_boot_rejects_source_template_guest_family_mismatch
    Dir.mktmpdir do |dir|
      firmware = File.join(dir, 'OVMF_CODE.secboot.fd')
      File.write(firmware, 'test firmware')
      coordinator = OneSwapHyperV::HotCoordinator.allocate
      coordinator.instance_variable_set(:@options, { :guest_os => 'linux', :uefi_sec_path => firmware })
      metadata = { 'SecureBoot' => true, 'SecureBootTemplate' => 'MicrosoftWindows' }
      error = assert_raises(OneSwapHyperV::Error) do
        coordinator.send(:validate_secure_boot_target!, metadata)
      end
      assert_match(/not qualified for agent-authoritative linux/, error.message)
    end
  end
end
