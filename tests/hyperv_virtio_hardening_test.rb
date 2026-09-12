require 'minitest/autorun'
require 'tmpdir'
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

  def test_guest_mac_binding_accepts_hyperv_source_macs_with_extra_guest_virtual_mac
    coordinator = OneSwapHyperV::HotCoordinator.allocate
    coordinator.instance_variable_set(:@options, {
      :expected_guest_macs => '00:15:5d:01:02:03,02:42:ac:11:00:02'
    })
    metadata = { 'NICs' => [{ 'MacAddress' => '00155D010203' }] }
    assert coordinator.send(:validate_guest_mac_binding!, metadata)
  end

  def test_guest_mac_binding_rejects_wrong_agent_or_changed_source_mac
    coordinator = OneSwapHyperV::HotCoordinator.allocate
    coordinator.instance_variable_set(:@options, {
      :expected_guest_macs => '00:15:5d:01:02:04'
    })
    metadata = { 'NICs' => [{ 'MacAddress' => '00-15-5D-01-02-03' }] }
    error = assert_raises(OneSwapHyperV::Error) do
      coordinator.send(:validate_guest_mac_binding!, metadata)
    end
    assert_match(/guest agent MAC inventory does not match/, error.message)
  end
end
