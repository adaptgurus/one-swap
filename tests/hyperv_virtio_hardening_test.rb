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
end
