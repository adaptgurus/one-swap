require 'minitest/autorun'
require 'base64'
require 'json'
require 'tmpdir'

$LOADED_FEATURES << 'opennebula/image_pool.rb' unless $LOADED_FEATURES.include?('opennebula/image_pool.rb')
$LOADED_FEATURES << 'opennebula/template_pool.rb' unless $LOADED_FEATURES.include?('opennebula/template_pool.rb')
module OpenNebula
  class ImagePool; end unless const_defined?(:ImagePool)
  class TemplatePool; end unless const_defined?(:TemplatePool)
  def self.is_error?(_value); false; end unless respond_to?(:is_error?)
end

class ConversionError < StandardError; end unless defined?(ConversionError)
class OneSwapHelper; end unless defined?(OneSwapHelper)
require_relative '../hyperv_network_hardening'

class HyperVNetworkHardeningTest < Minitest::Test
  MAC = '00:15:5d:01:02:03'

  def encoded_profile(entries)
    Base64.urlsafe_encode64(JSON.generate(entries), padding: false)
  end

  def coordinator(options = {})
    c = OneSwapHyperV::HotCoordinator.allocate
    defaults = {
      :guest_os => 'windows',
      :expected_guest_macs => MAC,
      :guest_network_profile => encoded_profile([
        {
          'name' => 'Ethernet',
          'mac' => MAC,
          'dhcp' => 'disabled',
          'addresses' => ['10.10.10.20/24'],
          'gateways' => ['10.10.10.1'],
          'dns_servers' => ['10.10.10.53', '10.10.10.54']
        }
      ])
    }
    c.instance_variable_set(:@options, defaults.merge(options))
    c
  end

  def test_windows_static_profile_builds_virt_v2v_mac_ip_argument
    args = coordinator.send(:windows_static_ip_args)
    assert_equal ["#{MAC}:ip:10.10.10.20,10.10.10.1,24,10.10.10.53,10.10.10.54"], args
  end

  def test_windows_dhcp_profile_does_not_force_static_address
    profile = encoded_profile([
      {'name' => 'Ethernet', 'mac' => MAC, 'dhcp' => 'enabled', 'addresses' => ['10.10.10.20/24']}
    ])
    assert_empty coordinator(:guest_network_profile => profile).send(:windows_static_ip_args)
  end

  def test_agent_driven_migration_rejects_skip_mac
    c = coordinator(:skip_mac => true)
    c.define_singleton_method(:layersentry_validate_local_before_network_hardening) { true }
    error = assert_raises(OneSwapHyperV::Error) { c.validate_local_prerequisites! }
    assert_match(/requires source MAC preservation/, error.message)
  end

  def test_static_profile_rejects_multiple_ipv4_addresses
    profile = encoded_profile([
      {
        'name' => 'Ethernet', 'mac' => MAC, 'dhcp' => 'disabled',
        'addresses' => ['10.10.10.20/24', '10.10.10.21/24']
      }
    ])
    error = assert_raises(OneSwapHyperV::Error) do
      coordinator(:guest_network_profile => profile).send(:normalized_guest_network_profile)
    end
    assert_match(/exactly one qualified IPv4 CIDR/, error.message)
  end

  def test_static_profile_must_bind_to_authoritative_hyperv_nic
    c = coordinator
    metadata = {'NICs' => [{'MacAddress' => '00:15:5d:99:88:77'}]}
    error = assert_raises(OneSwapHyperV::Error) do
      c.send(:validate_guest_network_profile_binding!, metadata)
    end
    assert_match(/not an authoritative Hyper-V source NIC/, error.message)
  end

  def test_network_profile_normalization_is_deterministic
    one = coordinator.send(:normalized_guest_network_profile)
    profile = encoded_profile([
      {
        'dns_servers' => ['10.10.10.54', '10.10.10.53'],
        'gateways' => ['10.10.10.1'],
        'addresses' => ['10.10.10.20/24'],
        'dhcp' => 'disabled', 'mac' => '00-15-5D-01-02-03', 'name' => 'Ethernet'
      }
    ])
    two = coordinator(:guest_network_profile => profile).send(:normalized_guest_network_profile)
    assert_equal one, two
  end
end
