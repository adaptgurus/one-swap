require 'minitest/autorun'
require 'tmpdir'

$LOADED_FEATURES << 'opennebula/image_pool.rb' unless $LOADED_FEATURES.include?('opennebula/image_pool.rb')
$LOADED_FEATURES << 'opennebula/template_pool.rb' unless $LOADED_FEATURES.include?('opennebula/template_pool.rb')
module OpenNebula
  class ImagePool; end unless const_defined?(:ImagePool)
  class TemplatePool; end unless const_defined?(:TemplatePool)
end

class ConversionError < StandardError; end unless defined?(ConversionError)
class OneSwapHelper; end unless defined?(OneSwapHelper)
require_relative '../hyperv_import_recovery_hardening'

class HyperVImportRecoveryTest < Minitest::Test
  def test_recovery_phase_model_includes_durable_capture_apply_import_stages
    expected = %w[DELTA_CAPTURING DELTA_APPLYING MORPHING DELTA_APPLIED IMPORTING IMPORTED]
    expected.each do |phase|
      assert_includes OneSwapHyperV::HotCoordinator::HOT_RECOVERY_PHASES, phase
    end
  end

  def test_morphing_is_a_hard_no_replay_barrier
    Dir.mktmpdir do |dir|
      state_path = File.join(dir, 'state.json')
      OneSwapHyperV::HotUtil.write_json_atomic(state_path, {
        'operation_id' => 'op-1',
        'vm_name' => 'vm-1',
        'phase' => 'MORPHING'
      })
      coordinator = OneSwapHyperV::HotCoordinator.allocate
      coordinator.instance_variable_set(:@state_path, state_path)
      coordinator.instance_variable_set(:@operation_id, 'op-1')
      coordinator.instance_variable_set(:@vm_name, 'vm-1')
      coordinator.define_singleton_method(:validate_local_prerequisites!) { true }
      coordinator.define_singleton_method(:validate_state_identity!) { |_state| true }
      error = assert_raises(OneSwapHyperV::Error) { coordinator.commit }
      assert_match(/stopped during MORPHING/, error.message)
      assert_match(/automatic replay is prohibited/, error.message)
    end
  end

  def test_hot_image_name_is_operation_scoped_and_disk_scoped
    first = OneSwapHyperV::HotCoordinator.allocate
    first.instance_variable_set(:@vm_name, 'Web VM 01')
    first.instance_variable_set(:@operation_id, 'op-1')
    second = OneSwapHyperV::HotCoordinator.allocate
    second.instance_variable_set(:@vm_name, 'Web VM 01')
    second.instance_variable_set(:@operation_id, 'op-2')

    first_disk0 = first.send(:hot_image_name, 0)
    first_disk1 = first.send(:hot_image_name, 1)
    second_disk0 = second.send(:hot_image_name, 0)
    assert_equal first_disk0, first.send(:hot_image_name, 0)
    refute_equal first_disk0, first_disk1
    refute_equal first_disk0, second_disk0
    assert_match(/disk-0\z/, first_disk0)
  end
end
