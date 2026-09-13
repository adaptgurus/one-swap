require 'minitest/autorun'
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
require_relative '../hyperv_final_safety_hardening'

class FinalSafetyImage
  attr_reader :id

  def initialize(id, values)
    @id = id
    @values = values
  end

  def [](key)
    @values[key]
  end
end

class FinalSafetyTemplate
  attr_reader :id

  def initialize(id, values, image_ids)
    @id = id
    @values = values
    disks = image_ids.map { |image_id| "<DISK><IMAGE_ID>#{image_id}</IMAGE_ID></DISK>" }.join
    @xml = "<VMTEMPLATE><TEMPLATE>#{disks}</TEMPLATE></VMTEMPLATE>"
  end

  def [](key)
    @values[key]
  end

  def to_xml
    @xml
  end
end

class HyperVFinalSafetyHardeningTest < Minitest::Test
  def coordinator(options = {})
    value = OneSwapHyperV::HotCoordinator.allocate
    value.instance_variable_set(:@options, options)
    value.instance_variable_set(:@operation_id, 'op-1')
    value
  end

  def test_trusted_artifact_digest_changes_when_content_changes
    Dir.mktmpdir do |dir|
      artifact = File.join(dir, 'OVMF_CODE.secboot.fd')
      File.write(artifact, 'firmware-v1')
      c = coordinator
      first = c.send(:trusted_artifact_digest, artifact, 'firmware')
      File.write(artifact, 'firmware-v2')
      second = c.send(:trusted_artifact_digest, artifact, 'firmware')
      refute_equal first, second
    end
  end

  def test_trusted_artifact_digest_rejects_group_writable_file
    skip 'POSIX mode semantics required' if Gem.win_platform?
    Dir.mktmpdir do |dir|
      artifact = File.join(dir, 'virtio.iso')
      File.write(artifact, 'bundle')
      File.chmod(0o664, artifact)
      error = assert_raises(OneSwapHyperV::Error) do
        coordinator.send(:trusted_artifact_digest, artifact, 'virtio-win bundle')
      end
      assert_match(/writable by group\/other/, error.message)
    end
  end

  def test_plain_http_disk_transfer_is_rejected
    error = assert_raises(OneSwapHyperV::Error) do
      coordinator(:http_transfer => true).send(:validate_production_transfer_security!)
    end
    assert_match(/not production-qualified/, error.message)
  end

  def test_recovered_image_must_match_source_vm_platform_and_datastore
    c = coordinator(:datastore => '17')
    c.instance_variable_set(:@layersentry_recovery_state, { 'source_vm_id' => 'vm-guid-1' })
    image = FinalSafetyImage.new(55, {
      'TEMPLATE/LAYERSENTRY_OPERATION_ID' => 'op-1',
      'TEMPLATE/LAYERSENTRY_DISK_INDEX' => '0',
      'TEMPLATE/LAYERSENTRY_SOURCE_VM_ID' => 'vm-guid-1',
      'TEMPLATE/LAYERSENTRY_SOURCE_PLATFORM' => 'HYPERV',
      'DATASTORE_ID' => '17'
    })
    assert c.send(:validate_image_marker!, image, 0)

    wrong = FinalSafetyImage.new(56, {
      'TEMPLATE/LAYERSENTRY_OPERATION_ID' => 'op-1',
      'TEMPLATE/LAYERSENTRY_DISK_INDEX' => '0',
      'TEMPLATE/LAYERSENTRY_SOURCE_VM_ID' => 'other-vm',
      'TEMPLATE/LAYERSENTRY_SOURCE_PLATFORM' => 'HYPERV',
      'DATASTORE_ID' => '17'
    })
    error = assert_raises(OneSwapHyperV::Error) { c.send(:validate_image_marker!, wrong, 0) }
    assert_match(/source VM marker mismatch/, error.message)
  end

  def test_recovered_image_rejects_wrong_datastore
    c = coordinator(:datastore => '17')
    c.instance_variable_set(:@layersentry_recovery_state, { 'source_vm_id' => 'vm-guid-1' })
    image = FinalSafetyImage.new(57, {
      'TEMPLATE/LAYERSENTRY_OPERATION_ID' => 'op-1',
      'TEMPLATE/LAYERSENTRY_DISK_INDEX' => '0',
      'TEMPLATE/LAYERSENTRY_SOURCE_VM_ID' => 'vm-guid-1',
      'TEMPLATE/LAYERSENTRY_SOURCE_PLATFORM' => 'HYPERV',
      'DATASTORE_ID' => '99'
    })
    error = assert_raises(OneSwapHyperV::Error) { c.send(:validate_image_marker!, image, 0) }
    assert_match(/datastore mismatch/, error.message)
  end

  def test_recovered_template_must_bind_exact_image_set
    c = coordinator
    c.instance_variable_set(:@layersentry_expected_template_image_ids, [11, 12])
    state = { 'source_vm_id' => 'vm-guid-1' }
    template = FinalSafetyTemplate.new(90, {
      'TEMPLATE/LAYERSENTRY_OPERATION_ID' => 'op-1',
      'TEMPLATE/LAYERSENTRY_SOURCE_VM_ID' => 'vm-guid-1',
      'TEMPLATE/LAYERSENTRY_SOURCE_PLATFORM' => 'HYPERV'
    }, [11, 99])
    error = assert_raises(OneSwapHyperV::Error) do
      c.send(:validate_template_marker!, template, state)
    end
    assert_match(/disk image-set mismatch/, error.message)
  end
end
