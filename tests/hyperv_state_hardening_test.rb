require 'minitest/autorun'
require 'tmpdir'

class ConversionError < StandardError; end unless defined?(ConversionError)
class OneSwapHelper; end unless defined?(OneSwapHelper)

require_relative '../hyperv_state_hardening'

class HyperVStateHardeningTest < Minitest::Test
  def test_canonical_json_preserves_false_and_nil_distinctly
    false_json = OneSwapHyperV::HotUtil.canonical_json({ 'flag' => false })
    nil_json = OneSwapHyperV::HotUtil.canonical_json({ 'flag' => nil })
    refute_equal false_json, nil_json
    assert_equal '{"flag":false}', false_json
    assert_equal '{"flag":null}', nil_json
  end

  def test_canonical_json_rejects_ambiguous_symbol_and_string_keys
    error = assert_raises(OneSwapHyperV::Error) do
      OneSwapHyperV::HotUtil.canonical_json({ 'phase' => 'A', :phase => 'B' })
    end
    assert_match(/ambiguous durable-state key/, error.message)
  end

  def test_atomic_state_write_is_owner_only_and_round_trips
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'state', 'hot-state.json')
      value = { 'phase' => 'SOURCE_OFF', 'flag' => false, 'count' => 1 }
      assert OneSwapHyperV::HotUtil.write_json_atomic(path, value)
      assert_equal value, JSON.parse(File.read(path))
      assert_equal 0o600, File.stat(path).mode & 0o777
      assert_equal 0o700, File.stat(File.dirname(path)).mode & 0o777
    end
  end
end
