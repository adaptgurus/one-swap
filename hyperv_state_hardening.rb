# -------------------------------------------------------------------------- #
# LayerSentry Hyper-V durable hot-state hardening                             #
# -------------------------------------------------------------------------- #

require_relative 'hyperv_hot_hardening'

module OneSwapHyperV
    module HotUtil
        class << self
            def canonical_json(value)
                case value
                when Hash
                    groups = value.keys.group_by(&:to_s)
                    duplicate = groups.find { |_key, originals| originals.length > 1 }
                    if duplicate
                        raise Error, "ambiguous durable-state key #{duplicate.first.inspect} has both string/symbol forms"
                    end
                    '{' + groups.keys.sort.map do |key|
                        original = groups.fetch(key).first
                        JSON.generate(key) + ':' + canonical_json(value.fetch(original))
                    end.join(',') + '}'
                when Array
                    '[' + value.map { |item| canonical_json(item) }.join(',') + ']'
                else
                    JSON.generate(value)
                end
            end

            def write_json_atomic(path, value)
                directory = File.dirname(path)
                FileUtils.mkdir_p(directory, mode: 0o700)
                File.chmod(0o700, directory)
                tmp = "#{path}.#{Process.pid}.#{SecureRandom.hex(4)}.tmp"
                File.open(tmp, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
                    file.write(JSON.pretty_generate(value))
                    file.write("\n")
                    file.flush
                    file.fsync
                end
                File.rename(tmp, path)
                File.chmod(0o600, path)
                File.open(directory, 'r') { |dir| dir.fsync }
                true
            ensure
                FileUtils.rm_f(tmp) if defined?(tmp) && tmp && File.exist?(tmp)
            end
        end
    end
end
