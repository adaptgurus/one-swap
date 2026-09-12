# -------------------------------------------------------------------------- #
# LayerSentry Hyper-V VirtIO production qualification                        #
# -------------------------------------------------------------------------- #

require_relative 'hyperv_source_security_hardening'

module OneSwapHyperV
    class HotCoordinator
        unless method_defined?(:layersentry_hot_validate_before_virtio_hardening)
            alias_method :layersentry_hot_validate_before_virtio_hardening, :validate_local_prerequisites!
            alias_method :layersentry_hot_morph_before_virtio_hardening, :rerun_v2v_in_place!
            alias_method :layersentry_hot_target_digest_before_virtio_hardening, :target_digest
            alias_method :layersentry_hot_target_mapping_before_guest_binding, :validate_target_mapping!
        end

        def validate_local_prerequisites!
            layersentry_hot_validate_before_virtio_hardening
            return true unless @options[:guest_os].to_s.casecmp('windows').zero?

            bundle = resolve_virtio_win!
            @options[:resolved_virtio_win] = bundle
            true
        end

        def validate_target_mapping!(metadata)
            layersentry_hot_target_mapping_before_guest_binding(metadata)
            validate_guest_mac_binding!(metadata)
            true
        end

        def rerun_v2v_in_place!(state)
            xml = File.join(@dir, 'final-libvirt.xml')
            raw_paths = state['disks'].map { |disk| disk['prepared_raw_path'] }
            File.open(xml, 'w', 0o600) do |file|
                file.write(final_raw_libvirt_xml(state, raw_paths))
            end

            env = {}
            libguestfs = @options[:libguestfs_path].to_s.strip
            env['LIBGUESTFS_PATH'] = libguestfs unless libguestfs.empty?
            if @options[:guest_os].to_s.casecmp('windows').zero?
                env['VIRTIO_WIN'] = @options[:resolved_virtio_win] || resolve_virtio_win!
            end
            binary = @options[:v2v_in_place_path] || 'virt-v2v-in-place'
            stdout, stderr, status = Open3.capture3(
                env, binary, '-v', '--machine-readable', '-i', 'libvirtxml', xml,
                '--root', (@options[:root] || 'first').to_s
            )
            $stdout.write(stdout) unless stdout.empty?
            $stderr.write(stderr) unless stderr.empty?
            raise Error, 'virt-v2v-in-place failed after source shutdown; prepared target disks are UNKNOWN and source must remain OFF' unless status.success?
        end

        private

        def target_digest
            guest_os = @options[:guest_os].to_s.downcase
            virtio = guest_os == 'windows' ? (@options[:resolved_virtio_win] || resolve_virtio_win!) : ''
            HotUtil.digest({
                               'base_target_digest' => layersentry_hot_target_digest_before_virtio_hardening,
                               'guest_os' => guest_os,
                               'virtio_win_source' => virtio,
                               'expected_guest_macs' => normalized_expected_guest_macs
                           })
        end

        def validate_guest_mac_binding!(metadata)
            expected = normalized_expected_guest_macs
            source_nics = Array(metadata['NICs'])
            agent_driven = %w[windows linux].include?(@options[:guest_os].to_s.downcase)
            if agent_driven && source_nics.any? && expected.empty?
                raise Error, 'agent-driven Hyper-V migration requires guest MAC evidence for every source VM with NICs'
            end
            return true if source_nics.empty? && expected.empty?
            return true if expected.empty?

            actual = source_nics.map do |nic|
                normalize_mac(nic['MacAddress'])
            end
            if actual.any?(&:nil?) || actual.length != source_nics.length
                raise Error, 'unable to resolve every Hyper-V source NIC MAC for guest-agent binding'
            end
            if actual.uniq.length != actual.length
                raise Error, 'Hyper-V source VM reports duplicate NIC MAC addresses; automatic guest identity binding is unsafe'
            end
            actual = actual.sort
            missing = actual - expected
            unless missing.empty?
                raise Error, "guest agent MAC inventory does not match the Hyper-V source VM; missing source MAC(s): #{missing.join(',')}"
            end
            true
        end

        def normalized_expected_guest_macs
            raw = @options[:expected_guest_macs].to_s
            return [] if raw.strip.empty?

            raw.split(',').map do |value|
                mac = normalize_mac(value)
                raise Error, "invalid expected guest MAC #{value.inspect}" unless mac
                mac
            end.uniq.sort
        end

        def normalize_mac(value)
            raw = value.to_s.strip
            hex = if raw.match?(/\A[0-9A-Fa-f]{12}\z/)
                      raw.downcase
                  elsif raw.match?(/\A(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\z/) || raw.match?(/\A(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\z/)
                      raw.delete(':-').downcase
                  end
            return nil unless hex&.match?(/\A[0-9a-f]{12}\z/)
            return nil if hex == ('0' * 12) || hex == ('f' * 12)
            return nil if hex[0, 2].to_i(16).odd?

            hex.scan(/../).join(':')
        end

        def resolve_virtio_win!
            candidates = []
            candidates << @options[:virtio_path].to_s.strip
            candidates << ENV['VIRTIO_WIN'].to_s.strip
            candidates << '/usr/share/virtio-win'
            candidates.reject(&:empty?).each do |candidate|
                expanded = File.expand_path(candidate)
                return expanded if File.file?(expanded) && File.readable?(expanded)
                return expanded if File.directory?(expanded) && File.readable?(expanded)
            end
            raise Error, 'Windows Hyper-V migration requires a readable trusted virtio-win bundle via --virtio, VIRTIO_WIN, or /usr/share/virtio-win before source cutover'
        end
    end
end
