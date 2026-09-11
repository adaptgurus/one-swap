# -------------------------------------------------------------------------- #
# LayerSentry Hyper-V VirtIO production qualification                        #
# -------------------------------------------------------------------------- #

require_relative 'hyperv_hot_hardening'

module OneSwapHyperV
    class HotCoordinator
        unless method_defined?(:layersentry_hot_validate_before_virtio_hardening)
            alias_method :layersentry_hot_validate_before_virtio_hardening, :validate_local_prerequisites!
            alias_method :layersentry_hot_morph_before_virtio_hardening, :rerun_v2v_in_place!
        end

        def validate_local_prerequisites!
            layersentry_hot_validate_before_virtio_hardening
            return true unless @options[:guest_os].to_s.casecmp('windows').zero?

            bundle = resolve_virtio_win!
            @options[:resolved_virtio_win] = bundle
            true
        end

        def rerun_v2v_in_place!(state)
            # The hardened parent implementation is intentionally not called:
            # this override is the same single post-RCT morph with VIRTIO_WIN
            # pinned into the environment for Windows. The source is already
            # OFF and the RAW baseline has already received the final RCT data.
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
            raise Error, 'Windows Hyper-V migration requires a readable signed virtio-win bundle via --virtio, VIRTIO_WIN, or /usr/share/virtio-win before source cutover'
        end
    end
end
