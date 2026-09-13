# -------------------------------------------------------------------------- #
# LayerSentry Hyper-V guest network intent hardening                         #
# -------------------------------------------------------------------------- #

require 'base64'
require 'ipaddr'
require 'json'
require_relative 'hyperv_final_safety_hardening'

module OneSwapHyperV
    class HotCoordinator
        unless method_defined?(:layersentry_validate_local_before_network_hardening)
            alias_method :layersentry_validate_local_before_network_hardening, :validate_local_prerequisites!
            alias_method :layersentry_validate_mapping_before_network_hardening, :validate_target_mapping!
            alias_method :layersentry_morph_before_network_hardening, :rerun_v2v_in_place!
            alias_method :layersentry_target_digest_before_network_hardening, :target_digest
        end

        def validate_local_prerequisites!
            layersentry_validate_local_before_network_hardening
            if agent_driven? && Util.bool(@options[:skip_mac])
                raise Error, 'agent-driven Hyper-V migration requires source MAC preservation; --skip-mac is prohibited'
            end
            normalized_guest_network_profile
            true
        end

        def validate_target_mapping!(metadata)
            layersentry_validate_mapping_before_network_hardening(metadata)
            validate_guest_network_profile_binding!(metadata)
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
            argv = [binary, '-v', '--machine-readable', '-i', 'libvirtxml', xml,
                    '--root', (@options[:root] || 'first').to_s]
            windows_static_ip_args.each do |value|
                argv << '--mac' << value
            end
            stdout, stderr, status = Open3.capture3(env, *argv)
            $stdout.write(stdout) unless stdout.empty?
            $stderr.write(stderr) unless stderr.empty?
            raise Error, 'virt-v2v-in-place failed after source shutdown; prepared target disks are UNKNOWN and source must remain OFF' unless status.success?
        end

        private

        def target_digest
            HotUtil.digest({
                               'base_target_digest' => layersentry_target_digest_before_network_hardening,
                               'guest_network_profile' => normalized_guest_network_profile
                           })
        end

        def agent_driven?
            %w[windows linux].include?(@options[:guest_os].to_s.downcase)
        end

        def normalized_guest_network_profile
            return @normalized_guest_network_profile if defined?(@normalized_guest_network_profile)

            raw = @options[:guest_network_profile].to_s.strip
            if raw.empty?
                @normalized_guest_network_profile = []
                return @normalized_guest_network_profile
            end
            unless @options[:guest_os].to_s.casecmp('windows').zero?
                raise Error, 'guest network profile is currently qualified only for agent-authoritative Windows migration'
            end
            decoded = decode_urlsafe_profile(raw)
            parsed = JSON.parse(decoded)
            raise Error, 'guest network profile must be a JSON array' unless parsed.is_a?(Array)

            expected = normalized_expected_guest_macs
            profile = parsed.map do |entry|
                raise Error, 'guest network profile entry must be an object' unless entry.is_a?(Hash)
                mac = normalize_mac(entry['mac'])
                raise Error, "guest network profile has invalid MAC #{entry['mac'].inspect}" unless mac
                unless expected.include?(mac)
                    raise Error, "guest network profile MAC #{mac} is absent from the admitted guest MAC baseline"
                end
                dhcp = entry['dhcp'].to_s.downcase.strip
                unless %w[enabled disabled].include?(dhcp)
                    raise Error, "guest network profile for #{mac} has unqualified DHCP state #{entry['dhcp'].inspect}"
                end
                addresses = normalize_cidr_list(entry['addresses'], "addresses for #{mac}")
                gateways = normalize_ip_list(entry['gateways'], "gateways for #{mac}")
                dns = normalize_ip_list(entry['dns_servers'], "DNS servers for #{mac}")
                if dhcp == 'disabled'
                    ipv4 = addresses.select { |item| IPAddr.new(item).ipv4? }
                    unless ipv4.length == 1
                        raise Error, "Windows static interface #{mac} requires exactly one qualified IPv4 CIDR; got #{ipv4.length}"
                    end
                    ipv4_gateways = gateways.select { |item| IPAddr.new(item).ipv4? }
                    if ipv4_gateways.length > 1
                        raise Error, "Windows static interface #{mac} has multiple IPv4 default gateways; automatic restoration is not qualified"
                    end
                end
                {
                    'mac' => mac,
                    'dhcp' => dhcp,
                    'addresses' => addresses,
                    'gateways' => gateways,
                    'dns_servers' => dns
                }
            end
            duplicate_macs = profile.group_by { |entry| entry['mac'] }.select { |_mac, entries| entries.length > 1 }.keys
            unless duplicate_macs.empty?
                raise Error, "guest network profile contains duplicate MAC entries: #{duplicate_macs.join(',')}"
            end
            @normalized_guest_network_profile = profile.sort_by { |entry| entry['mac'] }
        rescue ArgumentError, JSON::ParserError => e
            raise Error, "invalid guest network profile: #{e.message}"
        end

        def decode_urlsafe_profile(raw)
            padding = (4 - (raw.length % 4)) % 4
            Base64.urlsafe_decode64(raw + ('=' * padding))
        rescue ArgumentError => e
            raise Error, "guest network profile is not valid base64url: #{e.message}"
        end

        def normalize_cidr_list(values, label)
            Array(values).map do |value|
                text = value.to_s.strip
                raise Error, "#{label} contains an empty value" if text.empty?
                address, prefix = text.split('/', 2)
                raise Error, "#{label} contains non-CIDR value #{text.inspect}" if prefix.to_s.empty?
                ip = IPAddr.new(address)
                bits = Integer(prefix)
                max = ip.ipv4? ? 32 : 128
                raise Error, "#{label} has invalid prefix #{bits}" unless bits.between?(0, max)
                "#{ip}/#{bits}"
            end.uniq.sort
        rescue IPAddr::InvalidAddressError, ArgumentError => e
            raise Error, "#{label} is invalid: #{e.message}"
        end

        def normalize_ip_list(values, label)
            Array(values).map do |value|
                text = value.to_s.strip
                raise Error, "#{label} contains an empty value" if text.empty?
                IPAddr.new(text).to_s
            end.uniq.sort
        rescue IPAddr::InvalidAddressError => e
            raise Error, "#{label} is invalid: #{e.message}"
        end

        def validate_guest_network_profile_binding!(metadata)
            profile = normalized_guest_network_profile
            return true if profile.empty?

            actual = Array(metadata['NICs']).map { |nic| normalize_mac(nic['MacAddress']) }
            raise Error, 'unable to bind guest network profile to every authoritative Hyper-V NIC' if actual.any?(&:nil?)
            actual = actual.uniq
            profile.each do |entry|
                next if entry['dhcp'] == 'enabled'
                unless actual.include?(entry['mac'])
                    raise Error, "Windows static network profile MAC #{entry['mac']} is not an authoritative Hyper-V source NIC; automatic restoration is unsafe"
                end
            end
            true
        end

        def windows_static_ip_args
            return [] unless @options[:guest_os].to_s.casecmp('windows').zero?

            normalized_guest_network_profile.filter_map do |entry|
                next unless entry['dhcp'] == 'disabled'
                ipv4_cidrs = entry['addresses'].select { |item| IPAddr.new(item).ipv4? }
                cidr = ipv4_cidrs.fetch(0)
                address, prefix = cidr.split('/', 2)
                gateway = entry['gateways'].find { |item| IPAddr.new(item).ipv4? }.to_s
                nameservers = entry['dns_servers'].select { |item| IPAddr.new(item).ipv4? }
                fields = [address, gateway, prefix] + nameservers
                "#{entry['mac']}:ip:#{fields.join(',')}"
            end
        end
    end
end
