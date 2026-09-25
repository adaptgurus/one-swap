# -------------------------------------------------------------------------- #
# LayerSentry Hyper-V guest network intent hardening                         #
# -------------------------------------------------------------------------- #

require 'base64'
require 'ipaddr'
require 'json'
require 'rexml/document'
require_relative 'hyperv_final_safety_hardening'

module OneSwapHyperV
    module NetworkIntent
        module_function

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

        def expected_macs(raw)
            return [] if raw.to_s.strip.empty?

            raw.to_s.split(',').map do |value|
                mac = normalize_mac(value)
                raise Error, "invalid expected guest MAC #{value.inspect}" unless mac
                mac
            end.uniq.sort
        end

        def decode(raw, expected_macs)
            return [] if raw.to_s.strip.empty?

            padding = (4 - (raw.to_s.length % 4)) % 4
            parsed = JSON.parse(Base64.urlsafe_decode64(raw.to_s + ('=' * padding)))
            raise Error, 'guest network profile must be a JSON array' unless parsed.is_a?(Array)

            profile = parsed.map do |entry|
                raise Error, 'guest network profile entry must be an object' unless entry.is_a?(Hash)
                mac = normalize_mac(entry['mac'])
                raise Error, "guest network profile has invalid MAC #{entry['mac'].inspect}" unless mac
                unless expected_macs.include?(mac)
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
            profile.sort_by { |entry| entry['mac'] }
        rescue ArgumentError, JSON::ParserError => e
            raise Error, "invalid guest network profile: #{e.message}"
        end

        def static_ipv4(entry)
            return nil unless entry['dhcp'] == 'disabled'

            ipv4_cidrs = Array(entry['addresses']).select { |item| IPAddr.new(item).ipv4? }
            raise Error, "Windows static interface #{entry['mac']} does not have exactly one qualified IPv4 CIDR" unless ipv4_cidrs.length == 1
            address, prefix = ipv4_cidrs.first.split('/', 2)
            gateway = Array(entry['gateways']).find { |item| IPAddr.new(item).ipv4? }.to_s
            dns = Array(entry['dns_servers']).select { |item| IPAddr.new(item).ipv4? }
            {
                'address' => address,
                'prefix' => Integer(prefix),
                'gateway' => gateway,
                'dns' => dns
            }
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
    end

    class HotCoordinator
        unless method_defined?(:layersentry_validate_local_before_network_hardening)
            alias_method :layersentry_validate_local_before_network_hardening, :validate_local_prerequisites!
            alias_method :layersentry_validate_mapping_before_network_hardening, :validate_target_mapping!
            alias_method :layersentry_validate_targets_before_network_hardening, :validate_opennebula_targets!
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

        def validate_opennebula_targets!(metadata)
            layersentry_validate_targets_before_network_hardening(metadata)
            validate_static_target_vnets!(metadata)
            true
        end

        # This remains the single post-RCT guest morph. Network arguments are
        # appended to the same invocation that injects VirtIO drivers.
        def rerun_v2v_in_place!(state)
            xml = File.join(@dir, 'final-libvirt.xml')
            raw_paths = state['disks'].map { |disk| disk['prepared_raw_path'] }
            File.open(xml, 'w', 0o600) do |file|
                file.write(final_raw_libvirt_xml(state, raw_paths))
            end

            env = {}
            libguestfs = @options[:libguestfs_path].to_s.strip
            env['LIBGUESTFS_PATH'] = libguestfs unless libguestfs.empty?
            libguestfs_memsize = @options[:libguestfs_memsize].to_i
            env['LIBGUESTFS_MEMSIZE'] = libguestfs_memsize.to_s if libguestfs_memsize.positive?
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
            @normalized_guest_network_profile = NetworkIntent.decode(raw, normalized_expected_guest_macs)
        end

        def validate_guest_network_profile_binding!(metadata)
            profile = normalized_guest_network_profile
            return true if profile.empty?

            actual = Array(metadata['NICs']).map { |nic| NetworkIntent.normalize_mac(nic['MacAddress']) }
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
                static = NetworkIntent.static_ipv4(entry)
                next unless static
                fields = [static['address'], static['gateway'], static['prefix'].to_s] + static['dns']
                "#{entry['mac']}:ip:#{fields.join(',')}"
            end
        end

        def validate_static_target_vnets!(metadata)
            static_profiles = normalized_guest_network_profile.filter_map do |entry|
                static = NetworkIntent.static_ipv4(entry)
                static ? [entry['mac'], static] : nil
            end.to_h
            return true if static_profiles.empty?

            client = @helper.instance_variable_get(:@client)
            raise Error, 'OpenNebula client is unavailable for static target network validation' unless client
            source_nics = Array(metadata['NICs'])
            network_ids = @options[:network].to_s.split(',').map(&:strip).reject(&:empty?)
            network_ids = Array.new(source_nics.length, network_ids.first) if network_ids.length == 1

            source_nics.each_with_index do |nic, index|
                mac = NetworkIntent.normalize_mac(nic['MacAddress'])
                static = static_profiles[mac]
                next unless static
                network_id = Integer(network_ids.fetch(index))
                vnet = OpenNebula::VirtualNetwork.new(OpenNebula::VirtualNetwork.build_xml(network_id), client)
                rc = vnet.info
                raise Error, "OpenNebula VNet #{network_id} is unavailable during static-IP validation: #{rc.message}" if OpenNebula.is_error?(rc)
                validate_static_ip_against_vnet!(vnet, network_id, static)
            end
            true
        rescue ArgumentError, IndexError => e
            raise Error, "unable to validate static target VNet mapping: #{e.message}"
        end

        def validate_static_ip_against_vnet!(vnet, network_id, static)
            ip = IPAddr.new(static.fetch('address'))
            raise Error, 'only IPv4 static target validation is qualified' unless ip.ipv4?

            xml = REXML::Document.new(vnet.to_xml.to_s)
            ipv4_ranges = REXML::XPath.match(xml, '//AR_POOL/AR').filter_map do |ar|
                type = child_text(ar, 'TYPE').upcase
                next unless %w[IP4 IP4_6].include?(type)
                first = child_text(ar, 'IP')
                size = child_text(ar, 'SIZE')
                next if first.empty? || size.empty?
                begin
                    start = IPAddr.new(first)
                    count = Integer(size)
                    next unless start.ipv4? && count.positive?
                    [start.to_i, start.to_i + count - 1, ar]
                rescue IPAddr::InvalidAddressError, ArgumentError
                    raise Error, "OpenNebula VNet #{network_id} has malformed IPv4 Address Range metadata"
                end
            end

            matched_ar = nil
            unless ipv4_ranges.empty?
                target = ip.to_i
                matches = ipv4_ranges.select { |start_i, end_i, _ar| target.between?(start_i, end_i) }
                if matches.empty?
                    raise Error, "Windows static IP #{ip} is outside every IPv4 Address Range of OpenNebula VNet #{network_id}; cutover is blocked"
                end
                raise Error, "Windows static IP #{ip} matches multiple OpenNebula Address Ranges in VNet #{network_id}; mapping is ambiguous" if matches.length > 1
                matched_ar = matches.first[2]
            end

            network_address = effective_vnet_value(vnet, matched_ar, 'NETWORK_ADDRESS')
            network_mask = effective_vnet_value(vnet, matched_ar, 'NETWORK_MASK')
            if !network_address.empty? && (!network_mask.empty? || network_address.include?('/'))
                network = build_ipv4_network(network_address, network_mask)
                unless network.include?(ip)
                    raise Error, "Windows static IP #{ip} is outside declared subnet #{network} of OpenNebula VNet #{network_id}"
                end
            end

            expected_gateway = static['gateway'].to_s
            target_gateway = effective_vnet_value(vnet, matched_ar, 'GATEWAY')
            if !expected_gateway.empty? && !target_gateway.empty?
                expected = IPAddr.new(expected_gateway).to_s
                target = IPAddr.new(target_gateway).to_s
                unless expected == target
                    raise Error, "Windows static gateway #{expected} conflicts with OpenNebula VNet #{network_id} gateway #{target}; automatic restoration is unsafe"
                end
            end
            true
        rescue REXML::ParseException, IPAddr::InvalidAddressError => e
            raise Error, "OpenNebula VNet #{network_id} metadata is invalid during static-IP validation: #{e.message}"
        end

        def child_text(element, name)
            child = REXML::XPath.first(element, name)
            child ? child.text.to_s.strip : ''
        end

        def effective_vnet_value(vnet, ar, name)
            ar_value = ar ? child_text(ar, name) : ''
            return ar_value unless ar_value.empty?
            vnet["TEMPLATE/#{name}"].to_s.strip
        end

        def build_ipv4_network(address, mask)
            if address.include?('/')
                network = IPAddr.new(address)
                raise Error, "declared target network #{address.inspect} is not IPv4" unless network.ipv4?
                return network
            end
            prefix = dotted_mask_prefix(mask)
            IPAddr.new("#{address}/#{prefix}")
        rescue IPAddr::InvalidAddressError => e
            raise Error, "invalid target network metadata: #{e.message}"
        end

        def dotted_mask_prefix(mask)
            parts = mask.to_s.split('.')
            raise Error, "invalid IPv4 network mask #{mask.inspect}" unless parts.length == 4
            bytes = parts.map { |item| Integer(item) }
            raise Error, "invalid IPv4 network mask #{mask.inspect}" unless bytes.all? { |item| item.between?(0, 255) }
            bits = bytes.map { |item| format('%08b', item) }.join
            raise Error, "non-contiguous IPv4 network mask #{mask.inspect}" unless bits.match?(/\A1*0*\z/)
            bits.count('1')
        rescue ArgumentError
            raise Error, "invalid IPv4 network mask #{mask.inspect}"
        end
    end
end

class OneSwapHelper
    unless method_defined?(:layersentry_hyperv_vm_template_before_network_intent)
        alias_method :layersentry_hyperv_vm_template_before_network_intent, :hyperv_vm_template
    end

    def hyperv_vm_template(metadata, image_ids)
        raw_profile = @options[:guest_network_profile].to_s.strip
        return layersentry_hyperv_vm_template_before_network_intent(metadata, image_ids) if raw_profile.empty?

        expected = OneSwapHyperV::NetworkIntent.expected_macs(@options[:expected_guest_macs])
        profile = OneSwapHyperV::NetworkIntent.decode(raw_profile, expected)
        profile_by_mac = profile.each_with_object({}) { |entry, out| out[entry['mac']] = entry }

        memory_mb = Integer(metadata.fetch('MemoryStartupBytes')) / (1024 * 1024)
        cpu = Integer(metadata.fetch('ProcessorCount'))
        config = {
            'NAME' => @options[:name],
            'CPU' => (@options[:cpu] || cpu).to_s,
            'VCPU' => (@options[:vcpu] || cpu).to_s,
            'MEMORY' => memory_mb.to_s,
            'HYPERVISOR' => 'kvm',
            'GRAPHICS' => {
                'TYPE' => (@options[:graphics_type] || 'VNC').to_s.upcase,
                'LISTEN' => (@options[:graphics_listen] || '0.0.0.0').to_s
            },
            'HYPERV_SOURCE_VM_ID' => metadata.fetch('VMId').to_s,
            'HYPERV_SOURCE_HOST' => @hyperv_source_host.to_s,
            'ONESWAP_SOURCE_PLATFORM' => 'HYPERV'
        }
        unless @options[:disable_contextualization]
            config['CONTEXT'] = {
                'NETWORK' => 'YES',
                'SSH_PUBLIC_KEY' => '$USER[SSH_PUBLIC_KEY]'
            }
        end
        if OneSwapHyperV::Util.bool(metadata['DynamicMemoryEnabled'])
            maximum = Integer(metadata['MemoryMaximumBytes']) / (1024 * 1024)
            if maximum > memory_mb
                config['MEMORY_RESIZE_MODE'] = 'HOTPLUG'
                config['MEMORY_MAX'] = maximum.to_s
                config['HOT_RESIZE'] = { 'MEMORY_HOT_ADD_ENABLED' => 'YES' }
            end
        end
        config['CPU_MODEL'] = { 'MODEL' => @options[:cpu_model].to_s } if @options[:cpu_model]

        template = OpenNebula::Template.new(OpenNebula::Template.build_xml, @client)
        template.add_element('//VMTEMPLATE', config)

        image_ids.each_with_index do |image, index|
            disk = { 'IMAGE_ID' => image[:id].to_s }
            disk['DEV_PREFIX'] = (@options[:dev_prefix] || 'vd').to_s
            disk['TARGET'] = "vd#{hyperv_disk_suffix(index)}"
            template.add_element('//VMTEMPLATE', { 'DISK' => disk })
        end

        network_ids = @options[:network].to_s.split(',').map(&:strip).reject(&:empty?)
        nics = Array(metadata['NICs'])
        if nics.any?
            raise OneSwapHyperV::Error, 'Hyper-V import requires --network (or :network in OneSwap server config) when the source VM has NICs' if network_ids.empty?
            if network_ids.length != 1 && network_ids.length != nics.length
                raise OneSwapHyperV::Error, "number of OpenNebula networks (#{network_ids.length}) must be 1 or match Hyper-V NIC count (#{nics.length})"
            end
            network_ids = Array.new(nics.length, network_ids.first) if network_ids.length == 1
            nics.each_with_index do |nic, index|
                network_id = Integer(network_ids[index])
                raise OneSwapHyperV::Error, "invalid OpenNebula network ID #{network_ids[index].inspect}" if network_id.negative?
                entry = { 'NETWORK_ID' => network_id.to_s }
                mac = OneSwapHyperV::NetworkIntent.normalize_mac(nic['MacAddress'])
                raise OneSwapHyperV::Error, "invalid authoritative Hyper-V NIC MAC #{nic['MacAddress'].inspect}" unless mac
                entry['MAC'] = mac
                if (network_entry = profile_by_mac[mac]) && (static = OneSwapHyperV::NetworkIntent.static_ipv4(network_entry))
                    entry['IP'] = static['address']
                end
                template.add_element('//VMTEMPLATE', { 'NIC' => entry })
            end
        end

        generation = Integer(metadata.fetch('Generation'))
        if generation == 2
            secure = OneSwapHyperV::Util.bool(metadata['SecureBoot'])
            path = secure ? @options[:uefi_sec_path] : @options[:uefi_path]
            path = secure ? '/usr/share/OVMF/OVMF_CODE_4M.secboot.fd' : '/usr/share/OVMF/OVMF_CODE_4M.fd' if path.to_s.strip.empty?
            os = { 'ARCH' => 'x86_64', 'MACHINE' => 'q35', 'FIRMWARE' => path.to_s }
            os['FIRMWARE_SECURE'] = 'YES' if secure
            template.add_element('//VMTEMPLATE', { 'OS' => os })
        else
            template.add_element('//VMTEMPLATE', { 'OS' => { 'ARCH' => 'x86_64', 'FIRMWARE' => 'BIOS' } })
        end

        send(:template_scheduling, template) if respond_to?(:template_scheduling, true)
        template
    rescue KeyError, ArgumentError, TypeError => e
        raise OneSwapHyperV::Error, "unable to build OpenNebula Hyper-V template with guest network intent: #{e.message}"
    end
end
