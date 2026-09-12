# -------------------------------------------------------------------------- #
# LayerSentry Hyper-V restart-safe final-delta/import recovery                #
# -------------------------------------------------------------------------- #

require 'digest'
require 'opennebula/image_pool'
require 'opennebula/template_pool'
require_relative 'hyperv_materialization_guard'

module OneSwapHyperV
    class HotCoordinator
        HOT_RECOVERY_PHASES = %w[
            PREPARED CUTOVER_STARTED SOURCE_OFF DELTA_CAPTURING DELTA_APPLYING
            MORPHING DELTA_APPLIED IMPORTING IMPORTED DONE
        ].freeze

        # Complete override of the historical hot commit. This is intentional:
        # the previous hardening wrapper could persist IMPORTING and then call a
        # parent commit implementation that did not accept IMPORTING. The final
        # cutover is now one explicit restart-aware state machine.
        def commit
            validate_local_prerequisites!
            state = HotUtil.load_state(@state_path)
            raise Error, 'Hyper-V hot migration state is missing' unless state
            validate_state_identity!(state)
            phase = state['phase'].to_s
            raise Error, "unsupported Hyper-V hot recovery phase #{phase.inspect}" unless HOT_RECOVERY_PHASES.include?(phase)
            return state if %w[IMPORTED DONE].include?(phase)
            if phase == 'MORPHING'
                raise Error, 'Hyper-V hot migration stopped during MORPHING; virt-v2v-in-place may have partially modified target disks, so automatic replay is prohibited'
            end

            if state['phase'] == 'PREPARED'
                metadata = @source.inspect(@vm_name, require_state: 'Running')
                validate_target_mapping!(metadata)
                validate_opennebula_targets!(metadata)
                verify_prepared_drift!(state, metadata)
                @source.assert_reference_exists!(state)
                state['phase'] = 'CUTOVER_STARTED'
                state['cutover_started_at'] = Time.now.utc.iso8601
                HotUtil.write_json_atomic(@state_path, state)
            end

            if state['phase'] == 'CUTOVER_STARTED'
                @source.power_off!(@vm_name, timeout: (@options[:shutdown_timeout] || 300).to_i)
                metadata = @source.inspect(@vm_name, require_state: 'Off')
                verify_prepared_drift!(state, metadata)
                state['phase'] = 'SOURCE_OFF'
                state['source_off_at'] = Time.now.utc.iso8601
                HotUtil.write_json_atomic(@state_path, state)
            end

            capture_final_delta!(state) if %w[SOURCE_OFF DELTA_CAPTURING].include?(state['phase'])
            apply_final_delta!(state) if state['phase'] == 'DELTA_APPLYING'

            if state['phase'] == 'DELTA_APPLIED'
                verify_source_off_for_import!(state)
                state['phase'] = 'IMPORTING'
                state['import_started_at'] ||= Time.now.utc.iso8601
                state['image_imports'] ||= []
                HotUtil.write_json_atomic(@state_path, state)
            end

            if state['phase'] == 'IMPORTING'
                verify_source_off_for_import!(state)
                images = ensure_recoverable_images!(state)
                template = ensure_recoverable_template!(state, images)
                state['template_id'] = template.id.to_i
                state['phase'] = 'IMPORTED'
                state['imported_at'] = Time.now.utc.iso8601
                HotUtil.write_json_atomic(@state_path, state)
            end

            state
        end

        private

        def capture_final_delta!(state)
            metadata = @source.inspect(@vm_name, require_state: 'Off')
            verify_prepared_drift!(state, metadata)
            @source.assert_reference_exists!(state)
            state['phase'] = 'DELTA_CAPTURING'
            state['delta_capture_started_at'] ||= Time.now.utc.iso8601
            HotUtil.write_json_atomic(@state_path, state)

            delta_dir = File.join(@dir, 'deltas')
            FileUtils.mkdir_p(delta_dir, mode: 0o700)
            bundles = @source.create_delta_bundles!(
                state,
                delta_dir,
                timeout: positive_timeout(:hyperv_transfer_timeout)
            )
            raise Error, "final RCT delta bundle count #{bundles.length} does not match disk count #{state['disks'].length}" unless bundles.length == state['disks'].length

            state['delta_bundles'] = bundles.each_with_index.map do |path, index|
                raise Error, "final delta bundle #{index} is missing: #{path}" unless File.file?(path)
                {
                    'index' => index,
                    'path' => File.expand_path(path),
                    'size' => File.size(path),
                    'sha256' => Digest::SHA256.file(path).hexdigest
                }
            end
            state['delta_applied_indices'] = []
            state['phase'] = 'DELTA_APPLYING'
            state['delta_captured_at'] = Time.now.utc.iso8601
            HotUtil.write_json_atomic(@state_path, state)
        end

        def apply_final_delta!(state)
            verify_source_off_for_import!(state)
            bundles = Array(state['delta_bundles'])
            raise Error, 'durable final delta bundle evidence is missing' unless bundles.length == state['disks'].length
            applied = Array(state['delta_applied_indices']).map(&:to_i).uniq

            state['disks'].each_with_index do |disk, index|
                next if applied.include?(index)

                evidence = bundles.find { |entry| Integer(entry['index']) == index }
                raise Error, "durable final delta bundle evidence is missing for disk #{index}" unless evidence
                path = evidence['path'].to_s
                verify_local_artifact!(path, Integer(evidence['size']), evidence['sha256'].to_s, "final delta bundle #{index}")
                DeltaApplier.apply!(path, disk['prepared_raw_path'], Integer(disk['virtual_size']))
                applied << index
                state['delta_applied_indices'] = applied.sort
                HotUtil.write_json_atomic(@state_path, state)
            end

            state['phase'] = 'MORPHING'
            state['morph_started_at'] = Time.now.utc.iso8601
            HotUtil.write_json_atomic(@state_path, state)
            rerun_v2v_in_place!(state)
            state['phase'] = 'DELTA_APPLIED'
            state['delta_applied_at'] = Time.now.utc.iso8601
            HotUtil.write_json_atomic(@state_path, state)
        end

        def verify_local_artifact!(path, expected_size, expected_sha, label)
            raise Error, "#{label} is missing: #{path}" unless File.file?(path)
            raise Error, "#{label} size changed" unless File.size(path) == expected_size
            observed = Digest::SHA256.file(path).hexdigest
            raise Error, "#{label} SHA-256 changed" unless observed.casecmp(expected_sha).zero?
            true
        end

        def verify_source_off_for_import!(state)
            metadata = @source.inspect(@vm_name, require_state: 'Off')
            raise Error, 'source VM identity changed after cutover' unless metadata['VMId'].to_s.casecmp(state['source_vm_id'].to_s).zero?
            raise Error, 'Hyper-V source topology/security changed after cutover' unless HotUtil.digest(stable_metadata(metadata)) == state['metadata_digest'].to_s
            true
        end

        def ensure_recoverable_images!(state)
            if !@options[:http_transfer] && @helper.respond_to?(:local_path_image_allocation_preflight!, true)
                @helper.send(:local_path_image_allocation_preflight!)
            end
            imports = Array(state['image_imports'])
            disks = Array(state['disks'])
            datastores = @options[:datastore].to_s.split(',').map(&:strip).reject(&:empty?)
            raise Error, 'OpenNebula Image Datastore mapping disappeared during import' if datastores.empty?

            images = disks.each_with_index.map do |disk, index|
                record = imports.find { |entry| Integer(entry['index']) == index }
                record ||= { 'index' => index, 'customization' => 'PENDING' }
                images_for_marker = find_marked_images(index)
                raise Error, "multiple OpenNebula Images carry LayerSentry operation marker #{@operation_id.inspect} for disk #{index}; automatic adoption is unsafe" if images_for_marker.length > 1

                image = nil
                if record['image_id']
                    image = load_image(Integer(record['image_id']))
                    validate_image_marker!(image, index) if image
                end
                if image.nil? && images_for_marker.length == 1
                    image = images_for_marker.first
                    record['image_id'] = image.id.to_i
                    record['adopted_at'] ||= Time.now.utc.iso8601
                    upsert_image_record!(state, record)
                end

                unless image
                    if record['customization'] == 'STARTED'
                        raise Error, "disk #{index} stopped during guest customization before Image allocation; automatic replay is prohibited because the local disk may be partially modified"
                    end
                    if record['customization'] != 'DONE'
                        record['customization'] = 'STARTED'
                        record['customization_started_at'] = Time.now.utc.iso8601
                        upsert_image_record!(state, record)
                        guest_info = @helper.send(:detect_distro, disk['prepared_raw_path'])
                        os_name = false
                        if guest_info
                            @helper.send(:package_injection, disk['prepared_raw_path'], guest_info)
                            @helper.send(:remove_vmtools_injection, disk['prepared_raw_path'], guest_info)
                            os_name = guest_info['name']
                        end
                        record['os'] = os_name
                        record['image_type'] = guest_info ? 'OS' : 'DATABLOCK'
                        record['customization'] = 'DONE'
                        record['customized_at'] = Time.now.utc.iso8601
                        upsert_image_record!(state, record)
                    end

                    ds_id = Integer(datastores[index] || datastores.first)
                    image = allocate_marked_image!(state, disk, index, record, ds_id)
                    record['image_id'] = image.id.to_i
                    record['allocated_at'] = Time.now.utc.iso8601
                    upsert_image_record!(state, record)
                end

                wait_for_image_ready!(image, index)
                record['image_id'] = image.id.to_i
                record['ready_at'] ||= Time.now.utc.iso8601
                upsert_image_record!(state, record)
                { :id => image.id.to_i, :os => record['os'] || marker_value(image, 'LAYERSENTRY_OS_NAME') }
            end
            images
        end

        def allocate_marked_image!(state, disk, index, record, datastore_id)
            client = @helper.instance_variable_get(:@client)
            raise Error, 'OpenNebula client is unavailable during recoverable Image allocation' unless client
            image = OpenNebula::Image.new(OpenNebula::Image.build_xml, client)
            persistent = @options[:persistent_img] ? 'YES' : 'NO'
            name = hot_image_name(index)
            path = disk['prepared_raw_path']
            server_thread = nil
            if @options[:http_transfer]
                path = "http://#{@options[:http_host]}:#{@options[:http_port]}/#{File.basename(disk['prepared_raw_path'])}"
                server_thread = start_hot_http_server(disk['prepared_raw_path'])
            end
            image.add_element('//IMAGE', {
                                  'NAME' => name,
                'TYPE' => (record['image_type'] || 'DATABLOCK'),
                'PATH' => path,
                'PERSISTENT' => persistent,
                'LAYERSENTRY_OPERATION_ID' => @operation_id,
                'LAYERSENTRY_DISK_INDEX' => index.to_s,
                'LAYERSENTRY_SOURCE_PLATFORM' => 'HYPERV',
                'LAYERSENTRY_SOURCE_VM_ID' => state['source_vm_id'].to_s,
                'LAYERSENTRY_OS_NAME' => record['os'].to_s
                              })
            rc = image.allocate(image.to_xml, datastore_id)
            if OpenNebula.is_error?(rc)
                # Allocation response can be lost after server-side success. Do
                # not allocate again until marker reconciliation proves absence.
                matches = find_marked_images(index)
                raise Error, "OpenNebula Image allocation failed and marker reconciliation is ambiguous for disk #{index}: #{rc.message}" if matches.length > 1
                return matches.first if matches.length == 1
                raise Error, "failed to allocate marked OpenNebula Image #{name.inspect}: #{rc.message}"
            end
            if @helper.respond_to?(:chown_one_object, true) && @helper.respond_to?(:resolve_one_ownership, true)
                @helper.send(:chown_one_object, image, *@helper.send(:resolve_one_ownership))
            end
            image
        ensure
            if server_thread
                server_thread[:server]&.shutdown
                server_thread[:thread]&.join(10)
            end
        end

        def start_hot_http_server(disk_path)
            server = WEBrick::HTTPServer.new({
                                                 :Port => @options[:http_port],
                :DocumentRoot => File.dirname(disk_path),
                :RequestCallback => lambda { |_req, response| response['Cache-Control'] = 'public, max-age=3600' },
                :MaxThreads => 8,
                :Logger => WEBrick::Log.new(File::NULL),
                :AccessLog => []
                                             })
            thread = Thread.new { server.start }
            { :server => server, :thread => thread }
        end

        def wait_for_image_ready!(image, index)
            timeout = (@options[:img_wait] || 120).to_i
            ready = image.wait_state('READY', timeout)
            return true if ready

            image.info
            state = image.respond_to?(:short_state_str) ? image.short_state_str : marker_value(image, 'STATE')
            raise Error, "marked OpenNebula Image #{image.id} for disk #{index} did not become READY within #{timeout}s (state #{state})"
        end

        def ensure_recoverable_template!(state, images)
            matches = find_marked_templates
            raise Error, "multiple OpenNebula VM Templates carry LayerSentry operation marker #{@operation_id.inspect}; automatic adoption is unsafe" if matches.length > 1
            if state['template_id']
                template = load_template(Integer(state['template_id']))
                if template
                    validate_template_marker!(template, state)
                    return template
                end
            end
            unless matches.empty?
                template = matches.first
                validate_template_marker!(template, state)
                state['template_id'] = template.id.to_i
                state['template_adopted_at'] ||= Time.now.utc.iso8601
                HotUtil.write_json_atomic(@state_path, state)
                return template
            end

            template = @helper.hyperv_vm_template(state['metadata'], images)
            template.add_element('//VMTEMPLATE', {
                                     'LAYERSENTRY_OPERATION_ID' => @operation_id,
                'LAYERSENTRY_SOURCE_PLATFORM' => 'HYPERV',
                'LAYERSENTRY_SOURCE_VM_ID' => state['source_vm_id'].to_s
                                 })
            state['template_allocation_started_at'] ||= Time.now.utc.iso8601
            HotUtil.write_json_atomic(@state_path, state)
            rc = template.allocate(template.to_xml)
            if OpenNebula.is_error?(rc)
                matches = find_marked_templates
                raise Error, "OpenNebula Template allocation failed and marker reconciliation is ambiguous: #{rc.message}" if matches.length > 1
                if matches.length == 1
                    template = matches.first
                    validate_template_marker!(template, state)
                else
                    raise Error, "failed to allocate marked OpenNebula hot-migration Template #{@vm_name.inspect}: #{rc.message}"
                end
            end
            if @helper.respond_to?(:chown_one_object, true) && @helper.respond_to?(:resolve_one_ownership, true)
                @helper.send(:chown_one_object, template, *@helper.send(:resolve_one_ownership))
            end
            state['template_id'] = template.id.to_i
            state['template_allocated_at'] ||= Time.now.utc.iso8601
            HotUtil.write_json_atomic(@state_path, state)
            template
        end

        def find_marked_images(index)
            client = @helper.instance_variable_get(:@client)
            pool = OpenNebula::ImagePool.new(client, -2)
            rc = pool.info
            raise Error, "unable to reconcile OpenNebula Images: #{rc.message}" if OpenNebula.is_error?(rc)
            pool.each_with_object([]) do |image, matches|
                next unless marker_value(image, 'LAYERSENTRY_OPERATION_ID').to_s == @operation_id.to_s
                next unless marker_value(image, 'LAYERSENTRY_DISK_INDEX').to_s == index.to_s
                matches << image
            end
        end

        def find_marked_templates
            client = @helper.instance_variable_get(:@client)
            pool = OpenNebula::TemplatePool.new(client, -2)
            rc = pool.info
            raise Error, "unable to reconcile OpenNebula VM Templates: #{rc.message}" if OpenNebula.is_error?(rc)
            pool.each_with_object([]) do |template, matches|
                next unless marker_value(template, 'LAYERSENTRY_OPERATION_ID').to_s == @operation_id.to_s
                next unless marker_value(template, 'LAYERSENTRY_SOURCE_PLATFORM').to_s.casecmp('HYPERV').zero?
                matches << template
            end
        end

        def load_image(id)
            client = @helper.instance_variable_get(:@client)
            image = OpenNebula::Image.new_with_id(id, client)
            rc = image.info
            return nil if OpenNebula.is_error?(rc)
            image
        end

        def load_template(id)
            client = @helper.instance_variable_get(:@client)
            template = OpenNebula::Template.new_with_id(id, client)
            rc = template.info
            return nil if OpenNebula.is_error?(rc)
            template
        end

        def validate_image_marker!(image, index)
            raise Error, "OpenNebula Image #{image.id} operation marker mismatch" unless marker_value(image, 'LAYERSENTRY_OPERATION_ID').to_s == @operation_id.to_s
            raise Error, "OpenNebula Image #{image.id} disk-index marker mismatch" unless marker_value(image, 'LAYERSENTRY_DISK_INDEX').to_s == index.to_s
            true
        end

        def validate_template_marker!(template, state)
            raise Error, "OpenNebula Template #{template.id} operation marker mismatch" unless marker_value(template, 'LAYERSENTRY_OPERATION_ID').to_s == @operation_id.to_s
            raise Error, "OpenNebula Template #{template.id} source VM marker mismatch" unless marker_value(template, 'LAYERSENTRY_SOURCE_VM_ID').to_s.casecmp(state['source_vm_id'].to_s).zero?
            true
        end

        def marker_value(object, key)
            object["TEMPLATE/#{key}"] || object[key]
        rescue StandardError
            object[key]
        end

        def upsert_image_record!(state, record)
            state['image_imports'] ||= []
            index = Integer(record['index'])
            existing = state['image_imports'].index { |entry| Integer(entry['index']) == index }
            if existing
                state['image_imports'][existing] = record
            else
                state['image_imports'] << record
            end
            state['image_imports'].sort_by! { |entry| Integer(entry['index']) }
            HotUtil.write_json_atomic(@state_path, state)
        end

        def hot_image_name(index)
            vm = Util.safe_file_component(@vm_name)[0, 64]
            digest = Digest::SHA256.hexdigest(@operation_id.to_s)[0, 12]
            "#{vm}-ls-#{digest}-disk-#{index}"
        end
    end
end
