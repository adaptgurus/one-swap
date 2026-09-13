# -------------------------------------------------------------------------- #
# LayerSentry Hyper-V resumable import transport/pool hardening               #
# -------------------------------------------------------------------------- #

require 'webrick'
require_relative 'hyperv_import_recovery'

module OneSwapHyperV
    class HotCoordinator
        unless method_defined?(:layersentry_capture_before_import_transport_hardening)
            alias_method :layersentry_capture_before_import_transport_hardening, :capture_final_delta!
        end
        unless method_defined?(:layersentry_validate_before_import_customization_hardening)
            alias_method :layersentry_validate_before_import_customization_hardening, :validate_local_prerequisites!
        end

        def validate_local_prerequisites!
            layersentry_validate_before_import_customization_hardening
            validate_reflink_workspace!
            true
        end

        private

        # Automatic recovery of guest customization requires an immutable
        # post-RCT/morphed baseline. Require a COW reflink-capable workspace
        # before source shutdown so a crash during contextualization can discard
        # the clone and safely retry without replaying mutation on the baseline.
        def validate_reflink_workspace!
            return true unless %w[windows linux].include?(@options[:guest_os].to_s.downcase)

            FileUtils.mkdir_p(@dir, mode: 0o700)
            source = File.join(@dir, ".layersentry-reflink-probe-#{Process.pid}-#{SecureRandom.hex(4)}")
            clone = "#{source}.clone"
            File.open(source, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
                file.write('layersentry-reflink-probe')
                file.flush
                file.fsync
            end
            stdout, stderr, status = Open3.capture3('cp', '--reflink=always', '--sparse=always', '--', source, clone)
            unless status.success? && File.file?(clone)
                raise Error, "restart-safe Hyper-V import requires a reflink-capable conversion workspace; cp --reflink=always failed: #{stderr.empty? ? stdout : stderr}"
            end
            File.open(clone, 'r+b') do |file|
                file.seek(0)
                file.write('X')
                file.flush
                file.fsync
            end
            unless File.read(source) == 'layersentry-reflink-probe'
                raise Error, 'conversion workspace clone did not exhibit copy-on-write isolation'
            end
            true
        rescue Errno::ENOENT => e
            raise Error, "restart-safe Hyper-V import requires GNU cp with --reflink support: #{e.message}"
        ensure
            FileUtils.rm_f(clone) if defined?(clone) && clone
            FileUtils.rm_f(source) if defined?(source) && source
        end

        # A crash during DELTA_CAPTURING may leave a complete or partial local
        # bundle that was never durably recorded. Recreate local capture staging
        # from the authoritative Off source/reference instead of trusting stale
        # bytes. The remote producer overwrites its operation-scoped bundle.
        def capture_final_delta!(state)
            if %w[SOURCE_OFF DELTA_CAPTURING].include?(state['phase'].to_s)
                delta_dir = File.join(@dir, 'deltas')
                FileUtils.rm_rf(delta_dir)
                FileUtils.mkdir_p(delta_dir, mode: 0o700)
            end
            layersentry_capture_before_import_transport_hardening(state)
        end

        # Recoverable per-disk import. Marked OpenNebula objects are adopted
        # first. If no Image exists, guest customization runs on an operation-
        # scoped COW reflink, never on the immutable post-RCT/morphed baseline.
        # A crash in STARTED therefore deletes the clone and retries safely.
        def ensure_recoverable_images!(state)
            if !@options[:http_transfer] && @helper.respond_to?(:local_path_image_allocation_preflight!, true)
                @helper.send(:local_path_image_allocation_preflight!)
            end
            imports = Array(state['image_imports'])
            disks = Array(state['disks'])
            datastores = @options[:datastore].to_s.split(',').map(&:strip).reject(&:empty?)
            raise Error, 'OpenNebula Image Datastore mapping disappeared during import' if datastores.empty?

            disks.each_with_index.map do |disk, index|
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
                    validate_image_marker!(image, index)
                    record['image_id'] = image.id.to_i
                    record['adopted_at'] ||= Time.now.utc.iso8601
                    upsert_image_record!(state, record)
                end

                unless image
                    import_path = prepare_recoverable_import_disk!(state, disk, index, record)
                    ds_id = Integer(datastores[index] || datastores.first)
                    import_disk = disk.merge('prepared_raw_path' => import_path)
                    image = allocate_marked_image!(state, import_disk, index, record, ds_id)
                    record['image_id'] = image.id.to_i
                    record['allocated_at'] ||= Time.now.utc.iso8601
                    upsert_image_record!(state, record)
                end

                wait_for_image_ready!(image, index)
                record['image_id'] = image.id.to_i
                record['ready_at'] ||= Time.now.utc.iso8601
                upsert_image_record!(state, record)
                { :id => image.id.to_i, :os => record['os'] || marker_value(image, 'LAYERSENTRY_OS_NAME') }
            end
        end

        def prepare_recoverable_import_disk!(state, disk, index, record)
            baseline = File.expand_path(disk['prepared_raw_path'].to_s)
            raise Error, "immutable prepared RAW baseline for disk #{index} is missing" unless File.file?(baseline)

            if record['customization'] == 'DONE'
                path = record['import_path'].to_s
                path = baseline if path.empty?
                if path == baseline
                    return baseline
                end
                begin
                    verify_local_artifact!(path, Integer(record['import_size']), record['import_sha256'].to_s, "customized import disk #{index}")
                    return path
                rescue StandardError
                    # No marked Image exists (caller checked first), so it is
                    # safe to discard only the operation-scoped clone and rebuild
                    # from the immutable baseline.
                    FileUtils.rm_f(path)
                    record['customization'] = 'PENDING'
                    record.delete('import_path')
                    record.delete('import_size')
                    record.delete('import_sha256')
                    upsert_image_record!(state, record)
                end
            end

            guest_info = @helper.send(:detect_distro, baseline)
            unless guest_info
                record['os'] = false
                record['image_type'] = 'DATABLOCK'
                record['import_path'] = baseline
                record['customization'] = 'DONE'
                record['customized_at'] ||= Time.now.utc.iso8601
                upsert_image_record!(state, record)
                return baseline
            end

            import_path = File.join(@dir, "import-disk-#{index}-#{Digest::SHA256.hexdigest(@operation_id.to_s)[0, 12]}.raw")
            FileUtils.rm_f(import_path) if record['customization'] == 'STARTED' || File.exist?(import_path)
            record['customization'] = 'STARTED'
            record['import_path'] = import_path
            record['customization_started_at'] ||= Time.now.utc.iso8601
            upsert_image_record!(state, record)

            reflink_clone!(baseline, import_path, index)
            @helper.send(:package_injection, import_path, guest_info)
            @helper.send(:remove_vmtools_injection, import_path, guest_info)
            fsync_local_file_and_parent!(import_path)

            record['os'] = guest_info['name']
            record['image_type'] = 'OS'
            record['import_size'] = File.size(import_path)
            record['import_sha256'] = Digest::SHA256.file(import_path).hexdigest
            record['customization'] = 'DONE'
            record['customized_at'] = Time.now.utc.iso8601
            upsert_image_record!(state, record)
            import_path
        end

        def reflink_clone!(source, destination, index)
            stdout, stderr, status = Open3.capture3('cp', '--reflink=always', '--sparse=always', '--', source, destination)
            unless status.success? && File.file?(destination)
                FileUtils.rm_f(destination)
                raise Error, "restart-safe COW clone failed for disk #{index}: #{stderr.empty? ? stdout : stderr}"
            end
            File.chmod(0o600, destination)
            fsync_local_file_and_parent!(destination)
            destination
        rescue Errno::ENOENT => e
            FileUtils.rm_f(destination)
            raise Error, "restart-safe COW clone requires GNU cp: #{e.message}"
        end

        def fsync_local_file_and_parent!(path)
            File.open(path, 'rb') { |file| file.fsync }
            File.open(File.dirname(path), 'r') { |dir| dir.fsync }
            true
        end

        # OpenNebula can download PATH asynchronously after image.allocate
        # returns. Keep the operation-scoped HTTP server alive until the Image
        # becomes READY; otherwise a successful allocation can later fail with a
        # truncated/unreachable source. Marker reconciliation remains active if
        # the allocation response itself is lost.
        def allocate_marked_image!(state, disk, index, record, datastore_id)
            client = @helper.instance_variable_get(:@client)
            raise Error, 'OpenNebula client is unavailable during recoverable Image allocation' unless client

            image = OpenNebula::Image.new(OpenNebula::Image.build_xml, client)
            persistent = @options[:persistent_img] ? 'YES' : 'NO'
            name = hot_image_name(index)
            path = disk['prepared_raw_path']
            server_thread = nil
            if @options[:http_transfer]
                host = @options[:http_host].to_s.strip
                raise Error, 'HTTP Image transfer requires an explicit --http-host reachable by OpenNebula' if host.empty?
                path = "http://#{host}:#{@options[:http_port]}/#{File.basename(disk['prepared_raw_path'])}"
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
                matches = find_marked_images(index)
                if matches.length > 1
                    raise Error, "OpenNebula Image allocation failed and marker reconciliation is ambiguous for disk #{index}: #{rc.message}"
                end
                if matches.length == 1
                    image = matches.first
                else
                    raise Error, "failed to allocate marked OpenNebula Image #{name.inspect}: #{rc.message}"
                end
            elsif @helper.respond_to?(:chown_one_object, true) && @helper.respond_to?(:resolve_one_ownership, true)
                @helper.send(:chown_one_object, image, *@helper.send(:resolve_one_ownership))
            end

            wait_for_image_ready!(image, index) if server_thread
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
                                                 :RequestCallback => lambda { |_req, response| response['Cache-Control'] = 'no-store' },
                                                 :MaxThreads => 8,
                                                 :Logger => WEBrick::Log.new(File::NULL),
                                                 :AccessLog => []
                                             })
            thread = Thread.new { server.start }
            deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 5.0
            until server.status == :Running
                raise Error, 'operation-scoped HTTP Image server exited before becoming ready' unless thread.alive?
                if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
                    server.shutdown
                    thread.join(5)
                    raise Error, 'operation-scoped HTTP Image server did not become ready within 5 seconds'
                end
                sleep 0.05
            end
            { :server => server, :thread => thread }
        end

        def find_marked_images(index)
            client = @helper.instance_variable_get(:@client)
            pool = OpenNebula::ImagePool.new(client, -2)
            rc = pool.info
            raise Error, "unable to reconcile OpenNebula Images: #{rc.message}" if OpenNebula.is_error?(rc)
            matches = []
            pool.each do |image|
                next unless marker_value(image, 'LAYERSENTRY_OPERATION_ID').to_s == @operation_id.to_s
                next unless marker_value(image, 'LAYERSENTRY_DISK_INDEX').to_s == index.to_s
                matches << image
            end
            matches
        end

        def find_marked_templates
            client = @helper.instance_variable_get(:@client)
            pool = OpenNebula::TemplatePool.new(client, -2)
            rc = pool.info
            raise Error, "unable to reconcile OpenNebula VM Templates: #{rc.message}" if OpenNebula.is_error?(rc)
            matches = []
            pool.each do |template|
                next unless marker_value(template, 'LAYERSENTRY_OPERATION_ID').to_s == @operation_id.to_s
                next unless marker_value(template, 'LAYERSENTRY_SOURCE_PLATFORM').to_s.casecmp('HYPERV').zero?
                matches << template
            end
            matches
        end

        def load_image(id)
            client = @helper.instance_variable_get(:@client)
            image = OpenNebula::Image.new(OpenNebula::Image.build_xml(id), client)
            rc = image.info
            return nil if OpenNebula.is_error?(rc)
            image
        end

        def load_template(id)
            client = @helper.instance_variable_get(:@client)
            template = OpenNebula::Template.new(OpenNebula::Template.build_xml(id), client)
            rc = template.info
            return nil if OpenNebula.is_error?(rc)
            template
        end
    end
end
