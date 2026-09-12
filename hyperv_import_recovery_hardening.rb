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

        private

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

            # Critical for HTTP transfer: wait while the operation-scoped server
            # is still running. The caller may wait once more; that is a safe,
            # read-only READY check.
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
