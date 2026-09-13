# -------------------------------------------------------------------------- #
# LayerSentry final Hyper-V migration safety hardening                       #
# -------------------------------------------------------------------------- #

require 'digest'
require 'rexml/document'
require_relative 'hyperv_virtio_hardening'

module OneSwapHyperV
    class HotCoordinator
        unless method_defined?(:layersentry_target_digest_before_final_safety)
            alias_method :layersentry_target_digest_before_final_safety, :target_digest
            alias_method :layersentry_validate_local_before_final_safety, :validate_local_prerequisites!
            alias_method :layersentry_ensure_images_before_final_safety, :ensure_recoverable_images!
            alias_method :layersentry_find_images_before_final_safety, :find_marked_images
            alias_method :layersentry_validate_image_before_final_safety, :validate_image_marker!
            alias_method :layersentry_ensure_template_before_final_safety, :ensure_recoverable_template!
            alias_method :layersentry_validate_template_before_final_safety, :validate_template_marker!
        end

        def validate_local_prerequisites!
            layersentry_validate_local_before_final_safety
            validate_production_transfer_security!
            true
        end

        def ensure_recoverable_images!(state)
            previous = @layersentry_recovery_state
            @layersentry_recovery_state = state
            layersentry_ensure_images_before_final_safety(state)
        ensure
            @layersentry_recovery_state = previous
        end

        def find_marked_images(index)
            matches = layersentry_find_images_before_final_safety(index)
            if @layersentry_recovery_state
                matches.each { |image| validate_image_marker!(image, index) }
            end
            matches
        end

        def validate_image_marker!(image, index)
            layersentry_validate_image_before_final_safety(image, index)
            state = @layersentry_recovery_state
            return true unless state

            source_vm = marker_value(image, 'LAYERSENTRY_SOURCE_VM_ID').to_s
            unless source_vm.casecmp(state['source_vm_id'].to_s).zero?
                raise Error, "OpenNebula Image #{image.id} source VM marker mismatch"
            end
            unless marker_value(image, 'LAYERSENTRY_SOURCE_PLATFORM').to_s.casecmp('HYPERV').zero?
                raise Error, "OpenNebula Image #{image.id} source-platform marker mismatch"
            end

            datastore_ids = @options[:datastore].to_s.split(',').map(&:strip).reject(&:empty?)
            raise Error, 'OpenNebula Image Datastore mapping is unavailable during recovery validation' if datastore_ids.empty?
            expected_datastore = Integer(datastore_ids[index] || datastore_ids.first)
            actual_datastore = image['DATASTORE_ID'].to_s.strip
            if actual_datastore.empty? && image.respond_to?(:info)
                rc = image.info
                if defined?(OpenNebula) && OpenNebula.respond_to?(:is_error?) && OpenNebula.is_error?(rc)
                    raise Error, "unable to refresh OpenNebula Image #{image.id} while validating recovery identity: #{rc.message}"
                end
                actual_datastore = image['DATASTORE_ID'].to_s.strip
            end
            if actual_datastore.empty? || Integer(actual_datastore) != expected_datastore
                raise Error, "OpenNebula Image #{image.id} datastore mismatch; expected #{expected_datastore}, got #{actual_datastore.inspect}"
            end
            true
        rescue ArgumentError, TypeError => e
            raise Error, "invalid OpenNebula Image recovery identity for disk #{index}: #{e.message}"
        end

        def ensure_recoverable_template!(state, images)
            previous_state = @layersentry_recovery_state
            previous_images = @layersentry_expected_template_image_ids
            @layersentry_recovery_state = state
            @layersentry_expected_template_image_ids = images.map { |image| Integer(image[:id] || image['id']) }
            template = layersentry_ensure_template_before_final_safety(state, images)
            validate_template_marker!(template, state)
            template
        ensure
            @layersentry_recovery_state = previous_state
            @layersentry_expected_template_image_ids = previous_images
        end

        def validate_template_marker!(template, state)
            layersentry_validate_template_before_final_safety(template, state)
            unless marker_value(template, 'LAYERSENTRY_SOURCE_PLATFORM').to_s.casecmp('HYPERV').zero?
                raise Error, "OpenNebula Template #{template.id} source-platform marker mismatch"
            end
            expected = Array(@layersentry_expected_template_image_ids)
            return true if expected.empty?

            actual = template_image_ids(template)
            unless actual == expected
                raise Error, "OpenNebula Template #{template.id} disk image-set mismatch; expected #{expected.inspect}, got #{actual.inspect}"
            end
            true
        end

        private

        def target_digest
            guest_os = @options[:guest_os].to_s.downcase
            virtio = guest_os == 'windows' ? (@options[:resolved_virtio_win] || resolve_virtio_win!) : ''
            secure_uefi = @options[:uefi_sec_path].to_s.strip
            HotUtil.digest({
                               'base_target_digest' => layersentry_target_digest_before_final_safety,
                               'virtio_win_artifact_digest' => virtio.to_s.empty? ? '' : trusted_artifact_digest(virtio, 'virtio-win bundle'),
                               'secure_uefi_artifact_digest' => secure_uefi.empty? ? '' : trusted_artifact_digest(secure_uefi, 'secure UEFI firmware')
                           })
        end

        def validate_production_transfer_security!
            return true unless Util.bool(@options[:http_transfer])

            raise Error, 'plain unauthenticated --http-transfer is not production-qualified for Hyper-V VM disks; use a secure shared/local datastore path or an authenticated TLS transfer mechanism'
        end

        def trusted_artifact_digest(path, label)
            original = File.expand_path(path.to_s)
            stat = File.lstat(original)
            if stat.symlink?
                target = File.realpath(original)
                return Digest::SHA256.hexdigest("symlink\0#{File.readlink(original)}\0#{secure_regular_file_digest(target, label)}")
            end
            if stat.file?
                return secure_regular_file_digest(original, label)
            end
            unless stat.directory?
                raise Error, "#{label} is not a regular file or directory: #{original}"
            end
            ensure_not_mutable_by_untrusted_users!(stat, label, original)

            digest = Digest::SHA256.new
            files = 0
            Dir.glob(File.join(original, '**', '*'), File::FNM_DOTMATCH).sort.each do |entry|
                base = File.basename(entry)
                next if base == '.' || base == '..'
                relative = entry.delete_prefix(original + File::SEPARATOR)
                entry_stat = File.lstat(entry)
                if entry_stat.directory?
                    ensure_not_mutable_by_untrusted_users!(entry_stat, label, entry)
                    digest.update("D\0#{relative}\0")
                    next
                end
                if entry_stat.symlink?
                    real = File.realpath(entry)
                    digest.update("L\0#{relative}\0#{File.readlink(entry)}\0#{secure_regular_file_digest(real, label)}\0")
                    files += 1
                    next
                end
                unless entry_stat.file?
                    raise Error, "#{label} contains unsupported special file #{entry}"
                end
                digest.update("F\0#{relative}\0#{secure_regular_file_digest(entry, label)}\0")
                files += 1
            end
            raise Error, "#{label} directory contains no files: #{original}" if files.zero?

            digest.hexdigest
        rescue Errno::ENOENT, Errno::EACCES => e
            raise Error, "unable to hash trusted #{label}: #{e.message}"
        end

        def secure_regular_file_digest(path, label)
            stat = File.lstat(path)
            raise Error, "#{label} target is not a regular non-symlink file: #{path}" unless stat.file? && !stat.symlink?
            ensure_not_mutable_by_untrusted_users!(stat, label, path)
            Digest::SHA256.file(path).hexdigest
        end

        def ensure_not_mutable_by_untrusted_users!(stat, label, path)
            mode = stat.mode & 0o777
            if (mode & 0o022) != 0
                raise Error, "#{label} is writable by group/other users and is not trusted: #{path} (mode #{format('%o', mode)})"
            end
            true
        end

        def template_image_ids(template)
            xml = template.to_xml.to_s
            document = REXML::Document.new(xml)
            ids = REXML::XPath.match(document, '//DISK/IMAGE_ID').map do |node|
                Integer(node.text.to_s.strip)
            end
            raise Error, "OpenNebula Template #{template.id} contains no IMAGE_ID disk bindings" if ids.empty?
            ids
        rescue REXML::ParseException, ArgumentError, TypeError => e
            raise Error, "unable to validate OpenNebula Template #{template.id} disk image set: #{e.message}"
        end
    end
end
