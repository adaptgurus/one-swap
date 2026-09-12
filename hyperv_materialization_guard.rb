# -------------------------------------------------------------------------- #
# LayerSentry Hyper-V pre-materialization source-off guard                    #
# -------------------------------------------------------------------------- #

require_relative 'hyperv_source_security_hardening'

module OneSwapHyperV
    class HotCoordinator
        def verify_source_off
            state = HotUtil.load_state(@state_path)
            raise Error, 'hot migration state is missing; source-Off verification cannot proceed' unless state
            unless state['operation_id'].to_s == @operation_id.to_s && state['vm_name'].to_s == @vm_name.to_s
                raise Error, 'hot migration durable state does not belong to this operation/source VM'
            end
            unless %w[IMPORTED DONE].include?(state['phase'].to_s)
                raise Error, "source-Off verification requires imported hot state, found #{state['phase'].inspect}"
            end

            metadata = @source.inspect(@vm_name, require_state: 'Off')
            unless metadata['VMId'].to_s.casecmp(state['source_vm_id'].to_s).zero?
                raise Error, 'source VM identity changed before target materialization'
            end
            observed_digest = HotUtil.digest(stable_metadata(metadata))
            unless observed_digest == state['metadata_digest'].to_s
                raise Error, 'Hyper-V source topology/security changed after cutover; target materialization is blocked'
            end

            {
                'status' => 'SOURCE_OFF_VERIFIED',
                'operation_id' => @operation_id,
                'source_vm_id' => metadata['VMId'],
                'source_state' => metadata['State'],
                'metadata_digest' => observed_digest
            }
        end
    end
end

class OneSwapHelper
    def hyperv_hot_verify_source_off(vm_name, options)
        OneSwapHyperV::HotCoordinator.new(self, options.merge(:name => vm_name, :format => 'raw')).verify_source_off
    end
end
