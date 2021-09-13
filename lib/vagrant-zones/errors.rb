# frozen_string_literal: true

require 'vagrant'

module VagrantPlugins
  module ProviderZone
    module Errors
      class VagrantZonesError < Vagrant::Errors::VagrantError
        error_namespace('vagrant_zones.errors')
      end

      class SystemVersionIsTooLow < VagrantZonesError
        error_key(:system_version_too_low)
      end

      class MissingCompatCheckTool < VagrantZonesError
        error_key(:missing_compatability_check_tool)
      end

      class MissingBhyve < VagrantZonesError
        error_key(:missing_bhyve)
      end

      class HasNoRootPrivilege < VagrantZonesError
        error_key(:has_no_root_privilege)
      end

      class ExecuteError < VagrantZonesError
        error_key(:execute_error)
      end

      class TimeoutError < VagrantZonesError
        error_key(:timeout_error)
      end

      class VirtualBoxRunningConflictDetected < VagrantZonesError
        error_key(:virtual_box_running_conflict_detected)
      end

      class NotYetImplemented < VagrantZonesError
        error_key(:not_yet_implemented)
      end

      class InvalidBrand < VagrantZonesError
        error_key(:invalid_brand)
      end
    end
  end
end
