require "vagrant"

module VagrantPlugins
	module ProviderZone
		module Errors
			class VagrantZoneError < Vagrant::Errors::VagrantError
				error_namespace('vagrant_zone.errors')
			end

			class SystemVersionIsTooLow < VagrantZoneError
				error_key(:system_version_too_low)
			end

			class HasNoRootPrivilege < VagrantZoneError
				error_key(:has_no_root_privilege)
			end

			class ExecuteError < VagrantZoneError
				error_key(:execute_error)
			end
		end
	end
end
