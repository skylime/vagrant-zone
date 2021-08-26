require "vagrant"
require "log4r"

module VagrantPlugins
	module ProviderZone
		autoload :Driver, 'vagrant-zones/driver'

		class Provider < Vagrant.plugin('2', :provider)
			def initialize(machine)
				@logger = Log4r::Logger.new("vagrant::provider::zone")
				@machine = machine
			end

			def driver
				return @driver if @driver
				@driver = Driver.new(@machine)
			end

			def ssh_info				
				# We just return nil if were not able to identify the VM's IP and
				# let Vagrant core deal with it like docker provider does
				return nil if state.id != :running
				ip = driver.get_ip_address(@machine)
				user = driver.user(@machine)
				userkey = driver.userprivatekeypath(@machine).to_s
				vagrantuserpassword = driver.vagrantuserpass(@machine).to_s
				passwordauth = "yes" 
				return nil if !ip
				portnumber = "22"
				unless portnumber.to_s.nil? || portnumber.to_s == 0
					portnumber = driver.sshport(@machine).to_s 
				end
				ssh_info = {
					host: ip,
					port: portnumber,
					password: vagrantuserpassword,
					username: user,
					private_key_path: userkey,
					PasswordAuthentication: 'passwordauth'
				}
					
			end

			# This should return an action callable for the given name.
			#
			# @param [Symbol] name Name of the action.
			# @return [Object] A callable action sequence object, whether it
			#		is a proc, object, etc.
			def action(name)
				# Attrmpt to get the action method from the Action class if it 
				# exists, otherwise return nil to show that we don't support the
				# given action
				action_method = "action_#{name}"
				return Action.send(action_method) if Action.respond_to?(action_method)
				nil
			end

			# This method is called if the underying machine ID changes. Providers
			# can use this method to load in new data for the actual backing
			# machine or to realize that the machine is now gone (the ID can
			# become `nil`). No parameters are given, since the underlying machine
			# is simply the machine instance given to this object. And no
			# return value is necessary.
			def machine_id_changed
			end

			def state
				id = @machine.id
				state_id = nil
				state_id = :not_created unless @machine.id
				state_id = driver.state(@machine) if @machine.id && !state_id


				# This is a special pseudo-state so that we don't set the
				# NOT_CREATED_ID while we're setting up the machine. This avoids
				# clearing the data dir.
				state_id = :preparing if @machine.id == 'preparing'

				# Get the short and long description
				short = state_id.to_s.tr('_', ' ')

				# If we're not created, then specify the special ID flag
				if state_id == :not_created
					state_id = Vagrant::MachineState::NOT_CREATED_ID
				end

				# Return the MachineState object
				Vagrant::MachineState.new(state_id, short, short)
			end

		end
	end
end
