require "log4r"
require 'vagrant-zones/util/timer'
require 'vagrant/util/retryable'

module VagrantPlugins
	module ProviderZone
		module Action
			class WaitTillBoot
				include Vagrant::Util::Retryable

				def initialize(app, env)
					@logger = Log4r::Logger.new("vagrant_zones::action::import")
					@app = app
				end

				def call(env)
					@machine = env[:machine]
					@driver  = @machine.provider.driver
					ui = env[:ui]
					@driver.waitforboot(@machine, ui)
					
					@app.call(env)
				end
			end
		end
	end
end
