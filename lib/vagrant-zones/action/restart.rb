# encoding: utf-8
require "log4r"
require 'vagrant-zones/util/timer'
require 'vagrant/util/retryable'

module VagrantPlugins
	module ProviderZone
		module Action
			class Restart
				include Vagrant::Util::Retryable
				def initialize(app, env)
					@logger = Log4r::Logger.new("vagrant_zones::action::restart")
					@app = app
				end

				def call(env)
					@machine = env[:machine]
					@driver  = @machine.provider.driver
					puts  env[:machine].state.id 
					ui = env[:ui]			
					@driver.control(@machine, env[:ui], "restart")
					@app.call(env)
				end
			end
		end
	end
end
