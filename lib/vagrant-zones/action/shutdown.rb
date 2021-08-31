# encoding: utf-8
require "log4r"
require 'vagrant-zones/util/timer'
require 'vagrant/util/retryable'

module VagrantPlugins
	module ProviderZone
		module Action
			class Shutdown
				include Vagrant::Util::Retryable
				def initialize(app, env)
					@logger = Log4r::Logger.new("vagrant_zones::action::shutdown")
					@app = app
				end

				def call(env)
					@machine = env[:machine]
					@driver  = @machine.provider.driver
					ui = env[:ui]			
					@driver.control(@machine, env[:ui], "shutdown")
					sleep 60
					@driver.halt(@machine, env[:ui])
					@app.call(env)
				end
			end
		end
	end
end
