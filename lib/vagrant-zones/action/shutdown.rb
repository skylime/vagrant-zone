# coding: utf-8
require "log4r"

module VagrantPlugins
	module ProviderZone
		module Action
			class Shutdown
				def initialize(app, env)
					@logger = Log4r::Logger.new("vagrant_zones::action::import")
					@app = app
				end

				def call(env)
					@machine = env[:machine]
					@driver  = @machine.provider.driver
					@driver.control(@machine, env[:ui], "shutdown")
					@app.call(env)
				end
			end
		end
	end
end
