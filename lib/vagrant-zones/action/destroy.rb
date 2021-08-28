# coding: utf-8
require "log4r"
require "securerandom"
require "digest/md5"

module VagrantPlugins
	module ProviderZone
		module Action
			class Destroy
				def initialize(app, env)
					@logger = Log4r::Logger.new("vagrant_zones::action::import")
					@app = app
				end

				def call(env)
					@machine = env[:machine]
					@driver  = @machine.provider.driver
					@driver.halt(@machine, env[:ui])
					
					@driver.destroy(@machine, env[:ui])
					@driver.delete_dataset(@machine, env[:ui])
					@app.call(env)
				end
			end
		end
	end
end
