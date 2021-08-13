require "log4r"
require "securerandom"
require "digest/md5"

module VagrantPlugins
	module ProviderZone
		module Action
			class Network
				def initialize(app, env)
					@logger = Log4r::Logger.new("vagrant_zones::action::import")
					@app = app
				end

				def call(env)
					@machine = env[:machine]
					@driver  = @machine.provider.driver

					@driver.create_vnic(@machine, env[:ui])
					@app.call(env)
				end
			end
		end
	end
end
