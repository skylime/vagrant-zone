require "log4r"
require "securerandom"
require "digest/md5"

module VagrantPlugins
	module ProviderZone
		module Action
			class Create
				def initialize(app, env)
					@logger = Log4r::Logger.new("vagrant_zone::action::import")
					@app = app
				end

				def call(env)
					@machine = env[:machine]
					@driver  = @machine.provider.driver

					@machine.id = SecureRandom.uuid
					@driver.create_dataset(@machine, env[:ui])
					@driver.zonecfg(@machine, env[:ui])
					@driver.install(@machine, env[:ui])
					@app.call(env)
				end
			end
		end
	end
end
