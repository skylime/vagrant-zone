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
					# Initialize metrics if they haven't been
					env[:metrics] ||= {}


					env[:metrics]['instance_boot_time'] = Util::Timer.time do
						retryable(on: Errors::TimeoutError, tries: 1) do
							# If we're interrupted don't worry about waiting
							next if env[:interrupted]
							loop do
								break if env[:interrupted]
								break if @driver.waitforboot(@machine, ui)
							end
						end
					end



					
					
                    return terminate(env) if env[:interrupted]
                    ui.info(I18n.t("vagrant_zones.ssh_ready") + " in #{env[:metrics]['instance_ssh_time']} Seconds")
                    @app.call(env)
				end
			end
		end
	end
end
