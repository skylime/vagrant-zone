# encoding: utf-8
require "log4r"
require 'vagrant-zones/util/timer'
require 'vagrant/util/retryable'

module VagrantPlugins
	module ProviderZone
		module Action
			# This is used to shutdown the zone
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
					
					ui.info(I18n.t("vagrant_zones.graceful_shutdown_started"))
					@driver.control(@machine, env[:ui], "shutdown")

					env[:metrics] ||= {}
					env[:metrics]['instance_ssh_time'] = Util::Timer.time do
						retryable(on: Errors::TimeoutError, tries: 300) do
							# If we're interrupted don't worry about waiting
							next if env[:interrupted]
							loop do
								break if env[:interrupted]
								break if !env[:machine].communicate.ready?
							end
						end
					end
					ui.info(I18n.t("vagrant_zones.graceful_shutdown_complete"))


					@driver.halt(@machine, env[:ui])
					@app.call(env)
				end
			end
		end
	end
end
