require "log4r"
require 'vagrant-zone/util/timer'
require 'vagrant/util/retryable'

module VagrantPlugins
	module ProviderZone
		module Action
			class WaitTillUp
				include Vagrant::Util::Retryable

				def initialize(app, env)
					@logger = Log4r::Logger.new("vagrant_zone::action::import")
					@app = app
				end

				def call(env)
					@machine = env[:machine]
					@driver  = @machine.provider.driver

					# Initialize metrics if they haven't been
					env[:metrics] ||= {}

					env[:metrics]['instance_ssh_time'] = Util::Timer.time do
						retryable(on: Errors::TimeoutError, tries: 60) do
							# If we're interrupted don't worry about waiting
							next if env[:interrupted]
							loop do
								break if env[:interrupted]
								break if env[:machine].communicate.ready?
							end
						end
					end
					# if interrupted above, just terminate immediately
					return terminate(env) if env[:interrupted]
					@logger.info("Time for SSH ready: #{env[:metrics]['instance_ssh_time']}")

					@app.call(env)
				end
			end
		end
	end
end
