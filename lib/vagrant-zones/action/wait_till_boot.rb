# frozen_string_literal: true

require 'log4r'
require 'vagrant-zones/util/timer'
require 'vagrant/util/retryable'

module VagrantPlugins
  module ProviderZone
    module Action
      # This is used wait till the zone is booted
      class WaitTillBoot
        include Vagrant::Util::Retryable

        def initialize(app, env)
          @logger = Log4r::Logger.new('vagrant_zones::action::import')
          @app = app
        end

        def call(env)
          @machine = env[:machine]
          @driver  = @machine.provider.driver
          ui = env[:ui]
          # Initialize metrics if they haven't been
          env[:metrics] ||= {}
          env[:metrics]['instance_boot_time'] = Util::Timer.time do
            break if env[:interrupted]
            break if @driver.waitforboot(@machine, ui)
          end

                    return terminate(env) if env[:interrupted]
                    ui.info(I18n.t('vagrant_zones.boot_ready') + " in #{env[:metrics]['instance_boot_time']} Seconds")
                    @app.call(env)
        end
      end
    end
  end
end
