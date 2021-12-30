# frozen_string_literal: true

require 'log4r'
require 'vagrant-zones/util/timer'
require 'vagrant/util/retryable'

module VagrantPlugins
  module ProviderZone
    module Action
      # This is used to shutdown the zone
      class Shutdown
        include Vagrant::Util::Retryable
        def initialize(app, _env)
          @logger = Log4r::Logger.new('vagrant_zones::action::shutdown')
          @app = app
        end

        def call(env)
          @machine = env[:machine]
          @driver  = @machine.provider.driver
          name = @machine.name
          ui = env[:ui]

          ui.info(I18n.t('vagrant_zones.graceful_shutdown_started'))
          @driver.control(ui, 'shutdown')

          10.times do
            state_id = @driver.state(@machine)
            sleep 10 if state_id == 'running'
            puts state_id
          end

          env[:metrics] ||= {}
          env[:metrics]['instance_ssh_time'] = Util::Timer.time do
            retryable(on: Errors::TimeoutError, tries: 300) do
              # If we're interrupted don't worry about waiting
              break if env[:interrupted]
              break unless env[:machine].communicate.ready?
            end
          end
          
          10.times do
            state_id = @driver.state(@machine)
            sleep 10 if state_id == 'running'
            ui.info(I18n.t('vagrant_zones.graceful_shutdown_complete')) unless state_id == 'running'
            puts state_id
          end
         
          env[:metrics] ||= {}
          env[:metrics]['instance_ssh_time'] = Util::Timer.time do
            retryable(on: Errors::TimeoutError, tries: 300) do
              # If we're interrupted don't worry about waiting
              vm_state = @driver.state(@machine)
              sleep 10 if vm_state == 'running'
              next if env[:interrupted]
              break unless vm_state == 'running'
            end
          end
          @driver.halt(env[:ui])
          @app.call(env)
        end
      end
    end
  end
end
