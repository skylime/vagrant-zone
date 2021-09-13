# frozen_string_literal: true

require 'log4r'
require 'securerandom'
require 'digest/md5'

module VagrantPlugins
  module ProviderZone
    module Action
      # This is use to define the network
      class Network
        def initialize(app, env)
          @logger = Log4r::Logger.new('vagrant_zones::action::import')
          @app = app
        end

        def call(env)
          @machine = env[:machine]
          @driver  = @machine.provider.driver
          state = 'create'
          @driver.network(@machine, env[:ui], state)
          @app.call(env)
        end
      end
    end
  end
end
