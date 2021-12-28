# frozen_string_literal: true

require 'log4r'
require 'securerandom'
require 'digest/md5'

module VagrantPlugins
  module ProviderZone
    module Action
      # This is used to setup the zone
      class Setup
        def initialize(app, _env)
          @logger = Log4r::Logger.new('vagrant_zones::action::import')
          @app = app
        end

        def call(env)
          @machine = env[:machine]
          @driver = @machine.provider.driver
          @driver.setup(@machine, env[:ui])
          @app.call(env)
        end
      end
    end
  end
end
