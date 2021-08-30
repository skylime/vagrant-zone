# coding: utf-8
module VagrantPlugins
	module ProviderZone
    module Action
      class ListSnapshots
        def initialize(app, _env)
          @app = app
          puts app
        end
        def call(env)
          @machine = env[:machine]
          @driver  = @machine.provider.driver
          p env
          @driver.zfs(@machine, env[:ui], 'list' , @app)
          @app.call(env)
        end
      end
    end
  end
end


