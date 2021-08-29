# coding: utf-8
module VagrantPlugins
	module ProviderZone
    module Action
      class ListSnapshots
        def initialize(app, _env)
          @app = app
        end
        def call(env, snapshot)
          @machine = env[:machine]
          @driver  = @machine.provider.driver
          @driver.zfs(@machine, env[:ui], 'list', snapshot)
          @app.call(env)
        end
      end
    end
  end
end


