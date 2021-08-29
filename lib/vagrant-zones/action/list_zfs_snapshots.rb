# coding: utf-8
module VagrantPlugins
	module ProviderZone
    module Action
      class ListSnapshots
        def initialize(app, _env, snapshot)
          @app = app
          @snapshot = snapshot
        end
        def call(env)
          puts env
          @machine = env[:machine]
          @driver  = @machine.provider.driver
          @driver.zfs(@machine, env[:ui], 'list')
          @app.call(env)
        end
      end
    end
  end
end


