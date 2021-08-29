# coding: utf-8
module VagrantPlugins
	module ProviderZone
    module Action
      class DeleteSnapshots
        def initialize(app, _env)
          @app = app
        end
        def call(env)
          @machine = env[:machine]
          @driver  = @machine.provider.driver
          @driver.zfs(@machine, env[:ui]), 'destroy')
          @app.call(env)
        end
      end
    end
  end
end
