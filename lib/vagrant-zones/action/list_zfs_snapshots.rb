# coding: utf-8
module VagrantPlugins
	module ProviderZone
    module Action
      class ListSnapshots
        def initialize(app, _env)
          @app = app
        end
        def call(env)
          if env[:machine].id
            env[:ui].info (env[:machine].id)
            env[:ui].info ("test")
          end
        @app.call(env)
        end
      end
    end
  end
end


