# coding: utf-8
module VagrantPlugins
	module ProviderZone
      module Action
        class zfsSnapshots
          def initialize(app, env)
            @app = app
            @logger = Log4r::Logger.new("vagrant_zones::action::delete_server")
          end

          def call(env)
            if env[:machine].id
              env[:ui].info (env[:machine].id)
            end
            @app.call(env)
        end
      end
    end
  end