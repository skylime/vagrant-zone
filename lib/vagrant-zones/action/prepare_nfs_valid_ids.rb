# coding: utf-8
require "log4r"
require "securerandom"
require "digest/md5"

module VagrantPlugins
	module ProviderZone
		module Action
			class PrepareNFSValidIds

				def initialize(app, env)
					@logger = Log4r::Logger.new("vagrant_zones::action::prepare_nfs_valid_ids")
					@app = app
				end

				def call(env)
					env[:nfs_valid_ids] = [env[:machine].id]
					@app.call(env)
				end
			end
		end
	end
end
