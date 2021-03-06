require "log4r"

module VagrantPlugins
	module ProviderZone
		module Action
			class Import
				def initialize(app, env)
					@logger = Log4r::Logger.new("vagrant_zone::action::import")
					@joyent_images_url = 'https://images.joyent.com/images/'
					@app = app
				end

				def validate_uuid_format(uuid)
					uuid_regex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
					return true if uuid_regex.match?(uuid.to_s.downcase)
				end

				def call(env)
					@machine = env[:machine]
					image    = @machine.config.vm.box
					curdir   = Dir.pwd
					datadir  = @machine.data_dir
					@logger.info("DATADIR #{datadir}")
					# If image ends on '.zss' it's a local ZFS snapshot which
					# should be used
					if image[-4, 4] == '.zss'
						if File.exist?(curdir + '/' + image)
							FileUtils.cp(curdir + '/' + image, datadir.to_s + '/' + image)
						elsif not File.exist?(datadir.to_s + '/' + image)
							raise Vagrant::Errors::BoxNotFound
						end
					## If image looks like an UUID, download the ZFS snapshot from
					## Joyent images server
					elsif validate_uuid_format(image)
						raise Vagrant::Errors::BoxNotFound if not check(image)
						download(image, datadir.to_s + '/' + image)
					## If it's a regular name (everything else), try to find it
					## on Vagrant Cloud
					else
						# Support zss format only for now
						box_format = env[:machine].box.metadata['format']
						if box_format.nil?
							raise Errors::NoBoxFormatSet
						elsif box_format != 'zss'
							raise Errors::WrongBoxFormatSet
						end

						box_image_file = env[:machine].box.directory.join('box.zss').to_s
						FileUtils.cp(env[:machine].box.directory.join('box.zss').to_s, datadir.to_s + '/' + image)
					end
					@app.call(env)
				end
				
				def check(uuid)
					`curl --output /dev/null --silent -r 0-0 --fail #{@joyent_images_url}/#{uuid}`
					return $?.success?
				end
				def download(uuid, dest)
					`curl --output #{dest} --silent #{@joyent_images_url}/#{uuid}/file`
					return $?.success?
				end
			end
		end
	end
end
