# coding: utf-8
require 'net/http'
require 'vagrant-zones/util/subprocess'
require 'pp'
require "vagrant/box_metadata"
require "vagrant/util/downloader"
require "vagrant/util/platform"
require "vagrant/util/safe_chdir"
require "vagrant/util/subprocess"

module VagrantPlugins
	module ProviderZone
		module Action
			# This will import the zone boot image from the cloud, cache or file
			class Import
				def initialize(app, env)
					@logger = Log4r::Logger.new("vagrant_zones::action::import")
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
					@driver  = @machine.provider.driver
					ui = env[:ui]
					ui.info(I18n.t("vagrant_zones.meeting"))
					ui.info(I18n.t("vagrant_zones.detecting_box"))
					p @machine.inspect
					print(@machine)
					ui.info("DATADIR ==> #{datadir}")
					# If image ends on '.zss' it's a local ZFS snapshot which
					# should be used
					if image[-4, 4] == '.zss'
						if File.exist?(curdir + '/' + image)
							FileUtils.cp(curdir + '/' + image, datadir.to_s + '/' + image)
							ui.info(I18n.t("vagrant_zones.zfs_snapshot_stream_detected"))
						elsif not File.exist?(datadir.to_s + '/' + image)
							raise Vagrant::Errors::BoxNotFound
						end
					## If image looks like an UUID, download the ZFS snapshot from
					## Joyent images server
					elsif validate_uuid_format(image)
						raise Vagrant::Errors::BoxNotFound if not check(image,ui)
						uri = URI("#{@joyent_images_url}#{image}/file")
						Net::HTTP.start(uri.host, uri.port,	:use_ssl => uri.scheme == 'https') do |http|
							request = Net::HTTP::Get.new uri
							http.request request do |response|
								file_size = response['content-length'].to_i
								amount_downloaded = 0
								ratelimit = 0
								rate = 500
								large_file = datadir.to_s + '/' + image
								open large_file, 'wb' do |io| # 'b' opens the file in binary mode 
								  response.read_body do |chunk|
									io.write chunk
									amount_downloaded += chunk.size
									ui.rewriting do |uiprogress|
										ratelimit += 1
										if ratelimit >= rate
											uiprogress.clear_line()
											status = "%.2f%%" % (amount_downloaded.to_f / file_size * 100)
											uiprogress.info(I18n.t("vagrant_zones.importing_joyent_image") + "#{image} ==> ", new_line: false)
											uiprogress.report_progress(status, 100, false)
											ratelimit = 0
										end
									end
								  end
								  ui.clear_line()
								end
							  end
							end
						ui.info(I18n.t("vagrant_zones.joyent_image_uuid_detected") + image)

					## If it's a regular name (everything else), try to find it
					## on Vagrant Cloud
					
					else
						# Support zss format only for now, use other images and convert later
						puts @machine.inspect
						if !env[:machine].box.metadata['format'].nil?
						  box_format = env[:machine].box.metadata['format']
						end
						if box_format.nil?
							raise Errors::NoBoxFormatSet
						elsif box_format == 'ovf'
							## Code to try to convert existing box
							ui.info(I18n.t("vagrant_zones.detected_ovf_format"))
						elsif box_format != 'zss'  
							## Code to try to convert existing box
							raise Errors::WrongBoxFormatSet
						end
						ui.info(I18n.t("vagrant_zones.vagrant_cloud_box_detected") + image)
						box_image_file = env[:machine].box.directory.join('box.zss').to_s
						if(File.file?(box_image_file)) 

							command = "#{@pfexec} pv -n #{box_image_file} > #{datadir.to_s + '/box.zss'} "
							Util::Subprocess.new command do |stdout, stderr, thread|
								ui.rewriting do |uiprogress|
									uiprogress.clear_line()
									uiprogress.info(I18n.t("vagrant_zones.importing_box_image") + "#{image} ==> ", new_line: false)
									uiprogress.report_progress(stderr, 100, false)
								end
							end
						else 
							puts 'file not found, need to import from cloud'
						end
						
						ui.clear_line()  
					end
					@app.call(env)
				end
				
				def check(uuid, env_ui)
					`curl --output /dev/null --silent  -r 0-0 --fail #{@joyent_images_url}/#{uuid}`
					env_ui.info(I18n.t("vagrant_zones.joyent_image_uuid_verified") + "#{@joyent_images_url}#{uuid}")
					return $?.success?
				end
			end
		end
	end
end
