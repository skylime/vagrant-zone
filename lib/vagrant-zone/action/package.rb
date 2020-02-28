require "log4r"

module VagrantPlugins
	module ProviderZone
		module Action
			class Package
				def initialize(app, env)
					@logger = Log4r::Logger.new("vagrant_zone::action::import")
					@app = app
					env['package.output'] ||= 'package.box'
				end



				def call(env)
					@machine = env[:machine]
					@driver  = @machine.provider.driver

					boxname = env['package.output']
					raise "#{boxname}: Already exists" if File.exist?(boxname)

					tmp_dir = Dir.pwd + '/_tmp_package'
					tmp_img = tmp_dir + '/box.zss'
					Dir.mkdir(tmp_dir) unless File.exists?(tmp_dir)

					zonepath = @machine.provider_config.zonepath.sub!(/^\//, '')
					brand  = @machine.provider_config.brand
					kernel = @machine.provider_config.kernel

					snapshot_create(zonepath)
					snapshot_send(zonepath, tmp_img)
					snapshot_delete(zonepath)

					extra = ''
					@tmp_include = tmp_dir + '/_include'
					if env['package.include']
						extra = './_include'
						Dir.mkdir(@tmp_include)
						env['package.include'].each do |f|
							env[:ui].info("Including user file: #{f}")
							FileUtils.cp(f, @tmp_include)
						end
					end
					if env['package.vagrantfile']
						extra = './_include'
						Dir.mkdir(@tmp_include) unless File.directory?(@tmp_include)
						env[:ui].info('Including user Vagrantfile')
						FileUtils.cp(env['package.vagrantfile'], @tmp_include + '/Vagrantfile')
					end

					File.write(tmp_dir + '/metadata.json', metadata_content(brand, kernel))
					File.write(tmp_dir + '/Vagrantfile', vagrantfile_content(brand, kernel, zonepath))

					Dir.chdir(tmp_dir)
					assemble_box(boxname, extra)

					FileUtils.mv(tmp_dir + '/' + boxname, '../' + boxname)
					#FileUtils.rm_rf(tmp_dir)

					env[:ui].info('Box created')
					env[:ui].info('You can now add the box:')
					env[:ui].info("vagrant box add #{boxname} --name any_comfortable_name")

					@app.call(env)
				end

				def snapshot_create(zonepath)
					`pfexec zfs snapshot -r #{zonepath}@vagrant_boxing`
				end
				def snapshot_delete(zonepath)
					`pfexec zfs destroy #{zonepath}@vagrant_boxing`
				end
				def snapshot_send(zonepath, destination)
					`pfexec zfs send #{zonepath}@vagrant_boxing > #{destination}`
				end

				def metadata_content(brand, kernel)
					<<-EOF
					{
						"provider": "zone",
						"format": "zss",
						"brand": "#{brand}",
						"kernel": "#{kernel}"
					}
					EOF
				end

				def vagrantfile_content(brand, kernel, zonepath)
					<<-EOF
					Vagrant.configure("2") do |config|
						config.vm.provider :zone do |zone|
							zone.brand = "#{brand}"
							zone.kernel = "#{kernel}"
							zone.zonepath = "#{zonepath}"
						end
					end
					user_vagrantfile = File.expand_path('../_include/Vagrantfile', __FILE__)
					load user_vagrantfile if File.exists?(user_vagrantfile)
					EOF
				end

				def assemble_box(boxname, extra)
					`tar cvzf "#{boxname}" ./metadata.json ./Vagrantfile ./box.zss #{extra}`
				end
			end
		end
	end
end
