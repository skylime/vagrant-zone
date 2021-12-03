# frozen_string_literal: true

require 'log4r'
module VagrantPlugins
  module ProviderZone
    module Action
      # This is used to package the VM into a box
      class Package
        def initialize(app, env)
          @logger = Log4r::Logger.new('vagrant_zones::action::import')
          @app = app
          env['package.output'] ||= 'package.box'
        end

        def call(env)
          @machine = env[:machine]
          @driver  = @machine.provider.driver
          config  = @machine.provider_config
          name = @machine.name
          boxname = env['package.output']
          raise "#{boxname}: Already exists" if File.exist?(boxname)

          tmp_dir = "#{Dir.pwd}/_tmp_package"
          tmp_img = "#{tmp_dir}/box.zss"
          Dir.mkdir(tmp_dir) unless File.exist?(tmp_dir)

          zonepath = config.zonepath.delete_prefix('/').to_s
          brand  = @machine.provider_config.brand
          kernel = @machine.provider_config.kernel
          vagrant_cloud_creator = @machine.provider_config.vagrant_cloud_creator

          env[:ui].info("==> #{name}: Creating a Snapshot of the box.")
          snapshot_create(zonepath)
          env[:ui].info("==> #{name}: Sending Snapshot to ZFS Send Sream image.")
          snapshot_send(zonepath, tmp_img)
          env[:ui].info("==> #{name}: Remove templated snapshot.")
          snapshot_delete(zonepath)

          extra = ''
          @tmp_include = "#{tmp_dir}/_include"
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
            FileUtils.cp(env['package.vagrantfile'], "#{@tmp_include}/Vagrantfile")
          end

          File.write("#{@tmp_dir}/metadata.json", metadata_content(brand, kernel, vagrant_cloud_creator, boxname))
          File.write("#{@tmp_dir}/Vagrantfile", vagrantfile_content(brand, kernel, zonepath))

          Dir.chdir(tmp_dir)
          assemble_box(boxname, extra)

          FileUtils.mv("#{tmp_dir}/boxname", "../#{boxname}")
          FileUtils.rm_rf(tmp_dir)

          env[:ui].info('Box created')
          env[:ui].info('You can now add the box:')
          env[:ui].info("vagrant box add #{boxname} --name any_name_you_want")

          @app.call(env)
        end

        def snapshot_create(zonepath)
          `pfexec zfs snapshot -r #{zonepath}/boot@vagrant_boxing`
          puts "pfexec zfs snapshot -r #{zonepath}/boot@vagrant_boxing"
        end

        def snapshot_delete(zonepath)
          `pfexec zfs destroy -r -F #{zonepath}/boot@vagrant_boxing`
        end

        def snapshot_send(zonepath, destination)
          `pfexec zfs send #{zonepath}/boot@vagrant_boxing > #{destination}`
        end

        def metadata_content(brand, _kernel, vagrant_cloud_creator, boxname)
          <<-ZONEBOX
          {
            "provider": "zone",
            "format": "zss",
            "brand": "#{brand}",
            "url": "https://app.vagrantup.com/#{vagrant_cloud_creator}/boxes/#{boxname}"
          }
          ZONEBOX
        end

        def vagrantfile_content(brand, _kernel, zonepath)
          <<-ZONEBOX
          Vagrant.configure('2') do |config|
            config.vm.provider :zone do |zone|
              zone.brand = "#{brand}"
              zone.zonepath = "#{zonepath}"
            end
          end
          user_vagrantfile = File.expand_path('../_include/Vagrantfile', __FILE__)
          load user_vagrantfile if File.exists?(user_vagrantfile)
          ZONEBOX
        end

        def assemble_box(boxname, extra)
          `tar cvzf "#{boxname}" ./metadata.json ./Vagrantfile ./box.zss #{extra}`
        end
      end
    end
  end
end
