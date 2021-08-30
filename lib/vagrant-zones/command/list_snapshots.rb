module VagrantPlugins
  module ProviderZone
      module Command
        class ListSnapshots < Vagrant.plugin('2', :command)
          def execute
            options = {}       
            opts = OptionParser.new do |o|
              o.banner = 'Usage: vagrant zone zfssnapshot list [options]'
              o.on('--snapshot SNAPSHOTPATH', 'Specify snapshot path') do |p|
                options[:snapshot] = p
              end
            end

            argv = parse_options(opts)
            return unless argv

            unless argv.length <= 2
              @env.ui.info(opts.help)
              return
            end

            with_target_vms(argv, provider: :zone ) do |machine|
                driver  = machine.provider.driver
                
                driver.zfs(machine, @env.ui, 'list' )
              end

          end
        end
      end
   end
end