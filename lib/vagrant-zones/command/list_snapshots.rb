module VagrantPlugins
  module ProviderZone
      module Command
        class ListSnapshots < Vagrant.plugin('2', :command)
          def execute
            options = {}
            

         
            opts = OptionParser.new do |o|
              o.banner = 'Usage: vagrant zone zfssnapshot list [options]'
              #o.on('--snapshot SNAPSHOTPATH', 'Specify snapshot path') do |p|
              #  options[:snapshot] = p
              #end
            end

            argv = parse_options(opts)
            return unless argv

            unless argv.length <= 1
              @env.ui.info(opts.help)
              return
            end

            snapshot = "none" if argv[0].nil?
            snapshot = argv[0] if !argv[0].nil?
            
            with_target_vms(sargv, provider: :zone) do |machine|

                puts snapshot
                machine.action('list_zfs_snapshots' , machine , snapshot ) 
              end

          end
        end
      end
   end
end