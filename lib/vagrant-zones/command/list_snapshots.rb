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

            options[:snapshot] = argv[0]
            puts options[:snapshot]
            options[:snapshot] = "none" if options[:snapshot].nil?
            puts options[:snapshot]
            
            with_target_vms(argv, provider: :zone) do |machine|
              if !options[:snapshot].nil? && options[:snapshot] != 'none'
                machine.action('list_zfs_snapshots', ui ,options[:snapshot] ) 
              end
            end
          end
        end
      end
   end
end