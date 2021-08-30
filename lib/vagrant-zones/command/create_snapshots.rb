module VagrantPlugins
  module ProviderZone
      module Command
        class CreateSnapshots < Vagrant.plugin('2', :command)
          def execute
            options = {}       
            opts = OptionParser.new do |o|
              o.banner = 'Usage: vagrant zone zfssnapshot list [options]'
              o.on('--dataset SNAPSHOTPATH', 'Specify snapshot path') do |p|
                options[:dataset] = p
              end
              o.on('--snapshot_name @SNAPSHOTNAME', 'Specify snapshot name') do |p|
                options[:snapshot_name] = p
              end
            end

            argv = parse_options(opts)
            return unless argv

            unless argv.length <= 2
              @env.ui.info(opts.help)
              return
            end

            if options[:snapshot_name].nil?
              puts "name nil"
            end

            with_target_vms(argv, provider: :zone ) do |machine|
                driver  = machine.provider.driver
                driver.zfs(machine, @env.ui, 'create', options[:dataset],  options[:snapshot_name] )
              end

          end
        end
      end
   end
end