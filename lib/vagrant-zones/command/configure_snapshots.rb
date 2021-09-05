module VagrantPlugins
    module ProviderZone
      module Command
        # This is used to configure snapshots for the zone
        class ConfigureSnapshots < Vagrant.plugin('2', :command)
          def execute
            opts = OptionParser.new do |o|
              o.banner = 'Usage: vagrant zone zfssnapshot configure [options]'
            end
  
            argv = parse_options(opts)
            return unless argv
  
            with_target_vms(argv, provider: :zone) do |machine|
              machine.action('configure_zfs_snapshots')
            end
          end
        end
      end
    end
  end