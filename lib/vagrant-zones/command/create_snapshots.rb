module VagrantPlugins
    module ProviderZone
      module Command
        class CreateSnapshots < Vagrant.plugin('2', :command)
          def execute
            options = {}
            opts = OptionParser.new do |o|
              o.banner = 'Usage: vagrant zone zfssnapshot create [options]'
            end
  
            argv = parse_options(opts)
            return unless argv
  
            with_target_vms(argv, provider: :zone) do |machine|
              machine.action('create_zfs_snapshots')
            end
          end
        end
      end
    end
  end