# coding: utf-8
module VagrantPlugins
	module ProviderZone
      module Command
        class ZFSSnapshot < Vagrant.plugin("2", :command)
          def execute
            options = {}
            opts = OptionParser.new do |o|
              o.banner = "Usage: vagrant zone zfs-snapshot [options]"
            end
  
            argv = parse_options(opts)
            return if !argv
  
            with_target_vms(argv, :provider => :vagrant_zones) do |machine|
              machine.action('list_zfs_snapshot')
            end
          end
        end
      end
    end
  end