# coding: utf-8
module VagrantPlugins
	module ProviderZone
      module Command
        class ZFSSnapshot < Vagrant.plugin("2", :command)
          def initialize(argv, env)
            @main_args, @sub_command, @sub_args = split_main_and_subcommand(argv)
  
            @subcommands = Vagrant::Registry.new
            @subcommands.register(:list) do
              require File.expand_path('../list_images', __FILE__)
              ListSnapshots
            end
            @subcommands.register(:create) do
              require File.expand_path('../create_image', __FILE__)
              CreateSnapshots
            end
            @subcommands.register(:delete) do
              require File.expand_path('../delete_image', __FILE__)
              DeleteSnapshots
            end
  
            super(argv, env)
          end

          def execute
            if @main_args.include?('-h') || @main_args.include?('--help')
              # Print the help for all the vagrant-zones commands.
              return help
            end
  
            command_class = @subcommands.get(@sub_command.to_sym) if @sub_command
            return help if !command_class || !@sub_command
            @logger.debug("Invoking command class: #{command_class} #{@sub_args.inspect}")
  
            # Initialize and execute the command class
            command_class.new(@sub_args, @env).execute
          end

          def execute
            options = {}
            opts = OptionParser.new do |o|
              o.banner = "Usage: vagrant zone zfs-snapshot [options]"
            end
  
            argv = parse_options(opts)
            return if !argv
  
            with_target_vms(argv, :provider => :vagrant_zones) do |machine|
              machine.action('zfs_snapshot')
            end
          end
        end
      end
    end
  end