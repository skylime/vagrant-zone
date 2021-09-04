# coding: utf-8
require 'vagrant-zones/action'

module VagrantPlugins
	module ProviderZone
      module Command
      class Zone < Vagrant.plugin("2", :command)
        def self.synopsis
          "Manage zones and query zone information"
        end

        def initialize(argv, env)
          @main_args, @sub_command, @sub_args = split_main_and_subcommand(argv)

          @subcommands = Vagrant::Registry.new

          @subcommands.register(:zfssnapshot) do
            require File.expand_path("../zfssnapshot", __FILE__)
            ZFSSnapshot
          end
          @subcommands.register(:control) do
            require File.expand_path('../guest_power_controls', __FILE__)
            GuestPowerControls
          end
          @subcommands.register(:console) do
            require File.expand_path('../console', __FILE__)
            Console
          end
          super(argv, env)
        end
 
        def execute
          if @main_args.include?("-h") || @main_args.include?("--help")
            # Print the help for all the vagrant-zones commands.
            return help
          end

          command_class = @subcommands.get(@sub_command.to_sym) if @sub_command
          return help if !command_class || !@sub_command
          @logger.debug("Invoking command class: #{command_class} #{@sub_args.inspect}")

          # Initialize and execute the command class
          command_class.new(@sub_args, @env).execute
        end

        def help
          opts = OptionParser.new do |opts|
            opts.banner = "Usage: vagrant zone <subcommand> [<args>]"
            opts.separator ""
            opts.separator "Available subcommands:"

            # Add the available subcommands as separators in order to print them
            # out as well.
            keys = []
            @subcommands.each { |key, value| keys << key.to_s }

            keys.sort.each do |key|
              opts.separator "     #{key}"
            end

            opts.separator ""
            opts.separator "For help on any individual subcommand run `vagrant zone <subcommand> -h`"
          end

          @env.ui.info(opts.help, :prefix => false)
        end
      end
    end
  end
end