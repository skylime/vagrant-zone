# coding: utf-8
module VagrantPlugins
	module ProviderZone
      module Command
        # This is used to start a console to the zone via WebVNC, VNC or Serial/Telnet
        class Console < Vagrant.plugin("2", :command)
          def initialize(argv, env)
            @main_args, @sub_command, @sub_args = split_main_and_subcommand(argv)
  
            @subcommands = Vagrant::Registry.new
            @subcommands.register(:vnc) do
              require File.expand_path('../vnc_console', __FILE__)
              VNCConsole
            end
            @subcommands.register(:zlogin) do
              require File.expand_path('../zlogin_console', __FILE__)
              ZloginConsole
            end
            @subcommands.register(:webvnc) do
              require File.expand_path('../webvnc_console', __FILE__)
              WebVNCConsole
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

          def help
            opts = OptionParser.new do |opts|
              opts.banner = "Usage: vagrant zone console <subcommand> [<args>]"
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
              opts.separator "For help on any individual subcommand run `vagrant zone console <subcommand> -h`"
            end
            @env.ui.info(opts.help, :prefix => false)
          end
        end
      end
    end
  end