# frozen_string_literal: true

module VagrantPlugins
  module ProviderZone
      module Command
        # This is used to acces the zone via console, zlogin
        class ZloginConsole < Vagrant.plugin('2', :command)
          def execute
            options = {}       
            opts = OptionParser.new do |o|
              o.banner = 'Usage: vagrant zone console zlogin [options]'
              o.on('--ip <host_ip>', 'Specify host IP to listen on') do |p|
                options[:ip] = p
              end
              o.on('--port <port>', 'Specify port to listen on') do |p|
                options[:port] = p
              end
            end

            argv = parse_options(opts)
            return unless argv

            unless argv.length <= 4
              @env.ui.info(opts.help)
              return
            end

            if options[:ip].nil?
              options[:ip] = "127.0.0.1"
              
            end
            unless options[:ip]  =~ Resolv::IPv4::Regex ? true : false
              options[:ip] = "127.0.0.1"
            end

            puts options[:ip]


            if options[:port].nil?
              options[:port] = nil
            end
            unless options[:port]  =~ /\d/
              options[:port] = nil
            end

            puts options[:port]

            with_target_vms(argv, provider: :zone ) do |machine|
                driver  = machine.provider.driver
                driver.console(machine, @env.ui, 'zlogin', options[:ip], options[:port] )
              end
          end
        end
      end
   end
end