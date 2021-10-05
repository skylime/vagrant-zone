# frozen_string_literal: true

require 'resolv'
module VagrantPlugins
  module ProviderZone
    module Command
      # This is used to start a WebVNC console to the guest
      class WebVNCConsole < Vagrant.plugin('2', :command)
        def execute
          options = {}
          opts = OptionParser.new do |o|
            o.banner = 'Usage: vagrant zone console webvnc [options]'
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

          options[:ip] = '127.0.0.1' if options[:ip].nil?
          options[:ip] = nil unless options[:ip] =~ Resolv::IPv4::Regex ? true : false

          options[:port] = nil unless options[:port] =~ /\d/

          with_target_vms(argv, provider: :zone) do |machine|
            driver = machine.provider.driver
            driver.console(machine, 'webvnc', options[:ip], options[:port])
          end
        end
      end
    end
  end
end
