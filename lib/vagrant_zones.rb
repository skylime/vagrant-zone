require 'pathname'

module VagrantPlugins
	module ProviderZone
		lib_path = Pathname.new(File.expand_path("../vagrant-zones", __FILE__))

		autoload :Action, lib_path.join('action')
		autoload :Executor, lib_path.join('executor')
		autoload :Driver, lib_path.join('driver')
		autoload :Errors, lib_path.join('errors')

		# This function returns the path to the source of this plugin
		#
		# @return [Pathname]
		def self.source_root
			@source_root ||= Pathname.new(File.expand_path("../../", __FILE__))
		end
	end
end

begin
	require 'vagrant'
  rescue LoadError
	raise 'The Vagrant Libvirt plugin must be run within Vagrant.'
end

if Vagrant::VERSION < '2'
	raise 'The Vagrant Libvirt plugin is only compatible with Vagrant 2+.'
end

require "vagrant-zones/plugin"
