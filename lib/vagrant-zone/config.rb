require "vagrant"

module VagrantPlugins
	module ProviderZone
		class Config < Vagrant.plugin('2', :config)
			attr_accessor :brand
			attr_accessor :autoboot
			attr_accessor :kernel
			attr_accessor :zonepath
			attr_accessor :zonepathsize
			attr_accessor :memory

			def initialize
				# pkgsrc, lx, bhyve, kvm, illumos
				@brand    = UNSET_VALUE
				@autoboot = true
				@kernel   = UNSET_VALUE
				@zonepath = UNSET_VALUE
				@zonepathsize = UNSET_VALUE
				@memory   = UNSET_VALUE
			end
		end
	end
end
