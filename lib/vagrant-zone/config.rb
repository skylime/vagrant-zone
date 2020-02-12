require "vagrant"

module VagrantPlugins
	module ProviderZone
		class Config < Vagrant.plugin('2', :config)
			attr_accessor :brand
			attr_accessor :autoboot
			attr_accessor :kernel
			attr_accessor :zonepath
			attr_accessor :memory

			def initialize
				# pkgsrc, lx, bhyve, kvm, illumos
				@brand    = UNSET_VALUE
				@autoboot = false
				@kernel   = UNSET_VALUE
				@zonepath = UNSET_VALUE
				@memory   = UNSET_VALUE
			end
		end
	end
end
