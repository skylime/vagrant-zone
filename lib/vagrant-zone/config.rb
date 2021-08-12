require "vagrant"

module VagrantPlugins
	module ProviderZone
		class Config < Vagrant.plugin('2', :config)
			attr_accessor :brand
			attr_accessor :autoboot
			attr_accessor :kernel
			attr_accessor :zonepath
			attr_accessor :zonepathsize
			attr_accessor :disk1path
			attr_accessor :disk1size
			attr_accessor :cpus
			attr_accessor :vlan
			attr_accessor :memory
			attr_accessor :vagrant_user
			attr_accessor :vagrant_user_key
			attr_accessor :vagrant_user_private_key_path
			attr_accessor :setup_wait
			attr_accessor :dhcp
			
			def initialize
				# pkgsrc, lx, bhyve, kvm, illumos
				@brand    = UNSET_VALUE
				@autoboot = true
				@kernel   = UNSET_VALUE
				@zonepath = UNSET_VALUE
				@zonepathsize = UNSET_VALUE
				@disk1pathsize = UNSET_VALUE
				@disk1size = UNSET_VALUE
				@memory   = UNSET_VALUE
				@cpus   = UNSET_VALUE
				@vlan   = UNSET_VALUE
				@dhcp   = false
				@setup_wait  = 120
				@vagrant_user   = 'vagrant'
				@vagrant_user_private_key_path   =  UNSET_VALUE
				@vagrant_user_key   = 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NOTd0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcWyLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQ== vagrant insecure public key'
			end
		end
	end
end
