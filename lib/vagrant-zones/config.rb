require "vagrant"
## Do not Modify this File! Modify the Hosts.yml, Hosts.rb, or Vagrantfile!

module VagrantPlugins
	module ProviderZone
		class Config < Vagrant.plugin('2', :config)
			attr_accessor :brand
			attr_accessor :autoboot
			attr_accessor :kernel
			attr_accessor :zonepath
			attr_accessor :zonepathsize
			attr_accessor :diskif
			attr_accessor :netif
			attr_accessor :cdrom_path
			attr_accessor :disk1path
			attr_accessor :disk1size
			attr_accessor :cpus
			attr_accessor :memory
			attr_accessor :vagrant_user
			attr_accessor :vagrant_user_key
			attr_accessor :vagrant_user_private_key_path
			attr_accessor :setup_wait
			attr_accessor :clean_shutdown_time
			attr_accessor :dhcp
			attr_accessor :vagrant_user_pass
			attr_accessor :firmware_type
			attr_accessor :vm_type
			attr_accessor :partition_id
			attr_accessor :shared_disk_enabled
			attr_accessor :shared_dir
			attr_accessor :acpi
			attr_accessor :os_type
			attr_accessor :vnc
			attr_accessor :console
			attr_accessor :hostbridge
			attr_accessor :sshport
			attr_accessor :rdpport

			
			
			
			def initialize

				# pkgsrc, lx, bhyve, kvm, illumos
				@brand    			= 'bhyve'
				@autoboot 			= true
				@kernel   			= UNSET_VALUE
				@zonepath 			= UNSET_VALUE
				@zonepathsize 			= UNSET_VALUE
				@disk1pathsize 			= UNSET_VALUE
				@cdrom_path			= "none"
				@disk1path 			= "none"
				@shared_dir			= Dir.pwd
				@os_type			= 'generic'
				@shared_disk_enabled		= true
				@vnc				= false
				@console			= false
				@memory   			= '4G'
				@diskif   			= 'virtio-blk'
				@netif   			= 'virtio-net-viona'
				@cpus   			= 2
				@hostbridge   			= 'i440fx'
				@acpi 				= 'on'
				@firmware_type 			= "compatability"
				@firmware 			= UNSET_VALUE
				@dhcp   			= false
				@setup_wait  			= 30
				@clean_shutdown_time  		= 300
				@vmtype   			= 'production'
				@vm_type   			= UNSET_VALUE
				@partition_id  			= '0000'
				@sshport  			= '22'
				@rdpport  			= '3389'
				@vagrant_user   		= 'vagrant'
				@vagrant_user_pass  		= 'vagrant'
				@vagrant_user_private_key_path  =  UNSET_VALUE
				@vagrant_user_key  		= 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NOTd0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcWyLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQ== vagrant insecure public key'

				
				case @firmware_type
				when "compatability"  
					@firmware 		= 'BHYVE_RELEASE_CSM'
					when "UEFI"  
					@firmware 		= 'BHYVE_RELEASE'
					when "BIOS"  
					@firmware 		= 'BHYVE_CSM'
					when "UEFI_DEBUG"  
					@firmware 		= 'BHYVE_DEBUG'
					when "BIOS_DEBUG"  
					@firmware 		= 'BHYVE_RELEASE_CSM' 
				else  
					@firmware 		= "BHYVE_RELEASE_CSM"
				end	
				
				case @vmtype
				when 'template'
					@vm_type 		= "1"
				when 'development'
					@vm_type 		= "2"
				when 'production'
					@vm_type 		= "3"
				when 'firewall'
					@vm_type 		= "4"
				when 'other'
					@vm_type 		= "5"
				else
					@vm_type 		= "3"
				end
			end
		end
	end
end
