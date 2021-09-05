# encoding: utf-8
require "vagrant"
## Do not Modify this File! Modify the Hosts.yml, Hosts.rb, or Vagrantfile!
module VagrantPlugins
	module ProviderZone
		# This is used define the variables for the project
		class Config < Vagrant.plugin('2', :config)
			attr_accessor :brand
			attr_accessor :autoboot
			attr_accessor :kernel
			attr_accessor :zonepath
			attr_accessor :zonepathsize
			attr_accessor :diskif
			attr_accessor :netif
			attr_accessor :cdroms
			attr_accessor :disk1path
			attr_accessor :disk1size
			attr_accessor :cpus
			attr_accessor :cpu_configuration
			attr_accessor :complex_cpu_conf
			attr_accessor :memory
			attr_accessor :vagrant_user
			attr_accessor :vagrant_user_private_key_path
			attr_accessor :setup_wait
			attr_accessor :clean_shutdown_time
			attr_accessor :dhcp
			attr_accessor :vagrant_user_pass
			attr_accessor :firmware_type
			attr_accessor :firmware
			attr_accessor :vm_type
			attr_accessor :partition_id
			attr_accessor :shared_disk_enabled
			attr_accessor :shared_dir
			attr_accessor :acpi
			attr_accessor :os_type
			attr_accessor :console
			attr_accessor :consoleport
			attr_accessor :console_onboot
			attr_accessor :hostbridge
			attr_accessor :sshport
			attr_accessor :rdpport
			attr_accessor :override
			attr_accessor :additional_disks
			attr_accessor :cloud_init_enabled
			attr_accessor :dns
			
			def initialize
				# pkgsrc, lx, bhyve, kvm, illumos
				@brand    						= 'bhyve'
				@additional_disks				= nil
				@autoboot 						= true
				@kernel   						= UNSET_VALUE
				@zonepath 						= '/rpool/myvm'
				@zonepathsize 					= '20G'
				@cdroms							= nil
				@shared_dir						= nil
				@os_type						= 'generic'
				@shared_disk_enabled			= true
				@consoleport					= nil
				@console_onboot					= 'false'
				@console						= 'webvnc'
				@memory   						= '4G'
				@diskif   						= 'virtio-blk'
				@netif   						= 'virtio-net-viona'
				@cpus   						= 2
				@cpu_configuration				= 'simple'
				@complex_cpu_conf   			= UNSET_VALUE
				@hostbridge   					= 'i440fx'
				@acpi 							= 'on'
				@firmware_type 					= "compatability"
				@firmware 						= UNSET_VALUE
				@setup_wait  					= 60
				@clean_shutdown_time  			= 300
				@dns				  			= [{"nameserver" => "1.1.1.1"},{"nameserver" => "1.0.0.1"}]
				@vmtype   						= 'production'
				@vm_type   						= UNSET_VALUE
				@partition_id	  				= '0000'
				@sshport  						= '22'
				@rdpport  						= '3389'
				@vagrant_user   				= 'vagrant'
				@vagrant_user_pass  			= 'vagrant'
				@vagrant_user_private_key_path  = './id_rsa'
				@override						= false
				@cloud_init_enabled				= false
				
				case @firmware_type
					when "compatability"  
						@firmware 				= 'BHYVE_RELEASE_CSM'
					when "UEFI"  
						@firmware		 		= 'BHYVE_RELEASE'
					when "BIOS"  
						@firmware 				= 'BHYVE_CSM'
					when "UEFI_DEBUG"  
						@firmware 				= 'BHYVE_DEBUG'
					when "BIOS_DEBUG"  
						@firmware 				= 'BHYVE_RELEASE_CSM' 
				else  
					@firmware 					= "BHYVE_RELEASE_CSM"
				end	
				
				case @vmtype
					when 'template'
						@vm_type 				= "1"
					when 'development'
						@vm_type 				= "2"
					when 'production'
						@vm_type 				= "3"
					when 'firewall'
						@vm_type 				= "4"
					when 'other'
						@vm_type		 		= "5"
				else
					@vm_type 					= "3"
				end
			end
		end
	end
end
