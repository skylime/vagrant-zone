require "log4r"
require "fileutils"
require "digest/md5"
require "io/console"
require "ruby_expect"
require 'netaddr'
require 'ipaddr'
require "vagrant/util/numeric"
require 'pty'
require 'expect'
require "vagrant"
require 'vagrant-zones/util/timer'

module VagrantPlugins
	module ProviderZone
		class Driver
			attr_accessor :executor
			def initialize(machine)
				@logger = Log4r::Logger.new("vagrant_zones::driver")
				@machine = machine
				@executor = Executor::Exec.new

				if Process.uid == 0
					@pfexec = ''
				else
					sudo = system('sudo -v')
					if sudo
						@pfexec = 'sudo'
					else
						@pfexec = 'pfexec'
					end
				end
			end

			
			def state(machine)
				uuid = machine.id
				name = machine.name
				vm_state = execute(false, "#{@pfexec} zoneadm -z #{name} list -p | awk -F: '{ print $3 }'")
				
				if vm_state == 'running'
					:running
				elsif vm_state == 'configured'
					:preparing
				elsif vm_state == 'installed'
					:stopped
				elsif vm_state == 'incomplete'
					:incomplete
				else
					:not_created
				end
				
			end

			def execute(*cmd, **opts, &block)
				@executor.execute(*cmd, **opts, &block)
			end



			def install(machine, ui)
                                config = machine.provider_config
				box  = @machine.data_dir.to_s + '/' + @machine.config.vm.box
				name = @machine.name
				if config.brand == 'lx'
					puts "==> #{name}: Installing LX Zone."
					execute(false, "#{@pfexec} zoneadm -z #{name} install -s #{box}")
				end
				if config.brand == 'bhyve'
					puts "==> #{name}: Installing bhyve Zone."
					execute(false, "#{@pfexec} zoneadm -z #{name} install")
				end
				if config.brand == 'kvm'
					puts "==> #{name}: Installing KVM Zone."
					execute(false, "#{@pfexec} zoneadm -z #{name} install")
				end
				if config.brand == 'illumos'
					puts "==> #{name}: Installing Illumos Zone."
					execute(false, "#{@pfexec} zoneadm -z #{name} install")
				end
			end
			
			## Boot the Machine
			def boot(machine, ui)
				name = @machine.name
				puts "==> #{name}: Starting the zone."
				execute(false, "#{@pfexec} zoneadm -z #{name} boot")
			end
			
			
			def get_ip_address(machine)
				config = machine.provider_config
				machine.config.vm.networks.each do |_type, opts|
					if _type.to_s == "public_network"
						ip        = opts[:ip].to_s
						defrouter = opts[:gateway]
						return nil if ip.length == 0
						return ip.gsub /\t/, ''
					end
				end
			end
			
			
			## Create Network Interfaces
			def vnic(machine, ui, state)
				config = machine.provider_config
				dhcpenabled = config.dhcp
				name = @machine.name
				machine.config.vm.networks.each do |_type, opts|
					if _type.to_s == "public_network"
						link 		= opts[:bridge]
						nic_number	= opts[:nic_number].to_s
						netmask 	= IPAddr.new(opts[:netmask].to_s).to_i.to_s(2).count("1")
						ip        	= opts[:ip].to_s
						defrouter 	= opts[:gateway].to_s
						if ip.length == 0
							ip = nil
						else
							ip = ip.gsub /\t/, ''
						end
						mac  		= 'auto'
						vlan 		= 1
						if !opts[:mac].nil?
							mac  = opts[:mac]
						end
						if !opts[:type].nil?
							nictype  = opts[:nictype]
						end
						if !opts[:nameserver1].nil?
							nameserver1  = opts[:nameserver1].to_s
						else
							nameserver1  = "1.1.1.1"
						end
						if !opts[:nameserver2].nil?
							nameserver2  = opts[:nameserver2].to_s
						else
							nameserver2  = "1.0.0.1"
						end
						case nictype
						when /external/
						  nic_type = "e"
						when /internal/
						  nic_type = "i"
						when /carp/
						  nic_type = "c"
						when /management/
						  nic_type = "m"
						when /host/
						  nic_type = "h"
						else
						  nic_type = "e"
						end
						vnic_name = "vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number}"
						if state == "create"
							if !opts[:vlan].nil?
								vlan =  opts[:vlan]
								puts "==> #{name}: Creating VNIC: #{vnic_name} with VLAN: #{vlan}."
								execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} -v #{vlan} #{vnic_name}")
							else
								execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} #{vnic_name}")
							end		
						elsif state == "delete"
							vnic_configured = execute(false, "#{@pfexec} dladm show-vnic | grep #{vnic_name} | awk '{ print $1 }' ")
							if vnic_configured == "#{vnic_name}"
								execute(false, "#{@pfexec} dladm delete-vnic #{vnic_name}")
							end
						elsif state == "config"
							nic_attr = %{add net
	set physical=#{vnic_name}
end							}
							File.open('zone_config', 'a') do |f|
								f.puts nic_attr
							end
						elsif state == "setup"
							## Remove old installer netplan config
							puts "==> #{name}: Removing stale netplan configurations."
							zlogin(machine, "rm -rf /etc/netplan/00-installer-config.yaml")
							responses=[]
							PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read,zlogin_write,pid|
								zlogin_read.expect(/\n/) { |msg| zlogin_write.printf('ifconfig -s -a | grep -v lo | tail -1 | awk \'{ print $1 }\'') }
								Timeout.timeout(30) do
									loop do
										zlogin_read.expect(/\r\n/) { |line|  responses.push line}
										if responses[-1].to_s.match(/(enp\w*)\d/)
											vmnic = responses[-1].to_s
											puts ""
											puts ""
											puts ""
											puts vmnic
											puts vmnic.to_s
											puts ""
											puts ""
											puts ""
											puts ""
									        	break
										end
									end
								end
								Process.kill("HUP",pid)
							end
							
							if config.dhcp
								puts "==> #{name}: Generate fresh netplan configurations."
								netplan = %{network:
  version: 2
  ethernets:
    #{vmnic}:
      dhcp-identifier: mac
      dhcp4: yes
      dhcp6: yes
      nameservers:
        addresses: [#{nameserver1} , #{nameserver2}]
	    							}
								puts netplan
								zlogin(machine, "touch /etc/netplan/#{vnic_name}.yaml")
								zlogin(machine, "echo '#{netplan}' > /etc/netplan/#{vnic_name}.yaml")
								puts "==> #{machine.name} ==> DHCP is not yet Configured for use, this may not work"
							else
								## Create new netplan config
								puts "==> #{name}: Generate fresh netplan configurations."
								netplan = %{network:
  version: 2
  ethernets:
    #{vmnic}:
      dhcp-identifier: mac
      dhcp4: no
      dhcp6: no
      addresses: [#{ip}/#{netmask}]
      gateway4: #{defrouter}
      nameservers:
        addresses: [#{nameserver1} , #{nameserver2}]
	    							}
								puts netplan
								zlogin(machine, "touch /etc/netplan/#{vnic_name}.yaml")
								zlogin(machine, "echo '#{netplan}' > /etc/netplan/#{vnic_name}.yaml")
							end
							
							## Apply the Configuration
							puts "==> #{name}: Applying the network configuration"
							zlogin(machine, 'netplan apply')
							
						elsif state == "get_ip"
							if config.dhcp
								PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read,zlogin_write,pid|
									zlogin_read.expect(/\n/) { |msg| zlogin_write.printf("hostname -I") }
									Timeout.timeout(30) do
										loop do
											zlogin_read.expect(/\r\n/) { |line|  responses.push line}
											if responses[-1].to_s.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)
												ip = responses[-1].to_s
												return nil if ip.length == 0
												return ip.gsub /\t/, ''
										        	break
											elsif responses[-1].to_s.match(/Error Code: \b(?![0]\b)\d{1,4}\b/)
										        	raise "==> #{name}: \nCommand: \n ==> #{cmd} \nFailed with: \n responses[-1]"
											elsif responses[-1].nil?
										                break
											end
										end
									end
									Process.kill("HUP",pid)
								end
								puts "==> #{machine.name} ==> DHCP is not yet Configured for use"
							else
								if opts[:managed]
									return nil if ip.length == 0
									return ip.gsub /\t/, ''
								end
							end
						end
					end
				end
			end

			def create_dataset(machine, ui)
				name = @machine.name
				config  = machine.provider_config				
				dataset = config.zonepath.delete_prefix("/").to_s + "/boot"
				datadir  = machine.data_dir
				datasetroot = config.zonepath.delete_prefix("/").to_s
				if config.brand == 'lx'	
					puts "==> #{name}: Creating zoned ZFS dataset for LX zone"
					execute(false, "#{@pfexec} zfs create -o zoned=on -p #{dataset}")
				end
				if config.brand == 'bhyve'
					puts "==> #{name}: Creating ZFS root dataset for bhyve zone"
					execute(false, "#{@pfexec} zfs create #{datasetroot}")
					puts "==> #{name}: Creating ZFS boot volume dataset for bhyve zone"
					execute(false, "#{@pfexec} zfs create -V #{config.zonepathsize} #{dataset}")
					puts "==> #{name}: Importing Template to ZFS boot volume for bhyve zone"
					execute(false, "#{@pfexec} zfs recv -F #{dataset} < #{datadir.to_s}/box.zss'")
				elsif config.disk1
					disk1path = config.disk1.delete_prefix("/").to_s
					disk1size = config.disk1_size.to_s
					puts "==> #{name}: Creating additional ZFS volume for bhyve zone"
					execute(false, "#{@pfexec} zfs create -V #{disk1size} #{disk1path}")
				end
			end

			def delete_dataset(machine, ui)
				name = @machine.name
				config = machine.provider_config
				puts "==> #{name}: Destroy dataset: #{config.zonepath.delete_prefix("/")}."
				execute(false, "#{@pfexec} zfs destroy -r #{config.zonepath.delete_prefix("/")}")
			end

			def zonecfg(machine, ui)
				name = @machine.name
				## Seperate commands out to indvidual functions like Network, Dataset, and Emergency Console
				config = machine.provider_config
				attr = ''
				if config.brand == 'lx'
					puts "==> #{name}: Generating Configuration for LX Branded Zone"
					machine.config.vm.networks.each do |_type, opts|
						index = 1
						if _type.to_s == "public_network"
							@ip        = opts[:ip].to_s
							@network   = NetAddr.parse_net(opts[:ip].to_s + '/' + opts[:netmask].to_s)
							@defrouter = opts[:gateway]
						end
					end
					allowed_address  = @ip + @network.netmask.to_s
					attr = %{
add attr
	set name=kernel-version
	set type=string
	set value=#{config.kernel}
end
add net
	set physical=#{machine.name}0
	set global-nic=auto
	add property (name=gateway,value="#{@defrouter.to_s}")
	add property (name=ips,value="#{allowed_address}")
	add property (name=primary,value="true")
end
add capped-memory
	set physical=#{config.memory}
	set swap=#{config.memory}
	set locked=#{config.memory}
end
add dataset
	set name=#{config.zonepath.delete_prefix("/")}/boot
end
set max-lwps=2000
					}
				end
				if config.brand == 'bhyve'
					## General Configuration
					puts "==> #{name}: Generating Configuration for bhyve Branded Zone"
					attr = %{create
set zonepath=#{config.zonepath}/path
set brand=#{config.brand}
set autoboot=#{config.autoboot}
set ip-type=exclusive
add attr
	set name=acpi
	set type=string
	set value=#{config.acpi}
end
add attr
	set name=vcpus
	set type=string
	set value=#{config.cpus}
end
add attr
	set name=ram
	set type=string
	set value=#{config.memory}
end
add attr
	set name=bootrom
	set type=string
	set value=#{config.firmware}
end
add attr
	set name=hostbridge
	set type=string
	set value=#{config.hostbridge}
end
add attr
	set name=diskif
	set type=string
	set value=#{config.diskif}
end
add attr
	set name=netif
	set type=string
	set value=#{config.netif}
end
add device
	set match=/dev/zvol/rdsk#{config.zonepath}/boot
end
add attr
	set name=bootdisk
	set type=string
	set value=#{config.zonepath.delete_prefix("/")}/boot
end
add attr
	set name=type
	set type=string
	set value=#{config.os_type}
end					}
				end
				File.open('zone_config', 'w') do |f|
					f.puts attr
				end
				
				## Shared Disk Configurations
				if config.shared_disk_enabled
					shared_disk_attr = %{add fs
	set dir=/vagrant
	set special=#{config.shared_dir}
	set type=lofs
end					}				
					File.open('zone_config', 'a') do |f|
						f.puts shared_disk_attr
					end
				end
				
				## CDROM Configurations
				if config.cdrom_path != 'none'
					puts config.cdrom_path
					cdrom_attr = %{add attr
    set name=cdrom
    set type=string
    set value=#{config.cdrom_path}
end
add fs
    set dir=#{config.cdrom_path}
    set special=#{config.cdrom_path}
    set type=lofs
    add options ro
    add options nodevices
end					}
					File.open('zone_config', 'a') do |f|
						f.puts cdrom_attr
					end
				end

				
				### Passthrough PCI Devices
				#if config.ppt_devices == 'none'
				#	puts config.ppt
				#	puts config.config.ppt
				#	ppt_attr = %{
#add device
#  set match=/dev/ppt0
#end
#add attr
#  set name=ppt0
#  set type=string
#  set value="slot0"
#end
				#	}
				#	ppt_data_attr = %{
#{ppt_data}
				#	}
				
				#	File.open('zone_config', 'a') do |f|
				#		f.puts ppt_data_attr
				#	end
				#end

				
				## Additional Disk Configurations
				if config.disk1path != 'none'
					additional_disk_attr = %{add device
	set match=/dev/zvol/rdsk#{config.zonepath}/disk1
end
add attr
	set name=disk
	set type=string
	set value=#{config.zonepath.delete_prefix("/")}/disk1
end
					}
					File.open('zone_config', 'a') do |f|
						f.puts additional_disk_attr
					end
				end
				
				## Nic Configurations
				state = "config"
				vnic(@machine, ui, state)

				## Write out Config
				exit = %{exit}
				File.open('zone_config', 'a') do |f|
					f.puts exit
				end
				
				puts "==> #{name}: Exporting generated zonecfg configuration."
				## Export config to zonecfg
				execute(false, "cat zone_config | #{@pfexec} zonecfg -z #{machine.name}")
			end

			def check_zone_support(machine, ui)
				config = machine.provider_config
				box  = @machine.data_dir.to_s + '/' + @machine.config.vm.box
				name = @machine.name

				## Detect if Virtualbox is Running
				## Kernel, KVM, and Bhyve cannot run conncurently with Virtualbox:
				### https://forums.virtualbox.org/viewtopic.php?f=11&t=64652
				puts "==> #{name}: Checking for Virtualbox"
				result = execute(false, "#{@pfexec} VBoxManage list runningvms  ; echo $?")
				raise Errors::VirtualBoxRunningConflictDetected if result == 0
				
				if config.brand == 'lx'
					puts "==> #{name}: No LX Zones Checked, We assume that you have all the Appropriate packages"
					return
				end
				if config.brand == 'bhyve'			
					## Check for  bhhwcompat
					result = execute(true, "#{@pfexec} test -f /usr/sbin/bhhwcompat  ; echo $?")
					if result == 1
						execute(true, "#{@pfexec} curl -o /usr/sbin/bhhwcompat https://downloads.omnios.org/misc/bhyve/bhhwcompat && #{@pfexec} chmod +x /usr/sbin/bhhwcompat")
						result = execute(true, "#{@pfexec} test -f /usr/sbin/bhhwcompat  ; echo $?")
						raise Errors::MissingCompatCheckTool if result == 0
					end
					
					# Check whether OmniOS version is lower than r30
					
					cutoff_release = "1510380"
					cutoff_release = cutoff_release[0..-2].to_i 
					puts "==> #{name}: Checking OmniOS Release against cutoff:  #{cutoff_release}"
					release = File.open('/etc/release', &:readline)
					release = release.scan(/\w+/).values_at( -1)
					release = release[0][1..-2].to_i 
					raise Errors::SystemVersionIsTooLow if release  < cutoff_release
	
					# Check Bhyve compatability
					puts "==> #{name}: Checking bhyve installation environment."
					result = execute(false, "#{@pfexec} bhhwcompat -s")
					raise Errors::MissingBhyve if result.length == 1 
				end
     			end
			
			def setup(machine, ui)
				config = machine.provider_config
				name = machine.name
				
				puts "==> #{name}: Waiting for the Machine to boot..."
				waitforboot(machine)
				
				## Check if already setup and skip the following
				if machine.config.ssh.insert_key
					puts "==> #{name}: Inserting SSH Key"
					zlogin(machine, "echo #{config.vagrant_user_key} > \/home\/#{config.vagrant_user}\/.ssh\/authorized_keys")
					zlogin(machine, "chown -R #{config.vagrant_user}:#{config.vagrant_user} \/home\/#{config.vagrant_user}\/.ssh")
					zlogin(machine, "chmod 600 \/home\/#{config.vagrant_user}\/.ssh\/authorized_keys")
				end
				
				### Nic Configurations
				state = "setup"
				vnic(@machine, ui, state)
				
			end
			
			def waitforboot(machine)
				name = @machine.name
				config = machine.provider_config
				responses = []
				PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read,zlogin_write,pid|
				        if zlogin_read.expect(/Last login: /)
						puts "==> #{name}: Machine Booted, Checking for Login Access/Prompt over TTYS0"
						Timeout.timeout(config.setup_wait) do
							loop do
				        		       	zlogin_read.expect(/\n/) { |line|  responses.push line}
								if responses[-1].to_s.match(/:~#/)
									break
								elsif responses[-1].to_s.match(/login: /)
									## Code to try to login with username and password
									puts "==> #{name}: Could not login as Root, Check if Root Autologin Works"
								end
							end
						end
					end
					Process.kill("HUP",pid)
				end
			end	
				
			def zlogin(machine, cmd)
				name = @machine.name
				config = machine.provider_config
				responses = []
				PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read,zlogin_write,pid|
					zlogin_read.expect(/\n/) { |msg| zlogin_write.printf("#{cmd} \; echo \"Error Code: $?\"\n") }
					Timeout.timeout(30) do
						loop do
							zlogin_read.expect(/\r\n/) { |line|  responses.push line}
							if responses[-1].to_s.match(/Error Code: 0/)
						        	break
							elsif responses[-1].to_s.match(/Error Code: \b(?![0]\b)\d{1,4}\b/)
						        	raise "==> #{name}: \nCommand: \n ==> #{cmd} \nFailed with: \n responses[-1]"
							elsif responses[-1].nil?
						                break
							end
						end
					end
					Process.kill("HUP",pid)
				end
			end

			def user(machine)
				config = machine.provider_config
				user = config.vagrant_user
				return user
			end
			
			def userprivatekeypath(machine)
				config = machine.provider_config
				userkey = config.vagrant_user_private_key_path.to_s
				return userkey
			end
			
			def sshport(machine)
				config = machine.provider_config
				accessport = config.sshport.to_s
				return accessport
			end

			def rdpport(machine)
				config = machine.provider_config
				accessport = config.rdpport.to_s
				return accessport
			end
			
			def vagrantuserpass(machine)
				config = machine.provider_config
				vagrantuserpass = config.vagrant_user_pass.to_s
				return vagrantuserpass
			end

			def halt(machine, ui)
				name = @machine.name
				config = machine.provider_config
				vm_state = execute(false, "#{@pfexec} zoneadm -z #{name} list -p | awk -F: '{ print $3 }'")
				vm_configured = execute(false, "#{@pfexec} zoneadm list -i | grep  #{name} || true")
				if vm_state == "running"
					begin
						puts "==> #{name}: Attempting Graceful Shutdown"
						status = Timeout::timeout(config.clean_shutdown_time) {
						execute(false, "#{@pfexec} zoneadm -z #{name} shutdown")
					 }
					rescue Timeout::Error
  						puts "==> #{name}: VM failed to Shutdown in alloted time #{config.clean_shutdown_time.to_i}"
						begin halt_status = Timeout::timeout(60) {
							execute(false, "#{@pfexec} zoneadm -z #{name} halt")
						}
						rescue Timeout::Error
							raise "==> #{name}: VM failed to halt in alloted time 60 after waiting to shutdown for #{config.clean_shutdown_time.to_i}"
						end
					end
				end
			end
			
			def destroy(machine, id)
				name = @machine.name
				
				## Ensure machine is halted
				puts "==> #{name}: Halting Zone"
				
				## Check if it has a presence in zoneadm and if no presence in zoneadm destroy zonecfg
				vm_configured = execute(false, "#{@pfexec} zoneadm list -i | grep  #{name} || true")
				if vm_configured != name
					puts "==> #{name}: Removing zonecfg configuration"
					execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
				end
				
				## Check state in zoneadm
				vm_state = execute(false, "#{@pfexec} zoneadm -z #{name} list -p | awk -F: '{ print $3 }'")
				
				## If state is seen, uninstall from zoneadm and destroy from zonecfg
				if vm_state == 'incomplete' || vm_state == 'configured' || vm_state ==  "installed"
					puts "==> #{name}: Uninstalling Zone and Removing zonecfg configuration"
					execute(false, "#{@pfexec} zoneadm -z #{name} uninstall -F")
					puts "==> #{name}: Removing zonecfg configuration"
					execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
				end

				### Nic Configurations
				puts "==> #{name}: Deleting Associated VNICs"
				state = "delete"
				vnic(@machine, id, state)
				
				### Check State of additional Disks
				puts "==> #{name}: Deleting Associated Disks"
				#disks_configured = execute(false, "#{@pfexec}  zfs list ")

			end
			
		end
	end
end
