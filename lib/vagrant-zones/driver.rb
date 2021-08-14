require "log4r"
require "fileutils"
require "digest/md5"
require "io/console"
require "ruby_expect"
require 'netaddr'
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

			## Convert Subnet Mask into CIDR Notation
			def to_cidr(dotted_mask)
			  NetAddr::CIDR.create('0.0.0.0/'+dotted_mask).netmask
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

			def get_ip_address(machine)
				config = machine.provider_config
				dhcpenabled = config.dhcp
				if dhcpenabled
					raise "==> #{machine.name} ==> DHCP is not yet Configured for use"
				else
					machine.config.vm.networks.each do |_type, opts|
						index = 1
						if _type.to_s == "public_network"
							ip        = opts[:ip].to_s
							defrouter = opts[:gateway]
							return nil if ip.length == 0
							return ip.gsub /\t/, ''
						end

					end
				end
			end

			def install(machine, ui)
                                config = machine.provider_config
				box  = @machine.data_dir.to_s + '/' + @machine.config.vm.box
				name = @machine.name
				if config.brand == 'lx'
					execute(false, "#{@pfexec} zoneadm -z #{name} install -s #{box}")
				end
				if config.brand == 'bhyve'
					execute(false, "#{@pfexec} zoneadm -z #{name} install")
				end
				if config.brand == 'kvm'
					execute(false, "#{@pfexec} zoneadm -z #{name} install")
				end
				if config.brand == 'illumos'
					execute(false, "#{@pfexec} zoneadm -z #{name} install")
				end
			end
			
			## Boot the Machine
			def boot(machine, ui)
				name = @machine.name
				execute(false, "#{@pfexec} zoneadm -z #{name} boot")
			end
			
			## Create Network Interfaces
			def vnic(machine, ui, state)
				config = machine.provider_config
				machine.config.vm.networks.each do |_type, opts|
					index = 1
					nic_number = index
					if _type.to_s == "public_network"
						link = opts[:bridge]
						mac  = 'auto'
						vlan = 1
						if !opts[:mac].nil?
							mac  = opts[:mac]
						end
						if !opts[:type].nil?
							nictype  = opts[:nictype]
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
						if state == "create"
							if !opts[:vlan].nil?
								vlan =  opts[:vlan]
								execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} -v #{vlan} vnic#{nic_type}#{config.vm_type}#{nic_number}-#{config.partition_id}")
							else
								execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} vnic#{nic_type}#{config.vm_type}#{nic_number}-#{config.partition_id}")
							end		
						elsif state == "delete"
							vnic_configured = execute(false, "#{@pfexec} dladm show-vnic | grep vnic#{nic_type}#{config.vm_type}#{nic_number}-#{config.partition_id} | awk '{ print $1 }' ")
							if vnic_configured == "vnic#{nic_type}#{config.vm_type}#{nic_number}-#{config.partition_id}"
								execute(false, "#{@pfexec} dladm delete-vnic vnic#{nic_type}#{config.vm_type}#{nic_number}-#{config.partition_id}")
							end
						elsif state == "config"
							nic_attr = %{
								add net
									set physical=vnic#{nic_type}#{config.vm_type}#{nic_number}-#{config.partition_id}
								end
							}
							additional_nics_data = %{
								#{nic_attr}
							}
							File.open('zone_config', 'a') do |f|
								f.puts additional_nics_data
							end
						end
					end
				end
			end

			def create_dataset(machine, ui)
				config  = machine.provider_config				
				dataset = config.zonepath.delete_prefix("/").to_s + "/boot"
				datadir  = machine.data_dir
				datasetroot = config.zonepath.delete_prefix("/").to_s
				if config.brand == 'lx'					
					execute(false, "#{@pfexec} zfs create -o zoned=on -p #{dataset}")
				end
				if config.brand == 'bhyve'
					execute(false, "#{@pfexec} zfs create #{datasetroot}")
					execute(false, "#{@pfexec} zfs create -V #{config.zonepathsize} #{dataset}")
					execute(false, "#{@pfexec} zfs recv -F #{dataset} < #{datadir.to_s}/box.zss'")
				elsif config.disk1
					disk1path = config.disk1.delete_prefix("/").to_s
					disk1size = config.disk1_size.to_s
					execute(false, "#{@pfexec} zfs create -V #{disk1size} #{disk1path}")
				end
			end

			def delete_dataset(machine, ui)
				config = machine.provider_config
				execute(false, "#{@pfexec} zfs destroy -r #{config.zonepath.delete_prefix("/")}")
			end

			def zonecfg(machine, ui)
				## Seperate commands out to indvidual functions like Network, Dataset, and Emergency Console
				config = machine.provider_config
				config.shared_dir = Dir.pwd
				attr = ''
				if config.brand == 'lx'
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
					attr = %{
						create
						set zonepath=#{config.zonepath}/path
						set brand=#{config.brand}
						set autoboot=#{config.autoboot}
						set ip-type=exclusive
						add attr
							set name="acpi"
							set type="string"
							set value="#{config.acpi}"
						end
						add attr
							set name="vcpus"
							set type="string"
							set value=#{config.cpus}
						end
						add attr
							set name="ram"
							set type="string"
							set value=#{config.memory}
						end
						add attr
							set name=bootrom
							set type=string
							set value=#{config.firmware}
						end
						add device
							set match=/dev/zvol/rdsk#{config.zonepath}/boot
						end
						add attr
							set name=bootdisk
							set type=string
							set value=#{config.zonepath.delete_prefix("/")}/boot
						end
					}

				end
				data = %{
					#{attr}
				}
				File.open('zone_config', 'w') do |f|
					f.puts data
				end
				
				## Shared Disk Configurations
				if config.shared_disk_enabled
					shared_disk_attr = %{
						add fs
							set dir=/vagrant
							set special=#{lofs_current_dir}
							set type=lofs
						end
					}
					shared_disk_data = %{
						#{shared_disk_attr}
					}
				
					File.open('zone_config', 'a') do |f|
						f.puts shared_disk_data
					end
				end
				
				
				## Additional Disk Configurations
				additional_disk_attr = %{
					add device
						set match=/dev/zvol/rdsk#{config.zonepath}/disk1
					end
					add attr
						set name=disk
						set type=string
						set value=#{config.zonepath.delete_prefix("/")}/disk1
					end
				}
				additional_disks_data = %{
					#{additional_disk_attr}
				}
				File.open('zone_config', 'a') do |f|
					f.puts additional_disks_data
				end
				
				## Nic Configurations
				state = "config"
				@driver.vnic(@machine, env[:ui], state)


				## Write out Config
				exit = %{
					exit
				}
				File.open('zone_config', 'a') do |f|
					f.puts exit
				end
				
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
				result = execute(false, "#{@pfexec} VBoxManage list runningvms  ; echo $?")
				raise Errors::VirtualBoxRunningConflictDetected if result == 0
				
				if config.brand == 'lx'
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
					result = execute(true, "/usr/bin/bash -c \"RELEASE=1510380;VER=$(cat /etc/release | head -n 1 | cut -d' ' -f5 |  cut -c 2-); if (($VER -gt $RELEASE)); then exit 0; else exit 1; fi\"")
					puts ""
					
					cutoff_release = "1510380"
					cutoff_release = cutoff_release[0..-2].to_i 
					release = File.open('/etc/release', &:readline)
					release = release.scan(/\w+/).values_at( -1)
					release = release[0][1..-2].to_i 
					raise Errors::SystemVersionIsTooLow if release  >= cutoff_release
	
					# Check Bhyve compatability
					result = execute(false, "#{@pfexec} bhhwcompat -s")
					raise Errors::MissingBhyve if result.length == 1 
				end
     			end
			
			def setup(machine, ui)
				config = machine.provider_config
				name = machine.name
				insert_key = machine.config.ssh.insert_key
				
				puts "==> #{name}: Waiting for the Machine to boot..."
				waitforboot(machine)
				
				## Check if already setup and skip the following
				
				if insert_key
					zlogin(machine, "echo #{config.vagrant_user_key} > \/home\/#{config.vagrant_user}\/.ssh\/authorized_keys")
					zlogin(machine, "chown -R #{config.vagrant_user}:#{config.vagrant_user} \/home\/#{config.vagrant_user}\/.ssh")
					zlogin(machine, "chmod 600 \/home\/#{config.vagrant_user}\/.ssh\/authorized_keys")
				end
				
				machine.config.vm.networks.each do |_type, opts|
					index = 1
					if _type.to_s == "public_network"
						ip        	= opts[:ip].to_s
						netmask 	= to_cidr(opts[:netmask])
						defrouter 	= opts[:gateway]
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
						## Remove old installer netplan config
						zlogin(machine, "rm -rf /etc/netplan/00-installer-config.yaml")
						
						## Create new netplan config
						zlogin(machine, "touch /etc/netplan/00-installer-config.yaml")
						zlogin(machine, 'echo "network:" > /etc/netplan/00-installer-config.yaml')
						zlogin(machine, 'sed -i "$ a \  version: 2" /etc/netplan/00-installer-config.yaml')
						zlogin(machine, 'sed -i "$ a \  ethernets:" /etc/netplan/00-installer-config.yaml')
						zlogin(machine, 'APT=$(ifconfig -s -a | grep -v lo | tail -1 | awk \'{ print $1 }\') &&  sed -i "$ a \    $APT:" /etc/netplan/00-installer-config.yaml')
						zlogin(machine, 'sed -i "$ a \      dhcp-identifier: mac" /etc/netplan/00-installer-config.yaml')
						zlogin(machine, 'sed -i "$ a \      dhcp4: no" /etc/netplan/00-installer-config.yaml')
						zlogin(machine, 'sed -i "$ a \      dhcp6: no" /etc/netplan/00-installer-config.yaml')
						zlogin(machine, 'sed -i "$ a \      nameservers:" /etc/netplan/00-installer-config.yaml')
						zlogin(machine, "sed -i '$ a \\        addresses: [#{nameserver1} , #{nameserver2}]' /etc/netplan/00-installer-config.yaml")
						zlogin(machine, "sed -i '$ a \\      addresses: [#{ip}\/#{netmask}]' /etc/netplan/00-installer-config.yaml")
						zlogin(machine, "sed -i '$ a \\      gateway4: #{defrouter}' /etc/netplan/00-installer-config.yaml")
						
						
						## Apply the Configuration
						puts "==> #{name}: Applying the network configuration"
						zlogin(machine, 'netplan apply')
						
					end
				end
				
			end
			
			def waitforboot(machine)
				name = @machine.name
				config = machine.provider_config
				responses = []
				PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read,zlogin_write,pid|
				        if zlogin_read.expect(/Last login: /)
						puts "==> #{name}: Machine Booted, Running Setup"
						sleep 5
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
					 status = Timeout::timeout(config.clean_shutdown_time) {
						execute(false, "#{@pfexec} zoneadm -z #{name} shutdown")
					 }
					rescue Timeout::Error
  						puts "==> #{name}: VM failed to Shutdown in alloted time #{config.clean_shutdown_time}"
						begin halt_status = Timeout::timeout(60) {
							execute(false, "#{@pfexec} zoneadm -z #{name} halt")
						}
						rescue Timeout::Error
							raise "==> #{name}: VM failed to halt in alloted time 60 after waiting to shutdown for #{config.clean_shutdown_time}"
						end
					end
				end
			end
			
			def destroy(machine, id)
				name = @machine.name
				
				## Ensure machine is halted
				execute(false, "#{@pfexec} zoneadm -z #{name} halt")
				
				## Check if it has a presence in zoneadm and if no presence in zoneadm destroy zonecfg
				vm_configured = execute(false, "#{@pfexec} zoneadm list -i | grep  #{name} || true")
				if vm_configured != name
					execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
				end
				
				## Check state in zoneadm
				vm_state = execute(false, "#{@pfexec} zoneadm -z #{name} list -p | awk -F: '{ print $3 }'")
				
				## If state is seen, uninstall from zoneadm and destroy from zonecfg
				if vm_state == 'incomplete' || vm_state == 'configured' || vm_state ==  "installed"
					execute(false, "#{@pfexec} zoneadm -z #{name} uninstall -F")
					execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
				end

				### Nic Configurations
				state = "delete"
				@driver.vnic(@machine, env[:ui], state)
				
				
				### Check State of additional Disks
				#disks_configured = execute(false, "#{@pfexec}  zfs list ")

				
			end
			
		end
	end
end
