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
require 'vagrant-zone/util/timer'

module VagrantPlugins
	module ProviderZone
		class Driver
			attr_accessor :executor

			def initialize(machine)
				@logger = Log4r::Logger.new("vagrant_zone::driver")
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

			def get_ip_address(machine)
				config = machine.provider_config
				dhcpenabled = config.dhcp
				machine.config.vm.networks.each do |_type, opts|
					if _type.to_s == "public_network"
						ip        = opts[:ip].to_s
						network   = NetAddr.parse_net(opts[:ip].to_s + '/' + opts[:netmask].to_s)
						defrouter = opts[:gateway]
						return nil if ip.length == 0
						return ip.gsub /\t/, ''
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
			end

			def boot(machine, ui)
				name = @machine.name
				execute(false, "#{@pfexec} zoneadm -z #{name} boot")
			end

			def create_vnic(machine, ui)
				machine.config.vm.networks.each do |_type, opts|
					if _type.to_s == "public_network"
						link = opts[:bridge]
						mac  = 'auto'
						vlan = 1
						if !opts[:mac].nil?
							mac  = opts[:mac]
						end
						if !opts[:vlan].nil?
							vlan =  opts[:vlan]
							execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} -v #{vlan} #{machine.name}0")
						else
							
							execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} #{machine.name}0")
						end
					end
					if _type.to_s == "private_network"
						link = opts[:bridge]
						mac  = 'auto'
						vlan = 1
						if !opts[:mac].nil?
							mac  = opts[:mac]
						end
						if !opts[:vlan].nil?
							vlan =  opts[:vlan]
							execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} -v #{vlan} #{machine.name}0")
						else
							
							execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} #{machine.name}0")
						end
					end
					if _type.to_s == "ha_network"
						link = opts[:bridge]
						mac  = 'auto'
						vlan = 1
						if !opts[:mac].nil?
							mac  = opts[:mac]
						end
						if !opts[:vlan].nil?
							vlan =  opts[:vlan]
							execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} -v #{vlan} #{machine.name}0")
						else
							
							execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} #{machine.name}0")
						end
					end
				
					
				end
			end

			def create_dataset(machine, ui)
				config  = machine.provider_config				
				dataset = config.zonepath.delete_prefix("/").to_s + "/boot"
				datasetroot = config.zonepath.delete_prefix("/").to_s
				if config.brand == 'lx'					
					execute(false, "#{@pfexec} zfs create -o zoned=on -p #{dataset}")
				end
				if config.brand == 'bhyve'
					execute(false, "#{@pfexec} zfs create #{datasetroot}")
					execute(false, "#{@pfexec} zfs create -V #{config.zonepathsize} #{dataset}")
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
				config = machine.provider_config
				lofs_current_dir = Dir.pwd

				attr = ''
				if config.brand == 'lx'
					machine.config.vm.networks.each do |_type, opts|
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
					attr = %{
						set ip-type=exclusive
						add device
							set match=/dev/zvol/rdsk#{config.zonepath}/boot
						end
						add attr
							set name=bootrom
							set type=string
							set value=BHYVE_RELEASE_CSM
						end
						add net
							set physical=#{machine.name}0
						end
						add attr
							set name=bootdisk
							set type=string
							set value=#{config.zonepath.delete_prefix("/")}/boot
						end
						add attr
							set name="acpi"
							set type="string"
							set value="off"
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
					}
				end

				data = %{
					create
					set zonepath=#{config.zonepath}/path
					set brand=#{config.brand}
					set autoboot=true
					#{attr}
					add fs
						set dir=/vagrant
						set special=#{lofs_current_dir}
						set type=lofs
					end
					exit
				}
				File.open('zone_config', 'w') do |f|
					f.puts data
				end
				execute(false, "cat zone_config | #{@pfexec} zonecfg -z #{machine.name}")
			end

			def check_bhyve_support(machine, ui)
				config = machine.provider_config
				box  = @machine.data_dir.to_s + '/' + @machine.config.vm.box
				name = @machine.name

				if config.brand == 'lx'
					execute(false, "#{@pfexec} zoneadm -z #{name} install -s #{box}")
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
					result = execute(true, "#{@pfexec} cat /etc/release | head -n 1 | awk '{ print $3 }' | cut -c 2- ")
					puts result
					if result > 1510380
						raise Errors::SystemVersionIsTooLow if result == 0
					end
				
	
					# Check Bhyve compatability
					result = execute(false, "#{@pfexec} bhhwcompat -s")
					raise Errors::MissingBhyve if result.length == 1 
				end
     			end
			
			def setup(machine, ui)
				config = machine.provider_config
				vagrant_user = config.vagrant_user
				vagrant_user_key = config.vagrant_user_key
				puts "Waiting for the Machine to boot"
				waitforboot(machine)
				puts "Machine Booted, Running Setup"
				zlogin(machine, "echo 'nameserver 1.1.1.1' | tee  /etc/resolv.conf")
				zlogin(machine, "echo 'nameserver 1.0.0.1' | tee -a /etc/resolv.conf")
			
				insert_key = machine.config.ssh.insert_key
				if insert_key
					zlogin(machine, "echo #{vagrant_user_key} > \/home\/#{vagrant_user}\/.ssh\/authorized_keys")
					zlogin(machine, "chown -R #{vagrant_user}:#{vagrant_user} \/home\/#{vagrant_user}\/.ssh")
					zlogin(machine, "chmod 600 \/home\/#{vagrant_user}\/.ssh\/authorized_keys")
					zlogin(machine, "APT=$(ifconfig -s -a | grep -v lo | tail -1 | awk '{ print $1 }') &&  sed -i \"s/enp0s3:/$APT:/g\" /etc/netplan/00-installer-config.yaml ")
				end
				
				
				machine.config.vm.networks.each do |_type, opts|
					if _type.to_s == "public_network"
						ip        = opts[:ip].to_s
						network   = NetAddr.parse_net(opts[:ip].to_s + '/' + opts[:netmask].to_s)
						defrouter = opts[:gateway]
						zlogin(machine, "sed -i 's/dhcp4: yes/dhcp4: no/g' /etc/netplan/00-installer-config.yaml")
						zlogin(machine, "sed -i '$ d' /etc/netplan/00-installer-config.yaml")
						zlogin(machine, 'sed -i "$ a \      addresses:" /etc/netplan/00-installer-config.yaml')
						zlogin(machine, "sed -i '$ a \\        - #{ip}\/24' /etc/netplan/00-installer-config.yaml")
						zlogin(machine, "sed -i '$ a \\      gateway4: #{defrouter}' /etc/netplan/00-installer-config.yaml")
						zlogin(machine, 'sed -i "$ a \  version: 2" /etc/netplan/00-installer-config.yaml')
						zlogin(machine, 'netplan apply')
						puts "Applying The Network Configuration"
					end
				end
				
			end
			
			def waitforboot(machine)
				name = @machine.name
				config = machine.provider_config
				setup_wait = config.setup_wait
				responses = []
				subresponses = []
				PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read,zlogin_write,pid|
				        if zlogin_read.expect(/Last login: /)
						sleep 10
						Timeout.timeout(30) do
							loop do
				        		       	zlogin_read.expect(/\n/) { |line|  responses.push line}
								if responses[-1].to_s.match(/:~#/)
									break
								elsif responses[-1].to_s.match(/login: /)
									puts 	"Could not login as Root, Check if Root Autologin Works"
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
						        	raise "Command: #{cmd} Failed with: responses[-1]"
							elsif responses[-1].nil?
						                break
							end
						end
					end
					Process.kill("HUP",pid)
				end
			end

			def user(machine)
				name = @machine.name
				config = machine.provider_config
				user = config.vagrant_user
				return user
			end
			
			def userprivatekeypath(machine)
				name = @machine.name
				config = machine.provider_config
				userkey = config.vagrant_user_private_key_path.to_s
				return userkey
			end

			def halt(machine, ui)
				name = @machine.name
				vm_state = execute(false, "#{@pfexec} zoneadm -z #{name} list -p | awk -F: '{ print $3 }'")
				vm_configured = execute(false, "#{@pfexec} zoneadm list -i | grep  #{name} || true")
					if vm_state == "running"
						execute(false, "#{@pfexec} zoneadm -z #{name} halt")
					end
			end

			def destroy(machine, id)
				name = @machine.name
				
				vnic_configured = execute(false, "#{@pfexec} dladm show-vnic | grep #{name}0 | awk '{ print $1 }' ")
				vm_configured = execute(false, "#{@pfexec} zoneadm list -i | grep  #{name} || true")
				if vm_configured == name
					vm_state = execute(false, "#{@pfexec} zoneadm -z #{name} list -p | awk -F: '{ print $3 }'")
					if vm_state == 'incomplete' || vm_state == 'configured' 
						execute(false, "#{@pfexec} zoneadm -z #{name} uninstall -F")
						execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
						if vnic_configured == "#{name}0"
							execute(false, "#{@pfexec} dladm delete-vnic #{name}0")
						end
					elsif vm_state == "installed"
						execute(false, "#{@pfexec} zoneadm -z #{name} uninstall -F")
						execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
						if vnic_configured == "#{name}0"
							execute(false, "#{@pfexec} dladm delete-vnic #{name}0")
						end
					end
				else
					execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
					if vnic_configured == "#{name}0"
							execute(false, "#{@pfexec} dladm delete-vnic #{name}0")
					end
				end
			end
		end
	end
end
