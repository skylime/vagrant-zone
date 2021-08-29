# encoding: utf-8
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
require 'vagrant-zones/util/subprocess'

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
				ui.info(I18n.t("vagrant_zones.installing_zone")+" brand: #{config.brand}")
			end
			
			## Boot the Machine
			def boot(machine, ui)
				name = @machine.name
				ui.info(I18n.t("vagrant_zones.starting_zone"))
				execute(false, "#{@pfexec} zoneadm -z #{name} boot")
			end
			
			def get_ip_address(machine)
				config = machine.provider_config
				name = @machine.name
				machine.config.vm.networks.each do |_type, opts|
					responses=[]
					nic_number	= opts[:nic_number].to_s
					if !opts[:type].nil?
						nictype  = opts[:nictype]
					else 
						nictype = "external"
					end
					mac  		= 'auto'
					if !opts[:mac].nil?
						mac  = opts[:mac]
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
					if _type.to_s == "public_network"
						if opts[:dhcp] == true
							if opts[:managed]
								if mac == 'auto'
									PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read,zlogin_write,pid|
										zlogin_read.expect(/\n/) { |msg| zlogin_write.printf("ip -4 addr show dev vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number} | head -n -1 | tail -1  | awk '{ print $2 }'  | cut -f1 -d\"/\" \n") }
										Timeout.timeout(30) do
											loop do
												zlogin_read.expect(/\r\n/) { |line|  responses.push line}
												puts responses[-1]
												puts "This is a DHCP address"
												if responses[-1].to_s.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)
													ip = responses[-1][0].rstrip.gsub(/\e\[\?2004l/, "").lstrip
													puts responses[-1]
													puts ip
													return nil if ip.length == 0
													return ip.gsub /\t/, ''
													break
												elsif responses[-1].to_s.match(/Error Code: \b(?![0]\b)\d{1,4}\b/)
														raise "==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
												end
											end
										end
										Process.kill("HUP",pid)
									end
								else
									PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read,zlogin_write,pid|
										zlogin_read.expect(/\n/) { |msg| zlogin_write.printf("ip -4 addr show dev vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number} | head -n -1 | tail -1  | awk '{ print $2 }'  | cut -f1 -d\"/\" \n") }
										Timeout.timeout(30) do
											loop do
												zlogin_read.expect(/\r\n/) { |line|  responses.push line}
												puts responses[-1]
												p responses[-1]
												puts "This is a Static address"
												if responses[-1].to_s.match(/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/)
													ip = responses[-1][0].rstrip.gsub(/\e\[\?2004l/, "").lstrip
													puts responses[-1]
													puts ip
													return nil if ip.length == 0
													return ip.gsub /\t/, ''
													break
												elsif responses[-1].to_s.match(/Error Code: \b(?![0]\b)\d{1,4}\b/)
													raise "==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
												end
											end
										end
										Process.kill("HUP",pid)
									end
								end

							end
							puts "==> #{machine.name} ==> DHCP is not yet Configured for use"
						elsif opts[:dhcp] == false
							if opts[:managed]
								ip = opts[:ip].to_s
								return nil if ip.length == 0
								return ip.gsub /\t/, ''
							end
						end
					end
				end
			end

			
			## Manage Network Interfaces
			def vnic(machine, ui, state)
				config = machine.provider_config
				name = @machine.name

				if state == "setup"
					## Remove old installer netplan config
					ui.info(I18n.t("vagrant_zones.netplan_remove"))							
					zlogin(machine, "rm -rf  /etc/netplan/*.yaml")
				end
				machine.config.vm.networks.each do |_type, opts|
					if _type.to_s == "public_network"
						link 		= opts[:bridge]
						nic_number	= opts[:nic_number].to_s
						netmask 	= IPAddr.new(opts[:netmask].to_s).to_i.to_s(2).count("1")
						ip        	= opts[:ip].to_s
						defrouter 	= opts[:gateway].to_s
						cloud_init_enabled = false

						allowed_address = ip.to_s + "/" + netmask.to_s
						if ip.length == 0
							ip = nil
						else
							ip = ip.gsub /\t/, ''
						end
						mac  		= 'auto'
						vlan 		= 1
						if !opts[:mac].nil? || !opts[:mac].expect(/^(?:[[:xdigit:]]{2}([-:]))(?:[[:xdigit:]]{2}\1){4}[[:xdigit:]]{2}$/)
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
								ui.info(I18n.t("vagrant_zones.creating_vnic") + vnic_name)
								execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} -v #{vlan} #{vnic_name}")
							else
								execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} #{vnic_name}")
							end		
						elsif state == "delete"
							ui.info(I18n.t("vagrant_zones.removing_vnic") + vnic_name)
							vnic_configured = execute(false, "#{@pfexec} dladm show-vnic | grep #{vnic_name} | awk '{ print $1 }' ")
							if vnic_configured == "#{vnic_name}"
								execute(false, "#{@pfexec} dladm delete-vnic #{vnic_name}")
							end
						elsif state == "config"
							ui.info(I18n.t("vagrant_zones.vnic_setup") + vnic_name)
							if cloud_init_enabled
								nic_attr = %{add net
	set physical=#{vnic_name}
	set allowed-address=#{allowed_address}
end							}			
							else
								nic_attr = %{add net
	set physical=#{vnic_name}
end								}
								File.open("#{name}.zoneconfig", 'a') do |f|
									f.puts nic_attr
								end
							end
						elsif state == "setup"
							responses=[]
							vmnic=[]
							ui.info(I18n.t("vagrant_zones.configure_interface_using_vnic") + vnic_name)	
							regex=/(en|eth)(\d|o\d|s\d|x[0-9A-Fa-f]{2}{6}|(p\d)(s\d)(f?\d?))/
							PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read,zlogin_write,pid|
								zlogin_read.expect(/\n/) { |msg| zlogin_write.printf("\nifconfig -s -a | grep -v lo  | awk '{ print $1 }' | grep -v Iface\n") }
								Timeout.timeout(30) do
									run = 0
									loop do
										zlogin_read.expect(/\r\n/) { |line|  responses.push line}
										if responses[-1][0] =~ regex											
											if !vmnic.include? responses[-1][0][/#{regex}/]
												vmnic.append(responses[-1][0][/#{regex}/])
											end
										end
										vmnic.each { |interface|
											nicfunction = ""
											devid = ""
											if !interface[/#{regex}/, 1].nil?
											    if !interface[/#{regex}/, 3].nil?
											        nic = interface[/#{regex}/, 1]
											        nicbus = interface[/#{regex}/, 3]
											        devid = nicbus
											    else
											        if interface[/#{regex}/, 1] == "en"
											            interface_desc = interface[/#{regex}/, 2].split("")
											            nic = interface[/#{regex}/, 1] + interface_desc[0]
											            #puts nic
											            if interface_desc[0] == "x"
											                mac_interface = interface[/#{regex}/, 1] + interface[/#{regex}/, 2]
											                mac_interface = mac_interface.split("enx",0)
											                nicbus = mac_interface[1]
											            elsif interface_desc[0] == "s" || interface_desc[0] == "o"
											                nicbus = interface_desc[1]
											            end
											            devid = nicbus
											        else
											            nic = interface[/#{regex}/, 1]
											            nicbus = interface[/#{regex}/, 2]
											            devid = nicbus
											        end
											    end
											    if !interface[/#{regex}/, 4].nil?
											    	nicdevice = interface[/#{regex}/, 4]
											    	if interface[/#{regex}/, 5][/f\d/].nil?
											    		nicfunction = "f0"
											    		devid = nicfunction
											    	else
											    		nicfunction = interface[/#{regex}/, 5]
											    		devid = nicfunction
											    	end
											    else
											    	nicfunction = nicbus
											    	devid = nicfunction
											    end
											end																
											devid = devid.gsub /f/, ''
											if !devid.nil? 
												if nic_number == devid
													vnic=vmnic[devid.to_i]
													## Get Device Mac Address for when Mac is not specified
													if mac == 'auto'
														zlogin_write.printf("\nip link show dev #{vnic} | grep ether | awk '{ print $2 }'\n")
														if responses[-1].to_s.match(/^(?:[[:xdigit:]]{2}([-:]))(?:[[:xdigit:]]{2}\1){4}[[:xdigit:]]{2}$/)	
															mac = responses[-1][0][/^(?:[[:xdigit:]]{2}([-:]))(?:[[:xdigit:]]{2}\1){4}[[:xdigit:]]{2}$/]
														end
													end

													if opts[:dhcp] == true
														netplan = %{network:
  version: 2
  ethernets:  
    vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number}:
      match:
        macaddress: #{mac}
      dhcp-identifier: mac
      dhcp4: yes
      dhcp6: no
      set-name: vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number}
      nameservers:
        addresses: [#{nameserver1} , #{nameserver2}]	}
														if run == 0
															zlogin_write.printf("echo '#{netplan}' > /etc/netplan/vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number}.yaml; echo \"Subprocess Error Code: $?\"\n")
															run+=1
														end
														if responses[-1].to_s.match(/Subprocess Error Code: 0/)
															ui.info(I18n.t("vagrant_zones.netplan_applied_dhcp") + "/etc/netplan/vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number}.yaml")														
														elsif responses[-1].to_s.match(/Subprocess Error Code: \b(?![0]\b)\d{1,4}\b/)
															raise "\n==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
														end
													else	
														netplan = %{network:
  version: 2
  ethernets:  
    vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number}
	  match:
	    macaddress: #{mac}
      dhcp-identifier: mac
      dhcp4: no
      dhcp6: no
      set-name: vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number}
      addresses: [#{ip}/#{netmask}]
      gateway4: #{defrouter}
      nameservers:
        addresses: [#{nameserver1} , #{nameserver2}]	}
														if run == 0
															zlogin_write.printf("echo '#{netplan}' > /etc/netplan/vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number}.yaml; echo \"Subprocess Error Code: $?\"\n")
															run+=1
														end
														if responses[-1].to_s.match(/Subprocess Error Code: 0/)
															ui.info(I18n.t("vagrant_zones.netplan_applied_static") + "/etc/netplan/vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number}.yaml")															
														elsif responses[-1].to_s.match(/Subprocess Error Code: \b(?![0]\b)\d{1,4}\b/)
															raise "\n==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
														end
													end
												end
											end
										}
										zlogin_write.printf("echo \"Subprocess Error Code: $?\"\n")
										if responses[-1].to_s.match(/Error Code: 0/)
											ui.info(I18n.t("vagrant_zones.netplan_set"))
											break
										elsif responses[-1].to_s.match(/Error Code: \b(?![0]\b)\d{1,4}\b/)
											raise "==> #{name} ==> Command: ==>  \nFailed with: #{responses[-1]}"
										end									
									end
								end
								Process.kill("HUP",pid)
							end
							## Apply the Configuration
							zlogin(machine, 'netplan apply')
							ui.info(I18n.t("vagrant_zones.netplan_applied"))
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
				## Create Boot Volume
				if config.brand == 'lx'	
					ui.info(I18n.t("vagrant_zones.lx_zone_dataset:") + dataset)	
					execute(false, "#{@pfexec} zfs create -o zoned=on -p #{dataset}")
				elsif config.brand == 'bhyve'
					ui.info(I18n.t("vagrant_zones.bhyve_zone_dataset_root") + datasetroot)
					execute(false, "#{@pfexec} zfs create #{datasetroot}")

					ui.info(I18n.t("vagrant_zones.bhyve_zone_dataset_boot") + config.zonepathsize + ", " + dataset)
					execute(false, "#{@pfexec} zfs create -V #{config.zonepathsize} #{dataset}")
					ui.info(I18n.t("vagrant_zones.bhyve_zone_dataset_boot_volume") + "#{dataset}" )	
					command = "#{@pfexec} pv -n #{datadir.to_s}/box.zss   | #{@pfexec} zfs recv -u -v -F #{dataset}"
					Util::Subprocess.new command do |stdout, stderr, thread|
						ui.rewriting do |ui|
							ui.clear_line()
							ui.info("==> #{name}: Import ", new_line: false)
							ui.report_progress(stderr, 100, false)
						end
					  end
					  ui.info("", new_line: true)
					  ui.clear_line()

				elsif config.brand == 'illumos'
					raise Errors::NotYetImplemented
				elsif config.brand == 'kvm'
					raise Errors::NotYetImplemented
				else
					raise Errors::InvalidBrand
				end
				## Create Additional Disks
				unless config.disk1.to_s
					raise Errors::NotYetImplemented
					disk1path = config.disk1.delete_prefix("/").to_s
					disk1size = config.disk1_size.to_s
					ui.info(I18n.t("vagrant_zones.bhyve_zone_dataset_additional_volume") + cdisk1size + ", " + disk1path)
					execute(true, "#{@pfexec} zfs create -V #{disk1size} #{disk1path}")
				end
			end

			def delete_dataset(machine, ui)
				name = @machine.name
				config = machine.provider_config
				ui.info(I18n.t("vagrant_zones.delete_disks"))
				## Check if Boot Dataset exists
				dataset_boot_exists = execute(false, "#{@pfexec} zfs list | grep  #{config.zonepath.delete_prefix("/")}/boot |  awk '{ print $1 }' || true")

				## If boot Dataset exists, delete it
				if dataset_boot_exists == "#{config.zonepath.delete_prefix("/")}/boot"
					## Remove extra Disks first
					ui.info(I18n.t("vagrant_zones.destroy_dataset") + "#{config.zonepath.delete_prefix("/")}/NotYetImplemented")
					#execute(false, "#{@pfexec} zfs destroy -r #{config.zonepath.delete_prefix("/")}/boot")

					## Delete Boot dataset
					ui.info(I18n.t("vagrant_zones.destroy_dataset") + "#{config.zonepath.delete_prefix("/")}/boot" )
					execute(false, "#{@pfexec} zfs destroy -r #{config.zonepath.delete_prefix("/")}/boot")

					## Check if root dataset exists
					ui.info(I18n.t("vagrant_zones.destroy_dataset") + "#{config.zonepath.delete_prefix("/")}")
					dataset_root_exists = execute(false, "#{@pfexec} zfs list | grep  #{config.zonepath.delete_prefix("/")} |  awk '{ print $1 }' || true")
					if dataset_root_exists == "#{config.zonepath.delete_prefix("/")}"
						execute(false, "#{@pfexec} zfs destroy -r #{config.zonepath.delete_prefix("/")}")
					end
				else
					ui.info(I18n.t("vagrant_zones.dataset_nil") )
				end
				
			end

			def zonecfg(machine, ui)
				name = @machine.name
				## Seperate commands out to indvidual functions like Network, Dataset, and Emergency Console
				config = machine.provider_config
				attr = ''
				if config.brand == 'lx'
					ui.info(I18n.t("vagrant_zones.lx_zone_config_gen"))
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
					ui.info(I18n.t("vagrant_zones.bhyve_zone_config_gen"))
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
				File.open("#{name}.zoneconfig", 'w') do |f|
					f.puts attr
				end
				
				## Shared Disk Configurations
				unless config.shared_disk_enabled
					shared_disk_attr = %{add fs
	set dir=/vagrant
	set special=#{config.shared_dir}
	set type=lofs
end					}				
					File.open("#{name}.zoneconfig", 'a') do |f|
						f.puts shared_disk_attr
					end
				end


				## CPU Configurations
				if config.cpu_configuration == 'simple'
					cpu_attr = %{add attr
	set name=vcpus
	set type=string
	set value=#{config.cpus}
end					}				
					File.open("#{name}.zoneconfig", 'a') do |f|
						f.puts cpu_attr
					end
				elsif config.cpu_configuration == 'complex'
					
					hash = config.complex_cpu_conf[0]
					cpu_attr = %{add attr
	set name=vcpus
	set type=string
	set value="sockets=#{hash["sockets"]},cores=#{hash["cores"]},threads=#{hash["threads"]}"
end					}				
					File.open("#{name}.zoneconfig", 'a') do |f|
						f.puts cpu_attr
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
					File.open("#{name}.zoneconfig", 'a') do |f|
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
				
				#	File.open("#{name}.zoneconfig", 'a') do |f|
				#		f.puts ppt_data_attr
				#	end
				#end

				
				## Additional Disk Configurations
				unless config.disk1path != 'none' || config.disk1path
					additional_disk_attr = %{add device
	set match=/dev/zvol/rdsk#{config.zonepath}/disk1
end
add attr
	set name=disk
	set type=string
	set value=#{config.zonepath.delete_prefix("/")}/disk1
end
					}
					File.open("#{name}.zoneconfig", 'a') do |f|
						f.puts additional_disk_attr
					end
				end
				
				## Nic Configurations
				state = "config"
				vnic(@machine, ui, state)

				## Write out Config
				exit = %{exit}
				File.open("#{name}.zoneconfig", 'a') do |f|
					f.puts exit
				end
				ui.info(I18n.t("vagrant_zones.exporting_bhyve_zone_config_gen"))
				## Export config to zonecfg
				execute(false, "cat #{name}.zoneconfig | #{@pfexec} zonecfg -z #{machine.name}")
			end

			def check_zone_support(machine, ui)
				config = machine.provider_config
				box  = @machine.data_dir.to_s + '/' + @machine.config.vm.box
				name = @machine.name

				## Detect if Virtualbox is Running
				## Kernel, KVM, and Bhyve cannot run conncurently with Virtualbox:
				### https://forums.virtualbox.org/viewtopic.php?f=11&t=64652
				ui.info(I18n.t("vagrant_zones.vbox_run_check"))
				result = execute(false, "#{@pfexec} VBoxManage list runningvms  ; echo $?")
				raise Errors::VirtualBoxRunningConflictDetected if result == 0
				
				if config.brand == 'lx'
					ui.info(I18n.t("vagrant_zones.lx_check"))
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
					ui.info(I18n.t("vagrant_zones.bhyve_check") + "#{cutoff_release}")		
					release = File.open('/etc/release', &:readline)
					release = release.scan(/\w+/).values_at( -1)
					release = release[0][1..-2].to_i 
					raise Errors::SystemVersionIsTooLow if release  < cutoff_release
	
					# Check Bhyve compatability
					ui.info(I18n.t("vagrant_zones.bhyve_compat_check"))
					result = execute(false, "#{@pfexec} bhhwcompat -s")
					raise Errors::MissingBhyve if result.length == 1 
				end
     			end
			
			def setup(machine, ui)
				config = machine.provider_config
				name = machine.name
				### Nic Configurations
				
				state = "setup"
				vnic(@machine, ui, state)
				
			end
			
			def waitforboot(machine, ui)
				ui.info(I18n.t("vagrant_zones.wait_for_boot"))
				name = @machine.name
				config = machine.provider_config
				responses = []
				PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read,zlogin_write,pid|
				    if zlogin_read.expect(/Last login: /)
						ui.info(I18n.t("vagrant_zones.booted_check_terminal_access"))
						Timeout.timeout(config.setup_wait) do
							loop do
				        		zlogin_read.expect(/\n/) { |line|  responses.push line}
								if responses[-1].to_s.match(/:~#/)
									break
								elsif responses[-1].to_s.match(/login: /)
									## Code to try to login with username and password
									ui.info(I18n.t("vagrant_zones.booted_check_terminal_access_auto_login"))
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
						        	raise "==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
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
					ui.info(I18n.t("vagrant_zones.graceful_shutdown"))
					begin						
						status = Timeout::timeout(config.clean_shutdown_time) {
						execute(false, "#{@pfexec} zoneadm -z #{name} shutdown")
					 }
					rescue Timeout::Error
						ui.info(I18n.t("vagrant_zones.graceful_shutdown_failed") + config.clean_shutdown_time.to_i)
						begin 
							halt_status = Timeout::timeout(60) {
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
				
				id.info(I18n.t("vagrant_zones.leaving"))
				id.info(I18n.t("vagrant_zones.destroy_zone"))

				## Check if it has a presence in zoneadm and if no presence in zoneadm destroy zonecfg
				vm_configured = execute(false, "#{@pfexec} zoneadm list -i | grep  #{name} || true")
				vmcfg_set = execute(false, "#{@pfexec} zonecfg -z #{name} export -f #{name}.zoneconfig && test #{name}.zoneconfig && echo #{name} || true")

				if vm_configured != name
					id.info(I18n.t("vagrant_zones.bhyve_zone_config_remove"))
					if vmcfg_set  == name
						execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
					end
				end
				
				## Check state in zoneadm
				vm_state = execute(false, "#{@pfexec} zoneadm -z #{name} list -p | awk -F: '{ print $3 }'")
				
				## If state is seen, uninstall from zoneadm and destroy from zonecfg
				if vm_state == 'incomplete' || vm_state == 'configured' || vm_state ==  'installed'
					id.info(I18n.t("vagrant_zones.bhyve_zone_config_uninstall"))
					execute(false, "#{@pfexec} zoneadm -z #{name} uninstall -F")
					id.info(I18n.t("vagrant_zones.bhyve_zone_config_remove"))
					execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
				end

				### Nic Configurations
				state = "delete"
				vnic(@machine, id, state)
				
				### Check State of additional Disks
				
				#disks_configured = execute(false, "#{@pfexec}  zfs list ")

			end
			
		end
	end
end
