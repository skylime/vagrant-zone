require "log4r"
require "fileutils"
require "digest/md5"
require "io/console"
require "ruby_expect"
require 'netaddr'
require "vagrant/util/numeric"

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
				name = @machine.name
				ip   = execute(false, "#{@pfexec} zonecfg -z #{name} info net | sed -n 's|property: (name=ips,value=\"\\(.*\\)/.*\")|\\1|p'")
				return nil if ip.length == 0
				return ip.gsub /\t/, ''
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
						if !opts[:mac].nil?
							mac  = opts[:mac]
						end
						execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} #{machine.name}0")
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
				end
#				machine.config.vm.disks.each do |_type, opts|
#					if _type.to_s = "disk"
#						name = opts[:name] if !opts[:name].nil?
#						size = Vagrant::Util::Numeric.string_to_bytes(opts[:size].to_s) if !opts[:size].nil?
#						quota = "-o quota=" + size.to_s if size
#
#						execute(false, "#{@pfexec} zfs create #{quota} #{dataset}/#{name}")
#					end
#				end
			end

			def delete_dataset(machine, ui)
				config = machine.provider_config
				#execute(false, "#{@pfexec} zfs destroy -r #{config.zonepath.delete_prefix("/")}/boot")
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
							set value=#{config.zonepath}/boot
						end
						add attr
							set name="vnc"
							set type="string"
							set value="on,wait"
						end
						add attr:
							set name=console
							set type=string
							set value=socket,/tmp/vm.console
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

			def setup(machine, ui)
				zlogin(machine, %('echo nameserver 1.1.1.1 >> /etc/resolv.conf'))
				if not user_exists?(machine)
					zlogin(machine, "useradd -m -s /bin/bash -U vagrant")
				end
				zlogin(machine, %('echo "vagrant ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers.d/vagrant'))
				zlogin(machine, "mkdir -p /home/vagrant/.ssh")
				zlogin(machine, %('echo "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NOTd0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcWyLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQ== vagrant insecure public key" > /home/vagrant/.ssh/authorized_keys'))
				zlogin(machine, "chown -R vagrant:vagrant /home/vagrant/.ssh")
				zlogin(machine, "chmod 600 /home/vagrant/.ssh/authorized_keys")
			end

			def zlogin(machine, cmd)
				name = @machine.name
				execute(false, "#{@pfexec} zlogin #{name} #{cmd}")
			end

			def user_exists?(machine, user = 'vagrant')
				name = @machine.name
				ret  = execute(true, "#{@pfexec} zlogin #{name} id -u #{user}")
				if ret == 0
					return true
				end
				return false
			end

			def halt(machine, ui)
				name = @machine.name
				execute(false, "#{@pfexec} zoneadm -z #{name} halt")
			end

			def destroy(machine, id)
				name = @machine.name
				vm_state = execute(false, "#{@pfexec} zoneadm -z #{name} list -p | awk -F: '{ print $3 }'")
				if vm_state == 'incomplete'
					execute(false, "#{@pfexec} zoneadm -z #{name} uninstall -F")
					execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
					execute(false, "#{@pfexec} dladm delete-vnic #{name}0")
				else
					execute(false, "#{@pfexec} zoneadm -z #{name} halt")
					execute(false, "#{@pfexec} zoneadm -z #{name} uninstall -F")
					execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
					execute(false, "#{@pfexec} dladm delete-vnic #{name}0")
				end
			end
		end
	end
end
