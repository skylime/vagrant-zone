require "log4r"
require "fileutils"
require "digest/md5"
require "io/console"
require "ruby_expect"

module VagrantPlugins
	module ProviderZone
		class Driver
			attr_accessor :executor

			def initialize(machine)
				@logger = Log4r::Logger.new("vagrant_zone::driver")
				@machine = machine
				@executor = Executor::Exec.new
			end

			def state(machine)
				uuid = machine.id
				name = machine.name
				vm_state = execute(false, "zoneadm -z #{name} list -p | awk -F: '{ print $3 }'")
				if vm_state == 'running'
					:running
				elsif vm_state == 'configured'
					:preparing
				elsif vm_state == 'installed'
					:stopped
				else
					:not_created
				end
			end

			def execute(*cmd, **opts, &block)
				@executor.execute(*cmd, **opts, &block)
			end

			def get_ip_address(machine)
				name = @machine.name
				ip   = execute(false, "zonecfg -z #{name} info net | sed -n 's|property: (name=ips,value=\"\\(.*\\)/.*\")|\\1|p'")
				return nil if ip.length == 0
				return ip.gsub /\t/, ''
			end

			def zoneadm(machine, ui)
				box  = @machine.data_dir.to_s + '/' + @machine.config.vm.box
				name = @machine.name
				execute(false, "zoneadm -z #{name} install -s #{box}")
				execute(false, "zoneadm -z #{name} boot")
			end

			def zonecfg(machine, ui)
				config = machine.provider_config
				data = %{
					create
					set zonepath=#{config.zonepath}
					set brand=#{config.brand}
					set autoboot=false
					add net
						set physical=lx0
						set global-nic=auto
						add property (name=gateway,value="192.168.0.1")
						add property (name=ips,value="192.168.122.23/24")
						add property (name=primary,value="true")
					end
					add attr
						set name=kernel-version
						set type=string
						set value=#{config.kernel}
					end
					set max-lwps=2000
					exit
				}
				File.open('zone_config', 'w') do |f|
					f.puts data
				end
				execute(false, "cat zone_config | zonecfg -z #{machine.name}")
			end
		end
	end
end
