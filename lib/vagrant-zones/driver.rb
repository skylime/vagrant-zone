# frozen_string_literal: true

require 'log4r'
require 'fileutils'
require 'digest/md5'
require 'io/console'
require 'ruby_expect'
require 'netaddr'
require 'ipaddr'
require 'vagrant/util/numeric'
require 'pty'
require 'expect'
require 'vagrant'
require 'vagrant-zones/util/timer'
require 'vagrant-zones/util/subprocess'
require 'vagrant/util/retryable'

module VagrantPlugins
  module ProviderZone
    # This class does the heavy lifting of the zone
    class Driver
      attr_accessor :executor

      def initialize(machine)
        @logger = Log4r::Logger.new('vagrant_zones::driver')
        @machine = machine
        @executor = Executor::Exec.new
        @pfexec = if Process.uid.zero?
                    ''
                  elsif system('sudo -v')
                    'sudo'
                  else
                    'pfexec'
                  end
      end

      def state(machine)
        name = machine.name
        vm_state = execute(false, "#{@pfexec} zoneadm -z #{name} list -p | awk -F: '{ print $3 }'")
        case vm_state
        when 'running'
          :running
        when 'configured'
          :preparing
        when 'installed'
          :stopped
        when 'incomplete'
          :incomplete
        else
          :not_created
        end
      end

      def execute(*cmd, **opts, &block)
        @executor.execute(*cmd, **opts, &block)
      end

      def install(machine, uiinfo)
        config = machine.provider_config
        box  = "#{@machine.data_dir}/#{@machine.config.vm.box}"
        name = @machine.name
        if config.brand == 'lx'
          results = execute(false, "#{@pfexec} zoneadm -z #{name} install -s #{box}")
          raise 'You appear to not have LX Zones installed in this Machine' if results.include? 'unknown brand'
        end
        execute(false, "#{@pfexec} zoneadm -z #{name} install") if config.brand == 'bhyve'
        execute(false, "#{@pfexec} zoneadm -z #{name} install") if config.brand == 'kvm'
        execute(false, "#{@pfexec} zoneadm -z #{name} install") if config.brand == 'illumos'
        uiinfo.info(I18n.t('vagrant_zones.installing_zone') + " brand: #{config.brand}")
      end

      ## Control the Machine from inside the machine
      def control(machine, control)
        case control
        when 'restart'
          command = 'sudo shutdown -r'
          ssh_run_command(machine, command)
        when 'shutdown'
          command = 'sudo shutdown -h now'
          ssh_run_command(machine, command)
        else
          puts 'No Command specified'
        end
      end

      def ssh_run_command(machine, command)
        ip = get_ip_address(machine)
        user = user(machine)
        key = userprivatekeypath(machine).to_s
        password = vagrantuserpass(machine).to_s
        port = sshport(machine).to_s
        port = 22 if sshport(machine).to_s.nil?
        puts "#{password} not used for this connection at this time"
        execute(false, "#{@pfexec} pwd && ssh -o 'StrictHostKeyChecking=no' -p #{port} -i #{key} #{user}@#{ip}  '#{command}' ")
      end

      def console(machine, command, ip, port)
        name = machine.name
        if !port.nil?
          ip = '127.0.0.1' unless !ip.nil?
          netport = "#{ip}:#{port}"
        else
          netport = ''
        end
        execute(false, "pfexec zadm  webvnc #{netport} #{name}") if command == 'webvnc'
        execute(false, "pfexec zadm  vnc #{netport} #{name}") if command == 'vnc'
        execute(false, "pfexec zadm  console #{name}") if command == 'zlogin'
      end

      ## Boot the Machine
      def boot(machine, uiinfo)
        name = machine.name
        uiinfo.info(I18n.t('vagrant_zones.starting_zone'))
        execute(false, "#{@pfexec} zoneadm -z #{name} boot")
      end

      def get_ip_address(machine)
        config = machine.provider_config
        name = @machine.name
        machine.config.vm.networks.each do |adpatertype, opts|
          responses = []
          nic_number = opts[:nic_number].to_s
          nictype = if !opts[:nictype].nil?
            opts[:nictype]
          else
            'external'
          end
          mac = 'auto'
          mac = opts[:mac] unless opts[:mac].nil?
          nic_type = case nictype
          when /external/
            'e'
          when /internal/
            'i'
          when /carp/
            'c'
          when /management/
            'm'
          when /host/
            'h'
          else
            'e'
          end
          if adpatertype.to_s == 'public_network'
            if opts[:dhcp] == true
              if opts[:managed]
                vnic_name = "vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number}"
                if mac == 'auto'
                  PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read, zlogin_write, pid|
                    command = "ip -4 addr show dev #{vnic_name} | head -n -1 | tail -1  | awk '{ print $2 }'  | cut -f1 -d\"/\" \n"
                    zlogin_read.expect(/\n/) { |msg| zlogin_write.printf(command) }
                    Timeout.timeout(30) do
                      loop do
                        zlogin_read.expect(/\r\n/) { |line| responses.push line }
                        if responses[-1].to_s.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)
                          ip = responses[-1][0].rstrip.gsub(/\e\[\?2004l/, '').lstrip
                          return nil if ip.length.empty?
                          return ip.gsub(/\t/, '')
                          break
                        elsif responses[-1].to_s.match(/Error Code: \b(?!0\b)\d{1,4}\b/)
                          raise "==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
                        end
                      end
                    end
                    Process.kill('HUP', pid)
                  end
                else
                  PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read, zlogin_write, pid|
                    command = "ip -4 addr show dev  #{vnic_name} | head -n -1 | tail -1  | awk '{ print $2 }'  | cut -f1 -d\"/\" \n"
                    zlogin_read.expect(/\n/) { |msg| zlogin_write.printf(command) }
                    Timeout.timeout(30) do
                      loop do
                        zlogin_read.expect(/\r\n/) { |line| responses.push line }
                        if responses[-1].to_s.match(/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/)
                          ip = responses[-1][0].rstrip.gsub(/\e\[\?2004l/, '').lstrip
                          return nil if ip.empty?

                          return ip.gsub /\t/, ''
                          break
                        elsif responses[-1].to_s.match(/Error Code: \b(?![0]\b)\d{1,4}\b/)
                          raise "==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
                        end
                      end
                    end
                    Process.kill('HUP', pid)
                  end
                end

              end
            elsif opts[:dhcp] == false || opts[:dhcp].nil?
              if opts[:managed]
                ip = opts[:ip].to_s
                return nil if ip.empty?

                return ip.gsub /\t/, ''
              end
            end
          end
        end
      end

      ## Manage Network Interfaces
      def network(machine, uiinfo, state)
        config = machine.provider_config
        name = @machine.name
        cloud_init_enabled = config.cloud_init_enabled
        if state == 'setup'
          ## Remove old installer netplan config
          uiinfo.info(I18n.t('vagrant_zones.netplan_remove'))
          zlogin(machine, 'rm -rf  /etc/netplan/*.yaml')
        end
        machine.config.vm.networks.each do |adpatertype, opts|
          if adpatertype.to_s == 'public_network'
            link = opts[:bridge]
            nic_number = opts[:nic_number].to_s
            netmask = IPAddr.new(opts[:netmask].to_s).to_i.to_s(2).count('1')
            ip = opts[:ip].to_s
            defrouter = opts[:gateway].to_s
            
            allowed_address = "#{ip}/#{netmask}"
            if ip.empty?
              ip = nil
            else
              ip = ip.gsub /\t/, ''
            end
            mac = 'auto'
            vlan = unless !opts[:vlan].nil?
            unless opts[:mac].nil?
              if opts[:mac].match(/^(?:[[:xdigit:]]{2}([-:]))(?:[[:xdigit:]]{2}\1){4}[[:xdigit:]]{2}$/) || !opts[:mac].match(/auto/)
                mac = opts[:mac]
              end
            end
            nictype = opts[:nictype] unless opts[:nictype].nil?
            dns = config.dns
            dns = [{ 'nameserver' => '1.1.1.1' }, { 'nameserver' => '1.0.0.1' }] unless !config.dns.nil?
            servers = []
            unless dns.nil?
              dns.each do |server|
                servers.append(server)
              end
            end
            nic_type = case nictype
            when /external/
              'e'
            when /internal/
              'i'
            when /carp/
              'c'
            when /management/
              'm'
            when /host/
              'h'
            else
              'e'
            end
            vnic_name = "vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number}"
            case state
            when 'create'
              if !opts[:vlan].nil?
                vlan = opts[:vlan]
                uiinfo.info(I18n.t('vagrant_zones.creating_vnic') + vnic_name)
                execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} -v #{vlan} #{vnic_name}")
              else
                execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} #{vnic_name}")
              end
            when 'delete'
              uiinfo.info(I18n.t('vagrant_zones.removing_vnic') + vnic_name)
              vnic_configured = execute(false, "#{@pfexec} dladm show-vnic | grep #{vnic_name} | awk '{ print $1 }' ")
              if vnic_configured == "#{vnic_name}"
                execute(false, "#{@pfexec} dladm delete-vnic #{vnic_name}")
              end
            when 'config'
              uiinfo.info(I18n.t('vagrant_zones.vnic_setup') + vnic_name)
              if config.brand == 'lx'
                nic_attr = %{add net
  set physical=#{vnic_name}
  set global-nic=auto
  set allowed-address=#{allowed_address}
  add property (name=gateway,value="#{@defrouter.to_s}")
  add property (name=ips,value="#{allowed_address}")
  add property (name=primary,value="true")
end              }
                File.open("#{name}.zoneconfig", 'a') do |f|
                  f.puts nic_attr
                end
              elsif config.brand == 'bhyve'
                if cloud_init_enabled 
                  nic_attr = %{add net
  set physical=#{vnic_name}
  set allowed-address=#{allowed_address}
end                  }
                  File.open("#{name}.zoneconfig", 'a') do |f|
                    f.puts nic_attr
                  end
                else
                  nic_attr = %{add net
  set physical=#{vnic_name}
  set allowed-address=#{allowed_address}
end                  }
                  File.open("#{name}.zoneconfig", 'a') do |f|
                    f.puts nic_attr
                  end
                end
              end
            when 'setup'
              responses = []
              vmnic = []
              uiinfo.info(I18n.t('vagrant_zones.configure_interface_using_vnic') + vnic_name)
              ## regex to grab standard Device interface names in ifconfig
              regex = /(en|eth)(\d|o\d|s\d|x[0-9A-Fa-f]{2}{6}|(p\d)(s\d)(f?\d?))/
              PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read, zlogin_write, pid|
                zlogin_read.expect(/\n/) { |msg|
                  zlogin_write.printf("\nifconfig -s -a | grep -v lo  | awk '{ print $1 }' | grep -v Iface\n")
                }
                Timeout.timeout(30) do
                  staticrun = 0
                  dhcprun = 0
                  loop do
                    zlogin_read.expect(/\r\n/) { |line| responses.push line }
                    if responses[-1][0] =~ regex
                      if !vmnic.include? responses[-1][0][/#{regex}/]
                        vmnic.append(responses[-1][0][/#{regex}/])
                      else
                        raise 'We are testing something'
                      end
                    end
                    vmnic.each { |interface|
                      nicfunction = ''
                      devid = ''
                      if !interface[/#{regex}/, 1].nil?
                        if !interface[/#{regex}/, 3].nil?
                          nic = interface[/#{regex}/, 1]
                          nicbus = interface[/#{regex}/, 3]
                          devid = nicbus
                        else
                          if interface[/#{regex}/, 1] == 'en'
                            interface_desc = interface[/#{regex}/, 2].split('')
                            nic = interface[/#{regex}/, 1] + interface_desc[0]
                            if interface_desc[0] == 'x'
                              mac_interface = interface[/#{regex}/, 1] + interface[/#{regex}/, 2]
                              mac_interface = mac_interface.split('enx', 0)
                              nicbus = mac_interface[1]
                            elsif interface_desc[0] == 's' || interface_desc[0] == 'o'
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
                            nicfunction = 'f0'
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
                          vnic = vmnic[devid.to_i]
                          ## Get Device Mac Address for when Mac is not specified
                          if mac == 'auto'
                            zlogin_write.printf("\nip link show dev #{vnic} | grep ether | awk '{ print $2 }'\n")
                            if responses[-1].to_s.match(/^(?:[[:xdigit:]]{2}([-:]))(?:[[:xdigit:]]{2}\1){4}[[:xdigit:]]{2}$/)
                              mac = responses[-1][0][/^(?:[[:xdigit:]]{2}([-:]))(?:[[:xdigit:]]{2}\1){4}[[:xdigit:]]{2}$/]
                            end
                          end
                          if opts[:dhcp] == true || opts[:dhcp].nil?
                            netplan = %{network:
  version: 2
  ethernets:
    #{vnic_name}:
      match:
        macaddress: #{mac}
      dhcp-identifier: mac
      dhcp4: #{opts[:dhcp]}
      dhcp6: #{opts[:dhcp6]}
      set-name: #{vnic_name}
      nameservers:
        addresses: [#{servers[0]["nameserver"]} , #{servers[1]["nameserver"]}]  }
                            if dhcprun == 0
                              command = "echo '#{netplan}' > /etc/netplan/#{vnic_name}.yaml; echo \"DHCP Subprocess Error Code: $?\"\n"
                              zlogin_write.printf(command)
                              dhcprun += 1
                            end
                            if responses[-1].to_s.match(/DHCP Subprocess Error Code: 0/)
                              uiinfo.info(I18n.t('vagrant_zones.netplan_applied_dhcp') + "/etc/netplan/#{vnic_name}.yaml")
                            elsif responses[-1].to_s.match(/DHCP Subprocess Error Code: \b(?![0]\b)\d{1,4}\b/)
                              raise "\n==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
                            end
                          elsif opts[:dhcp] == false
                            netplan = %{network:
  version: 2
  ethernets:
    #{vnic_name}:
      match:
        macaddress: #{mac}
      dhcp-identifier: mac
      dhcp4: #{opts[:dhcp]}
      dhcp6: #{opts[:dhcp6]}
      set-name: #{vnic_name}
      addresses: [#{ip}/#{netmask}]
      gateway4: #{defrouter}
      nameservers:
        addresses: [#{servers[0]["nameserver"]} , #{servers[1]["nameserver"]}]  }
                            if staticrun == 0
                              zlogin_write.printf("echo '#{netplan}' > /etc/netplan/#{vnic_name}.yaml; echo \"Static Error Code: $?\"\n")
                              staticrun += 1
                            end
                            if responses[-1].to_s.match(/Static Error Code: 0/)
                              uiinfo.info(I18n.t('vagrant_zones.netplan_applied_static') + "/etc/netplan/#{vnic_name}.yaml")
                            elsif responses[-1].to_s.match(/Static Error Code: \b(?![0]\b)\d{1,4}\b/)
                              raise "\n==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
                            end
                          end
                        end
                      end
                    }
                    ## Check if last command ran successfully and break from the loop
                    zlogin_write.printf("echo \"Final Network Check Error Code: $?\"\n")
                    if responses[-1].to_s.match(/Final Network Check Error Code: 0/)
                      uiinfo.info(I18n.t('vagrant_zones.netplan_set'))
                      break
                    elsif responses[-1].to_s.match(/Final Network Check Error Code: \b(?![0]\b)\d{1,4}\b/)
                      raise "==> #{name} ==> Final Network Check \nFailed with: #{responses[-1]}"
                    end
                  end
                end
                Process.kill('HUP', pid)
              end
              ## Apply the Configuration
              zlogin(machine, 'netplan apply')
              zlogin(machine, 'netplan apply')
              uiinfo.info(I18n.t('vagrant_zones.netplan_applied'))
            end
          end
        end
      end

      # This helps us create all the datasets for the zone
      def create_dataset(machine, uiinfo)
        name = @machine.name
        config  = machine.provider_config
        dataset = "#{config.zonepath.delete_prefix('/').to_s}/boot"
        datadir = machine.data_dir
        datasetroot = config.zonepath.delete_prefix('/').to_s
        ## Create Boot Volume
        if config.brand == 'lx'
          uiinfo.info(I18n.t('vagrant_zones.lx_zone_dataset') + dataset)
          execute(false, "#{@pfexec} zfs create -o zoned=on -p #{dataset}")
        elsif config.brand == 'bhyve'
          uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_root') + datasetroot)
          execute(false, "#{@pfexec} zfs create #{datasetroot}")
          cinfo="#{config.zonepathsize}, #{dataset}"
          uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_boot') + cinfo)
          execute(false, "#{@pfexec} zfs create -V #{config.zonepathsize} #{dataset}")
          uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_boot_volume') + dataset)
          commandtransfer = "#{@pfexec} pv -n #{@machine.box.directory.join('box.zss').to_s} | #{@pfexec} zfs recv -u -v -F #{dataset} "
          Util::Subprocess.new commandtransfer do |stdout, stderr, thread|
            uiinfo.rewriting do |uiprogress|
              uiprogress.clear_line
              uiprogress.info(I18n.t('vagrant_zones.importing_box_image_to_disk') + "#{datadir.to_s}/box.zss ==> ", new_line: false)
              uiprogress.report_progress(stderr, 100, false)
            end
          end
          uiinfo.clear_line
        elsif config.brand == 'illumos'
          raise Errors::NotYetImplemented
        elsif config.brand == 'kvm'
          raise Errors::NotYetImplemented
        else
          raise Errors::InvalidBrand
        end
        ## Create Additional Disks
        unless  !config.additional_disks.nil? || config.additional_disks != 'none'
          disks = config.additional_disks
          diskrun = 0
          disks.each do |disk|
            diskname = 'disk'
            cinfo="#{disk['size'].to_s}, #{disk['array']}#{disk['path']}"
            uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_additional_volume') + cinfo)
            if diskrun > 0
              diskname = diskname + diskrun.to_s
            end
            diskrun += 1
            execute(true, "#{@pfexec} zfs create -V #{disk["size"].to_s} #{disk["array"]}#{disk["path"]}")
          end
        end
      end

      # This helps us set delete any associated datasets of the zone
      def delete_dataset(machine, uiinfo)
        name = @machine.name
        config = machine.provider_config
        uiinfo.info(I18n.t('vagrant_zones.delete_disks'))
        ## Check if Boot Dataset exists
        zp = "#{config.zonepath.delete_prefix('/')}"
        dataset_boot_exists = execute(false, "#{@pfexec} zfs list | grep  #{zp}/boot |  awk '{ print $1 }' || true")
        ## If boot Dataset exists, delete it
        if dataset_boot_exists == "#{zp}/boot"
          ## Destroy Additional Disks
          unless  !config.additional_disks.nil? || config.additional_disks != 'none'
            disks = config.additional_disks
            diskrun = 0
            disks.each do |disk|
              addataset = "#{disk["array"]}#{disk["path"]}"
              diskname = 'disk'
              cinfo="#{disk["size"]}, #{addataset}"
              uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_additional_volume_destroy') + cinfo)
              dataset_exists = execute(false, "#{@pfexec} zfs list | grep  #{addataset} |  awk '{ print $1 }' || true")
              if dataset_exists == addataset
                if diskrun > 0
                  diskname = diskname + diskrun.to_s
                end
                diskrun += 1
                execute(false, "#{@pfexec} zfs destroy -r #{addataset}")
              end
            end
          end
          ## Destroy Boot dataset
          uiinfo.info(I18n.t("vagrant_zones.destroy_dataset") + "#{zp}/boot")
          execute(false, "#{@pfexec} zfs destroy -r #{zp}/boot")

        else
          uiinfo.info(I18n.t("vagrant_zones.dataset_nil"))
        end
        ## Check if root dataset exists
        uiinfo.info(I18n.t("vagrant_zones.destroy_dataset") + zp)
        dataset_root_exists = execute(false, "#{@pfexec} zfs list | grep  #{zp} |  awk '{ print $1 }' | grep -v path  || true")
        if dataset_root_exists == "#{zp}"
          execute(false, "#{@pfexec} zfs destroy -r #{zp}")
        end
      end

      # This helps us set the zone configurations for the zone
      def zonecfg(machine, uiinfo)
        name = @machine.name
        ## Seperate commands out to indvidual functions like Network, Dataset, and Emergency Console
        config = machine.provider_config
        attr = ''
        if config.brand == 'lx'
          uiinfo.info(I18n.t("vagrant_zones.lx_zone_config_gen"))
          machine.config.vm.networks.each do |adpatertype, opts|
            index = 1
            if adpatertype.to_s == "public_network"
              @ip = opts[:ip].to_s
              cinfo = "#{opts[:ip].to_s}/#{opts[:netmask].to_s}"
              @network = NetAddr.parse_net(cinfo)
              @defrouter = opts[:gateway]
            end
          end
          allowed_address = @ip + @network.netmask.to_s
          attr = %{create
set zonepath=#{config.zonepath}/path
set brand=#{config.brand}
set autoboot=#{config.autoboot}
add attr
  set name=kernel-version
  set type=string
  set value=#{config.kernel}
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
        elsif config.brand == 'bhyve'
          ## General Configuration
          uiinfo.info(I18n.t("vagrant_zones.bhyve_zone_config_gen"))
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
end          }
        end
        File.open("#{name}.zoneconfig", 'w') do |f|
          f.puts attr
        end

        ## Shared Disk Configurations
        unless !config.shared_disk_enabled
          uiinfo.info(I18n.t("vagrant_zones.setting_alt_shared_disk_configurations") + path.path)
          shared_disk_attr = %{add fs
  set dir=/vagrant
  set special=#{config.shared_dir}
  set type=lofs
end          }
          File.open("#{name}.zoneconfig", 'a') do |f|
            f.puts shared_disk_attr
          end
        end

        ## CPU Configurations
        if config.cpu_configuration == 'simple' && (config.brand == 'bhyve' || config.brand == 'kvm')
          cpu_attr = %{add attr
  set name=vcpus
  set type=string
  set value=#{config.cpus}
end          }
          File.open("#{name}.zoneconfig", 'a') do |f|
            f.puts cpu_attr
          end
        elsif config.cpu_configuration == 'complex' && (config.brand == 'bhyve' || config.brand == 'kvm')

          hash = config.complex_cpu_conf[0]
          cpu_attr = %{add attr
  set name=vcpus
  set type=string
  set value="sockets=#{hash["sockets"]},cores=#{hash["cores"]},threads=#{hash["threads"]}"
end          }
          File.open("#{name}.zoneconfig", 'a') do |f|
            f.puts cpu_attr
          end
        end

        ### Passthrough PCI Devices
        # if config.ppt_devices == 'none'
        #   ui.info(I18n.t("vagrant_zones.setting_pci_configurations") + path.path)
        #  puts config.ppt
        #  puts config.config.ppt
        #  ppt_attr = %{
        # add device
        #  set match=/dev/ppt0
        # end
        # add attr
        #  set name=ppt0
        #  set type=string
        #  set value="slot0"
        # end
        #  }
        #  ppt_data_attr = %{
        # {ppt_data}
        #  }

        #  File.open("#{name}.zoneconfig", 'a') do |f|
        #    f.puts ppt_data_attr
        #  end
        # end

        ## CDROM Configurations

        if !config.cdroms.nil?
          cdroms = config.cdroms
          cdrun = 0
          cdroms.each do |cdrom|
            cdname = "cdrom"
            uiinfo.info(I18n.t("vagrant_zones.setting_cd_rom_configurations") + cdrom["path"])
            if cdrun > 0
              cdname = cdname + cdrun.to_s
            end
            cdrun += 1
            cdrom_attr = %{add attr
    set name=#{cdname}
    set type=string
    set value=#{cdrom["path"]}
end
add fs
    set dir=#{cdrom["path"]}
    set special=#{cdrom["path"]}
    set type=lofs
    add options ro
    add options nodevices
end            }
            File.open("#{name}.zoneconfig", 'a') do |f|
              f.puts cdrom_attr
            end
          end
        end

        ## Additional Disk Configurations
        if !config.additional_disks.nil?
          disks = config.additional_disks
          diskrun = 0
          disks.each do |disk|
            diskname = "disk"
            uiinfo.info(I18n.t("vagrant_zones.setting_additional_disks_configurations") + disk["size"] + ", " + disk["path"])
            if diskrun > 0
              diskname = diskname + diskrun.to_s
            end
            diskrun += 1
            additional_disk_attr = %{add device
  set match=/dev/zvol/rdsk#{disk["path"]}
end
add attr
  set name=#{diskname}
  set type=string
  set value=#{disk["path"]}
end            }
            File.open("#{name}.zoneconfig", 'a') do |f|
              f.puts additional_disk_attr
            end
          end
        end

        ## Console access configuration
        if !config.console.nil?
          console = config.console
          if console != 'disabled'

            if console == 'webvnc' || console == 'vnc'
              console = 'vnc'
              value = 'on'
            elsif console == 'console'
              value = 'on'
              if !config.consoleport.nil?
                value = config.consoleport
              end
            end

            if config.console_onboot
              value = value + ",wait"
            end

            uiinfo.info(I18n.t("vagrant_zones.setting_console_access") + console.to_s + ", " + config.consoleport.to_s + ", " + value.to_s)
            console_attr = %{add attr
    set name=#{console}
    set type=string
    set value=#{value}
end            }
            File.open("#{name}.zoneconfig", 'a') do |f|
              f.puts console_attr
            end
          end
        end

        ## Nic Configurations
        network(@machine, uiinfo, "config")

        ## Write out Config
        exit = %{exit}
        File.open("#{name}.zoneconfig", 'a') do |f|
          f.puts exit
        end
        uiinfo.info(I18n.t("vagrant_zones.exporting_bhyve_zone_config_gen"))
        ## Export config to zonecfg
        execute(false, "cat #{name}.zoneconfig | #{@pfexec} zonecfg -z #{machine.name}")
      end

      # This ensures the zone is safe to boot
      def check_zone_support(machine, uiinfo)
        config = machine.provider_config
        box  = "#{@machine.data_dir.to_s}/#{@machine.config.vm.box}"
        name = @machine.name

        ## Detect if Virtualbox is Running
        ## Kernel, KVM, and Bhyve cannot run conncurently with Virtualbox:
        ### https://forums.virtualbox.org/viewtopic.php?f=11&t=64652
        uiinfo.info(I18n.t("vagrant_zones.vbox_run_check"))
        result = execute(true, "#{@pfexec} VBoxManage list runningvms")
        if result == 0
          raise Errors::VirtualBoxRunningConflictDetected
        end

        ## https://man.omnios.org/man5/brands
        if config.brand == 'lx'
          uiinfo.info(I18n.t("vagrant_zones.lx_check"))
          return
        end
        if config.brand == 'ipkg'
          uiinfo.info(I18n.t("vagrant_zones.ipkg_check"))
          return
        end
        if config.brand == 'lipkg'
          uiinfo.info(I18n.t("vagrant_zones.lipkg_check"))
          return
        end
        if config.brand == 'pkgsrc'
          uiinfo.info(I18n.t("vagrant_zones.pkgsrc_check"))
          return
        end
        if config.brand == 'sparse'
          uiinfo.info(I18n.t("vagrant_zones.sparse_check"))
          return
        end
        if config.brand == 'kvm'
          ## https://man.omnios.org/man5/kvm
          uiinfo.info(I18n.t("vagrant_zones.kvm_check"))
          return
        end
        if config.brand == 'illumos'
          uiinfo.info(I18n.t("vagrant_zones.illumos_check"))
          return
        end
        if config.brand == 'bhyve'
          ## https://man.omnios.org/man5/bhyve
          ## Check for  bhhwcompat
          result = execute(true, "#{@pfexec} test -f /usr/sbin/bhhwcompat  ; echo $?")
          if result == 1
            bhhwcompaturl = 'https://downloads.omnios.org/misc/bhyve/bhhwcompat'
            execute(true, "#{@pfexec} curl -o /usr/sbin/bhhwcompat #{bhhwcompaturl}  && #{@pfexec} chmod +x /usr/sbin/bhhwcompat")
            result = execute(true, "#{@pfexec} test -f /usr/sbin/bhhwcompat  ; echo $?")
            raise Errors::MissingCompatCheckTool if result == 0
          end

          # Check whether OmniOS version is lower than r30

          cutoff_release = "1510380"
          cutoff_release = cutoff_release[0..-2].to_i
          uiinfo.info(I18n.t("vagrant_zones.bhyve_check") + "#{cutoff_release}")
          release = File.open('/etc/release', &:readline)
          release = release.scan(/\w+/).values_at(-1)
          release = release[0][1..-2].to_i
          raise Errors::SystemVersionIsTooLow if release < cutoff_release

          # Check Bhyve compatability
          uiinfo.info(I18n.t("vagrant_zones.bhyve_compat_check"))
          result = execute(false, "#{@pfexec} bhhwcompat -s")
          raise Errors::MissingBhyve if result.length == 1
        end
      end

      # This helps us set up the networking of the VM
      def setup(machine, uiinfo)
        config = machine.provider_config
        name = machine.name
        ### network Configurations

        if config.brand == 'bhyve'
          network(@machine, uiinfo, 'setup')
        end
      end

      # This helps up wait for the boot of the vm by using zlogin
      def waitforboot(machine, uiinfo)
        uiinfo.info(I18n.t('vagrant_zones.wait_for_boot'))
        name = @machine.name
        config = machine.provider_config
        responses = []
        if config.brand == 'bhyve'
          PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read, zlogin_write, pid|
            if zlogin_read.expect(/Last login: /)
              uiinfo.info(I18n.t('vagrant_zones.booted_check_terminal_access'))
              Timeout.timeout(config.setup_wait) do
                loop do
                  zlogin_read.expect(/\n/) { |line| responses.push line }
                  if responses[-1].to_s.match(/:~#/)
                    break
                  elsif responses[-1].to_s.match(/login: /)
                    ## Code to try to login with username and password
                    uiinfo.info(I18n.t('vagrant_zones.booted_check_terminal_access_auto_login'))
                  end
                end
              end
            end
            Process.kill('HUP', pid)
          end
        elsif config.brand == 'lx'
          if not user_exists?(machine, config.vagrant_user)
            zlogincommand(machine, %('echo nameserver 1.1.1.1 >> /etc/resolv.conf'))
            zlogincommand(machine, %('echo nameserver 1.0.0.1 >> /etc/resolv.conf'))
            zlogincommand(machine, 'useradd -m -s /bin/bash -U vagrant')
            zlogincommand(machine, "echo \"vagrant ALL=(ALL:ALL) NOPASSWD:ALL\" \\> /etc/sudoers.d/vagrant")
            zlogincommand(machine, 'mkdir -p /home/vagrant/.ssh')
            key_url = 'https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant.pub'
            zlogincommand(machine, "curl #{key_url} -O /home/vagrant/.ssh/authorized_keys")

            id_rsa = 'https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant'
            command = "#{@pfexec} curl #{id_rsa}  -O id_rsa"
            Util::Subprocess.new command do |stdout, stderr, thread|
              uiinfo.rewriting do |ui|
                ui.clear_line()
                ui.info(I18n.t('vagrant_zones.importing_vagrant_key'), new_line: false)
                ui.report_progress(stderr, 100, false)
              end
            end
            uiinfo.clear_line()
            zlogincommand(machine, 'chown -R vagrant:vagrant /home/vagrant/.ssh')
            zlogincommand(machine, 'chmod 600 /home/vagrant/.ssh/authorized_keys')
          end
        end
      end
      
      # This checks if the user exists on the VM, usually for LX zones
      def user_exists?(machine, user = 'vagrant')
        name = @machine.name
        ret  = execute(true, "#{@pfexec} zlogin #{name} id -u #{user}")
        if ret == 0
          return true
        end

        return false
      end


      # This gives us a console to the VM for the user
      def zlogincommand(machine, cmd)
        name = @machine.name
        execute(false, "#{@pfexec} zlogin #{name} #{cmd}")
      end

      # This gives us a console to the VM
      def zlogin(machine, cmd)
        name = @machine.name
        config = machine.provider_config
        responses = []
        PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read, zlogin_write, pid|
          zlogin_read.expect(/\n/) { |msg| zlogin_write.printf("#{cmd} \; echo \"Error Code: $?\"\n") }
          Timeout.timeout(30) do
            loop do
              zlogin_read.expect(/\r\n/) { |line| responses.push line }
              if responses[-1].to_s.match(/Error Code: 0/)
                break
              elsif responses[-1].to_s.match(/Error Code: \b(?![0]\b)\d{1,4}\b/)
                raise "==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
              end
            end
          end
          Process.kill('HUP', pid)
        end
      end

      # This filters the vagrantuser
      def user(machine)
        config = machine.provider_config
        user = config.vagrant_user
        return user
      end

      # This filters the userprivatekeypath
      def userprivatekeypath(machine)
        config = machine.provider_config
        userkey = config.vagrant_user_private_key_path.to_s
        if userkey.nil?
          File.open('id_rsa', 'w') do |f|
            f.puts 'sol'
            puts 'Not Key Defined, putting SOL in file so user can update later'
          end
          userkey = './id_rsa'
        end
        return userkey
      end

      # This filters the sshport
      def sshport(machine)
        config = machine.provider_config
        accessport = config.sshport.to_s
        unless accessport.to_s.nil? || accessport.to_i.zero?
          accessport = '22'
				end
        return accessport
      end

      # This filters the rdpport
      def rdpport(machine)
        config = machine.provider_config
        accessport = config.rdpport.to_s
        return accessport
      end

      # This filters the vagrantuserpass
      def vagrantuserpass(machine)
        config = machine.provider_config
        vagrantuserpass = config.vagrant_user_pass.to_s
        return vagrantuserpass
      end

      # This helps us create ZFS Snapshots
      def zfs(machine, uiinfo, job, dataset, snapshot_name)
        config = machine.provider_config
        name = machine.name
        if job == 'list'
          uiinfo.info(I18n.t('vagrant_zones.zfs_snapshot_list'))
          zfs_snapshots = execute(false, "#{@pfexec} zfs list -t snapshot | grep #{name}")
          zfssnapshots = zfs_snapshots.split(/\n/)
          snapshotrun = 0
          header = "Snapshot\tUsed\tAvailable\tRefer\tName"
          zfssnapshots.each do |snapshot|
            attributes = snapshot.gsub(/\s+/m, ' ').strip.split(' ')
            if !attributes[4].nil? && attributes[4] != '-'
              puts 'Drive Mounted at: ' + attributes[4]
            end
            # data = "##{snapshotrun}\t\t#{attributes[1]}\t#{attributes[2]}\t\t#{attributes[3]}\t#{attributes[0]}"
            snapshotrun += 1
          end
        elsif job == 'create'
          uiinfo.info(I18n.t('vagrant_zones.zfs_snapshot_create'))
          execute(false, "#{@pfexec} zfs snapshot #{dataset}@#{snapshot_name}")
        elsif job == 'destroy'
          uiinfo.info(I18n.t('vagrant_zones.zfs_snapshot_destroy'))
          zfs_snapshots = execute(false, "#{@pfexec} zfs destroy  #{dataset}@#{snapshot_name}")
        end
      end

      # Halts the Zone, first via shutdown command, then a halt.
      def halt(machine, uiinfo)
        name = @machine.name
        config = machine.provider_config
        vm_state = execute(false, "#{@pfexec} zoneadm -z #{name} list -p | awk -F: '{ print $3 }'")
        if vm_state == 'running'
          uiinfo.info(I18n.t('vagrant_zones.graceful_shutdown'))
          begin
            Timeout::timeout(config.clean_shutdown_time) {
              execute(false, "#{@pfexec} zoneadm -z #{name} shutdown")
            }
          rescue Timeout::Error
            uiinfo.info(I18n.t('vagrant_zones.graceful_shutdown_failed') + config.clean_shutdown_time.to_s)
            begin
              Timeout::timeout(60) {
                execute(false, "#{@pfexec} zoneadm -z #{name} halt")
              }
            rescue Timeout::Error
              raise "==> #{name}: VM failed to halt in alloted time 60 after waiting to shutdown for #{config.clean_shutdown_time.to_i}"
            end
          end
        end
      end

      # Destroys the Zone configurations and path
      def destroy(machine, id)
        name = @machine.name

        id.info(I18n.t('vagrant_zones.leaving'))
        id.info(I18n.t('vagrant_zones.destroy_zone'))

        ## Check state in zoneadm
        vm_state = execute(false, "#{@pfexec} zoneadm -z #{name} list -p | awk -F: '{ print $3 }'")

        ## If state is seen, uninstall from zoneadm and destroy from zonecfg
        if vm_state == 'installed'
          id.info(I18n.t('vagrant_zones.bhyve_zone_config_uninstall'))
          execute(false, "#{@pfexec} zoneadm -z #{name} uninstall -F")
          id.info(I18n.t('vagrant_zones.bhyve_zone_config_remove'))
          execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
        end
        ## If state is seen, uninstall from zoneadm and destroy from zonecfg
        if vm_state == 'incomplete' || vm_state == 'configured'
          id.info(I18n.t('vagrant_zones.bhyve_zone_config_remove'))
          execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
        end

        ### Nic Configurations
        state = 'delete'
        network(@machine, id, state)
      end
    end
  end
end
