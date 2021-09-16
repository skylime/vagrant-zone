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
        case config.brand
        when 'lx'
          results = execute(false, "#{@pfexec} zoneadm -z #{name} install -s #{box}")
          raise 'You appear to not have LX Zones installed in this Machine' if results.include? 'unknown brand'
        when 'bhyve'
          execute(false, "#{@pfexec} zoneadm -z #{name} install")
        when 'kvm' || 'illumos'
          raise Errors::NotYetImplemented
        end
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
        if port.nil?
          netport = ''
        else
          ip = '127.0.0.1' if ip.nil?
          netport = "#{ip}:#{port}"
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
          nictype = if opts[:nictype].nil?
                      'external'
                    else
                      opts[:nictype]

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
                     end
          if adpatertype.to_s == 'public_network'
            if opts[:dhcp] == true
              if opts[:managed]
                vnic_name = "vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number}"
                if mac == 'auto'
                  PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read, zlogin_write, pid|
                    command = "ip -4 addr show dev #{vnic_name} | head -n -1 | tail -1  | awk '{ print $2 }'  | cut -f1 -d\"/\" \n"
                    zlogin_read.expect(/\n/) { zlogin_write.printf(command) }
                    Timeout.timeout(30) do
                      loop do
                        zlogin_read.expect(/\r\n/) { |line| responses.push line }
                        if responses[-1].to_s.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)
                          ip = responses[-1][0].rstrip.gsub(/\e\[\?2004l/, '').lstrip
                          return nil if ip.length.empty?

                          return ip.gsub(/\t/, '') unless ip.length.empty?

                          break
                        end
                        errormessage = "==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
                        raise errormessage if responses[-1].to_s.match(/Error Code: \b(?!0\b)\d{1,4}\b/)
                      end
                    end
                    Process.kill('HUP', pid)
                  end
                else
                  PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read, zlogin_write, pid|
                    command = "ip -4 addr show dev  #{vnic_name} | head -n -1 | tail -1  | awk '{ print $2 }'  | cut -f1 -d\"/\" \n"
                    zlogin_read.expect(/\n/) { zlogin_write.printf(command) }
                    Timeout.timeout(30) do
                      loop do
                        zlogin_read.expect(/\r\n/) { |line| responses.push line }
                        if responses[-1].to_s.match(/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/)
                          ip = responses[-1][0].rstrip.gsub(/\e\[\?2004l/, '').lstrip
                          return nil if ip.empty?
                          return ip.gsub(/\t/, '') unless ip.empty?

                          break
                        end
                        errormessage = "==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
                        raise errormessage if responses[-1].to_s.match(/Error Code: \b(?!0\b)\d{1,4}\b/)
                      end
                    end
                    Process.kill('HUP', pid)
                  end
                end
              end
            elsif (opts[:dhcp] == false || opts[:dhcp].nil?) && opts[:managed]
              ip = opts[:ip].to_s
              return nil if ip.empty?

              return ip.gsub(/\t/, '')
            end
          end
        end
      end

      ## Manage Network Interfaces
      def network(machine, uiinfo, state)
        config = machine.provider_config
        name = @machine.name
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
            ip = if ip.empty?
                   nil
                 else
                   ip.gsub(/\t/, '')
                 end
            regex = /^(?:[[:xdigit:]]{2}([-:]))(?:[[:xdigit:]]{2}\1){4}[[:xdigit:]]{2}$/
            mac = opts[:mac] unless opts[:mac].nil?
            mac = 'auto' unless mac.match(regex)
            nictype = opts[:nictype] unless opts[:nictype].nil?
            dns = config.dns
            dns = [{ 'nameserver' => '1.1.1.1' }, { 'nameserver' => '8.8.8.8' }] if config.dns.nil?
            servers = []
            unless dns&.nil?
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
                       end
            vnic_name = "vnic#{nic_type}#{config.vm_type}_#{config.partition_id}_#{nic_number}"
            case state
            when 'create'
              if opts[:vlan].nil?
                execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} #{vnic_name}")
              else
                vlan = opts[:vlan]
                uiinfo.info(I18n.t('vagrant_zones.creating_vnic') + vnic_name)
                execute(false, "#{@pfexec} dladm create-vnic -l #{link} -m #{mac} -v #{vlan} #{vnic_name}")
              end
            when 'delete'
              uiinfo.info(I18n.t('vagrant_zones.removing_vnic') + vnic_name)
              vnic_configured = execute(false, "#{@pfexec} dladm show-vnic | grep #{vnic_name} | awk '{ print $1 }' ")
              execute(false, "#{@pfexec} dladm delete-vnic #{vnic_name}") if vnic_configured == vnic_name.to_s
            when 'config'
              uiinfo.info(I18n.t('vagrant_zones.vnic_setup') + vnic_name)
              case config.brand
              when 'lx'
                nic_attr = %(add net
  set physical=#{vnic_name}
  set global-nic=auto
  set allowed-address=#{allowed_address}
  add property (name=gateway,value="#{@defrouter}")
  add property (name=ips,value="#{allowed_address}")
  add property (name=primary,value="true")
end              )
                File.open("#{name}.zoneconfig", 'a') do |f|
                  f.puts nic_attr
                end
              when 'bhyve'
                nic_attr = %(add net
  set physical=#{vnic_name}
  set allowed-address=#{allowed_address}
end             )
                File.open("#{name}.zoneconfig", 'a') do |f|
                  f.puts nic_attr
                end
              end
            when 'setup'
              responses = []
              vmnic = []
              uiinfo.info(I18n.t('vagrant_zones.configure_interface_using_vnic') + vnic_name)
              ## regex to grab standard Device interface names in ifconfig
              regex = /(en|eth)(\d|o\d|s\d|x[0-9A-Fa-f]{2}{6}|(p\d)(s\d)(f?\d?))/
              PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read, zlogin_write, pid|
                zlogin_read.expect(/\n/) do
                  zlogin_write.printf("\nifconfig -s -a | grep -v lo  | awk '{ print $1 }' | grep -v Iface\n")
                end
                Timeout.timeout(30) do
                  staticrun = 0
                  dhcprun = 0
                  loop do
                    zlogin_read.expect(/\r\n/) { |line| responses.push line }
                    raise 'Did not receive expected networking configurations' if vmnic.include? responses[-1][0][/#{regex}/]

                    vmnic.append(responses[-1][0][/#{regex}/]) if responses[-1][0] =~ regex
                    vmnic.each do |interface|
                      unless interface[/#{regex}/, 1].nil?
                        if interface[/#{regex}/, 3].nil? && interface[/#{regex}/, 1] == 'en'
                          interface_desc = interface[/#{regex}/, 2].chars
                          case interface_desc[0]
                          when 'x'
                            mac_interface = interface[/#{regex}/, 1] + interface[/#{regex}/, 2]
                            mac_interface = mac_interface.split('enx', 0)
                            nicbus = mac_interface[1]
                          when 's' || 'o'
                            nicbus = interface_desc[1]
                          end
                        elsif interface[/#{regex}/, 1] != 'en'
                          nicbus = interface[/#{regex}/, 2]
                        else
                          nicbus = interface[/#{regex}/, 3]
                        end
                      end
                      devid = if interface[/#{regex}/, 4].nil?
                                nicbus
                              elsif interface[/#{regex}/, 5][/f\d/].nil?
                                'f0'
                              else
                                interface[/#{regex}/, 5]
                              end
                      raise 'No Device ID found' if devid.nil?

                      if mac == 'auto'
                        zlogin_write.printf("\nip link show dev #{vnic} | grep ether | awk '{ print $2 }'\n")
                        if responses[-1].to_s.match(/^(?:[[:xdigit:]]{2}([-:]))(?:[[:xdigit:]]{2}\1){4}[[:xdigit:]]{2}$/)
                          mac = responses[-1][0][/^(?:[[:xdigit:]]{2}([-:]))(?:[[:xdigit:]]{2}\1){4}[[:xdigit:]]{2}$/]
                        end
                      end

                      if nic_number == devid.gsub(/f/, '')
                        vnic = vmnic[devid.to_i]
                        ## Get Device Mac Address for when Mac is not specified

                        if opts[:dhcp] == true || opts[:dhcp].nil?
                          netplan = %(network:
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
        addresses: [#{servers[0]['nameserver']} , #{servers[1]['nameserver']}]  )
                          if dhcprun.zero?
                            command = "echo '#{netplan}' > /etc/netplan/#{vnic_name}.yaml; echo \"DHCP Error Code: $?\"\n"
                            zlogin_write.printf(command)
                            dhcprun += 1
                          end
                          infomessage = I18n.t('vagrant_zones.netplan_applied_dhcp') + "/etc/netplan/#{vnic_name}.yaml"
                          uiinfo.info(infomessage) if responses[-1].to_s.match(/DHCP Error Code: 0/)
                          errormessage = "\n==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
                          raise errormessage if responses[-1].to_s.match(/DHCP Error Code: \b(?!0\b)\d{1,4}\b/)
                        elsif opts[:dhcp] == false
                          netplan = %(network:
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
        addresses: [#{servers[0]['nameserver']} , #{servers[1]['nameserver']}] )
                          if staticrun.zero?
                            cmd = "echo '#{netplan}' > /etc/netplan/#{vnic_name}.yaml; echo \"Static Error Code: $?\"\n"
                            zlogin_write.printf(cmd)
                            staticrun += 1
                          end
                          if responses[-1].to_s.match(/Static Error Code: 0/)
                            uiinfo.info(I18n.t('vagrant_zones.netplan_applied_static') + "/etc/netplan/#{vnic_name}.yaml")
                          end
                          errormessage = "\n==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
                          raise errormessage if responses[-1].to_s.match(/Static Error Code: \b(?!0\b)\d{1,4}\b/)
                        end
                      end
                    end
                    ## Check if last command ran successfully and break from the loop
                    zlogin_write.printf("echo \"Final Network Check Error Code: $?\"\n")
                    if responses[-1].to_s.match(/Final Network Check Error Code: 0/)
                      uiinfo.info(I18n.t('vagrant_zones.netplan_set'))
                      break
                    end
                    errormessage = "==> #{name} ==> Final Network Check \nFailed with: #{responses[-1]}"
                    raise errormessage if responses[-1].to_s.match(/Final Network Check Error Code: \b(?!0\b)\d{1,4}\b/)
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
        config  = machine.provider_config
        dataset = "#{config.zonepath.delete_prefix('/')}/boot"
        datadir = machine.data_dir
        datasetroot = config.zonepath.delete_prefix('/').to_s
        ## Create Boot Volume
        case config.brand
        when 'lx'
          uiinfo.info(I18n.t('vagrant_zones.lx_zone_dataset') + dataset)
          execute(false, "#{@pfexec} zfs create -o zoned=on -p #{dataset}")
        when 'bhyve'
          uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_root') + datasetroot)
          execute(false, "#{@pfexec} zfs create #{datasetroot}")
          cinfo = "#{config.zonepathsize}, #{dataset}"
          uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_boot') + cinfo)
          execute(false, "#{@pfexec} zfs create -V #{config.zonepathsize} #{dataset}")
          uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_boot_volume') + dataset)
          commandtransfer = "#{@pfexec} pv -n #{@machine.box.directory.join('box.zss')} | #{@pfexec} zfs recv -u -v -F #{dataset} "
          Util::Subprocess.new commandtransfer do |_stdout, stderr, _thread|
            uiinfo.rewriting do |uiprogress|
              uiprogress.clear_line
              uiprogress.info(I18n.t('vagrant_zones.importing_box_image_to_disk') + "#{datadir}/box.zss ==> ", new_line: false)
              uiprogress.report_progress(stderr, 100, false)
            end
          end
          uiinfo.clear_line
        when 'illumos' || 'kvm'
          raise Errors::NotYetImplemented
        else
          raise Errors::InvalidBrand
        end
        ## Create Additional Disks
        unless config.additional_disks.nil?
          config.additional_disks.each do |disk|
            cinfo = ",#{disk['size']}, #{disk['array']}#{disk['path']}"
            uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_additional_volume') + cinfo)
            execute(false, "#{@pfexec} zfs create -V #{disk['size']} #{disk['array']}#{disk['path']}")
          end
        end
      end

      # This helps us set delete any associated datasets of the zone
      def delete_dataset(machine, uiinfo)
        config = machine.provider_config
        uiinfo.info(I18n.t('vagrant_zones.delete_disks'))
        ## Check if Boot Dataset exists
        zp = config.zonepath.delete_prefix('/').to_s
        dataset_boot_exists = execute(false, "#{@pfexec} zfs list | grep  #{zp}/boot |  awk '{ print $1 }' || true")
        ## If boot Dataset exists, delete it
        if dataset_boot_exists == "#{zp}/boot"
          ## Destroy Additional Disks
          unless  config.additional_disks.nil?
            disks = config.additional_disks
            disks.each do |disk|
              addataset = "#{disk['array']}#{disk['path']}"
              cinfo = "#{disk['size']}, #{addataset}"
              uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_additional_volume_destroy') + cinfo)
              dataset_exists = execute(false, "#{@pfexec} zfs list | grep  #{addataset} |  awk '{ print $1 }' || true")
              execute(false, "#{@pfexec} zfs destroy -r #{addataset}") if dataset_exists == addataset
            end
          end
          ## Destroy Boot dataset
          uiinfo.info(I18n.t('vagrant_zones.destroy_dataset') + "#{zp}/boot")
          execute(false, "#{@pfexec} zfs destroy -r #{zp}/boot")

        else
          uiinfo.info(I18n.t('vagrant_zones.dataset_nil'))
        end
        ## Check if root dataset exists
        uiinfo.info(I18n.t('vagrant_zones.destroy_dataset') + zp)
        dataset_root_exists = execute(false, "#{@pfexec} zfs list | grep  #{zp} |  awk '{ print $1 }' | grep -v path  || true")
        execute(false, "#{@pfexec} zfs destroy -r #{zp}") if dataset_root_exists == zp.to_s
      end

      # This helps us set the zone configurations for the zone
      def zonecfg(machine, uiinfo)
        name = @machine.name
        ## Seperate commands out to indvidual functions like Network, Dataset, and Emergency Console
        config = machine.provider_config
        attr = ''
        case config.brand
        when 'lx'
          uiinfo.info(I18n.t('vagrant_zones.lx_zone_config_gen'))
          machine.config.vm.networks.each do |adpatertype, opts|
            if adpatertype.to_s == 'public_network'
              @ip = opts[:ip].to_s
              cinfo = "#{opts[:ip]}/#{opts[:netmask]}"
              @network = NetAddr.parse_net(cinfo)
              @defrouter = opts[:gateway]
            end
          end
          attr = %(create
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
  set name=#{config.zonepath.delete_prefix('/')}/boot
end
set max-lwps=2000
        )
        when 'bhyve'
          ## General Configuration
          uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_config_gen'))
          attr = %(create
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
  set value=#{config.zonepath.delete_prefix('/')}/boot
end
add attr
  set name=type
  set type=string
  set value=#{config.os_type}
end     )
        end
        File.open("#{name}.zoneconfig", 'w') do |f|
          f.puts attr
        end

        ## Shared Disk Configurations
        if config.shared_disk_enabled
          uiinfo.info(I18n.t('vagrant_zones.setting_alt_shared_disk_configurations') + path.path)
          shared_disk_attr = %(add fs
  set dir=/vagrant
  set special=#{config.shared_dir}
  set type=lofs
end       )
          File.open("#{name}.zoneconfig", 'a') do |f|
            f.puts shared_disk_attr
          end
        end

        ## CPU Configurations
        if config.cpu_configuration == 'simple' && (config.brand == 'bhyve' || config.brand == 'kvm')
          cpu_attr = %(add attr
  set name=vcpus
  set type=string
  set value=#{config.cpus}
end       )
          File.open("#{name}.zoneconfig", 'a') do |f|
            f.puts cpu_attr
          end
        elsif config.cpu_configuration == 'complex' && (config.brand == 'bhyve' || config.brand == 'kvm')

          hash = config.complex_cpu_conf[0]
          cpu_attr = %(add attr
  set name=vcpus
  set type=string
  set value="sockets=#{hash['sockets']},cores=#{hash['cores']},threads=#{hash['threads']}"
end       )
          File.open("#{name}.zoneconfig", 'a') do |f|
            f.puts cpu_attr
          end
        end

        ### Passthrough PCI Devices
        # if config.ppt_devices == 'none'
        #   ui.info(I18n.t('vagrant_zones.setting_pci_configurations') + path.path)
        #  puts config.ppt
        #  puts config.config.ppt
        #  ppt_attr = %(
        # add device
        #  set match=/dev/ppt0
        # end
        # add attr
        #  set name=ppt0
        #  set type=string
        #  set value='slot0'
        # end
        #  }
        #  ppt_data_attr = %(
        # {ppt_data}
        #  }

        #  File.open("#{name}.zoneconfig", 'a') do |f|
        #    f.puts ppt_data_attr
        #  end
        # end

        ## CDROM Configurations

        unless config.cdroms.nil?
          cdroms = config.cdroms
          cdrun = 0
          cdroms.each do |cdrom|
            cdname = 'cdrom'
            uiinfo.info(I18n.t('vagrant_zones.setting_cd_rom_configurations') + cdrom['path'])
            cdname += cdrun.to_s if cdrun.positive?
            cdrun += 1
            cdrom_attr = %(add attr
    set name=#{cdname}
    set type=string
    set value=#{cdrom['path']}
end
add fs
    set dir=#{cdrom['path']}
    set special=#{cdrom['path']}
    set type=lofs
    add options ro
    add options nodevices
end         )
            File.open("#{name}.zoneconfig", 'a') do |f|
              f.puts cdrom_attr
            end
          end
        end

        ## Additional Disk Configurations
        unless config.additional_disks.nil?
          disks = config.additional_disks
          diskrun = 0
          disks.each do |disk|
            diskname = 'disk'
            cinfo = "#{disk['size']}, #{disk['path']}"
            uiinfo.info(I18n.t('vagrant_zones.setting_additional_disks_configurations') + cinfo)
            diskname += diskrun.to_s if diskrun.positive?
            diskrun += 1
            additional_disk_attr = %(add device
  set match=/dev/zvol/rdsk#{disk['path']}
end
add attr
  set name=#{diskname}
  set type=string
  set value=#{disk['path']}
end         )
            File.open("#{name}.zoneconfig", 'a') do |f|
              f.puts additional_disk_attr
            end
          end
        end

        ## Console access configuration
        unless config.console.nil?
          console = config.console
          if console != 'disabled'
            port = if %w[console].include?(console) && config.consoleport.nil?
                     'socket,/tmp/vm.com1'
                   elsif %w[webvnc vnc].include?(console)
                     console = 'vnc'
                     'on'
                   else
                     config.consoleport
                   end

            port += ',wait' if config.console_onboot
            cinfo = "Console type: #{console},  Port: #{port}"
            uiinfo.info(I18n.t('vagrant_zones.setting_console_access') + cinfo)
            console_attr = %(add attr
    set name=#{console}
    set type=string
    set value=#{port}
end            )
            File.open("#{name}.zoneconfig", 'a') do |f|
              f.puts console_attr
            end
          end
        end

        ## Cloud-init settings
        if config.cloud_init_enabled
          cloudconfig = case config.cloud_init_enabled
                        when 'on'
                          'on'
                        when 'off'
                          'off'
                        else
                          config.cloud_init_enabled
                        end
          unless config.cloud_init_dnsdomain.nil?
            cinfo = "Cloud-init dns-domain: #{config.cloud_init_dnsdomain}"
            uiinfo.info(I18n.t('vagrant_zones.setting_cloud_dnsdomain') + cinfo)
            cloud_init_dnsdomain_attr = %(add attr
      set name=dns-domain
      set type=string
      set value=#{config.cloud_init_dnsdomain}
  end       )
            File.open("#{name}.zoneconfig", 'a') do |f|
              f.puts cloud_init_dnsdomain_attr
            end
          end
          unless config.cloud_init_password.nil?
            cinfo = "Cloud-init password: #{config.cloud_init_password}"
            uiinfo.info(I18n.t('vagrant_zones.setting_cloud_password') + cinfo)
            cloud_init_password_attr = %(add attr
      set name=password
      set type=string
      set value=#{config.cloud_init_password}
  end       )
            File.open("#{name}.zoneconfig", 'a') do |f|
              f.puts cloud_init_password_attr
            end
          end
          unless config.cloud_init_resolvers.nil?
            cinfo = "Cloud-init resolvers: #{config.cloud_init_resolvers}"
            uiinfo.info(I18n.t('vagrant_zones.setting_cloud_resolvers') + cinfo)
            cloud_init_resolvers_attr = %(add attr
      set name=resolvers
      set type=string
      set value=#{config.cloud_init_resolvers}
  end       )
            File.open("#{name}.zoneconfig", 'a') do |f|
              f.puts cloud_init_resolvers_attr
            end
          end
          unless config.cloud_init_sshkey.nil?
            cinfo = "Cloud-init SSH Key: #{config.cloud_init_sshkey}"
            uiinfo.info(I18n.t('vagrant_zones.setting_cloud_ssh_key') + cinfo)
            cloud_init_ssh_attr = %(add attr
      set name=sshkey
      set type=string
      set value=#{config.cloud_init_sshkey}
  end       )
            File.open("#{name}.zoneconfig", 'a') do |f|
              f.puts cloud_init_ssh_attr
            end
          end

          cinfo = "Cloud Config: #{cloudconfig}"
          uiinfo.info(I18n.t('vagrant_zones.setting_cloud_init_access') + cinfo)
          cloud_init_attr = %(add attr
    set name=cloud-init
    set type=string
    set value=#{cloudconfig}
end          )
          File.open("#{name}.zoneconfig", 'a') do |f|
            f.puts cloud_init_attr
          end
        end

        ## Nic Configurations
        network(@machine, uiinfo, 'config')

        ## Write out Config
        exit = %(exit)
        File.open("#{name}.zoneconfig", 'a') do |f|
          f.puts exit
        end
        uiinfo.info(I18n.t('vagrant_zones.exporting_bhyve_zone_config_gen'))
        ## Export config to zonecfg
        execute(false, "cat #{name}.zoneconfig | #{@pfexec} zonecfg -z #{machine.name}")
      end

      # This ensures the zone is safe to boot
      def check_zone_support(machine, uiinfo)
        config = machine.provider_config
        ## Detect if Virtualbox is Running
        ## Kernel, KVM, and Bhyve cannot run conncurently with Virtualbox:
        ### https://forums.virtualbox.org/viewtopic.php?f=11&t=64652
        uiinfo.info(I18n.t('vagrant_zones.vbox_run_check'))
        result = execute(true, "#{@pfexec} VBoxManage list runningvms")
        raise Errors::VirtualBoxRunningConflictDetected if result.zero?

        ## https://man.omnios.org/man5/brands
        case config.brand
        when 'lx'
          uiinfo.info(I18n.t('vagrant_zones.lx_check'))
        when 'ipkg'
          uiinfo.info(I18n.t('vagrant_zones.ipkg_check'))
        when 'lipkg'
          uiinfo.info(I18n.t('vagrant_zones.lipkg_check'))
        when 'pkgsrc'
          uiinfo.info(I18n.t('vagrant_zones.pkgsrc_check'))
        when 'sparse'
          uiinfo.info(I18n.t('vagrant_zones.sparse_check'))
        when 'kvm'
          ## https://man.omnios.org/man5/kvm
          uiinfo.info(I18n.t('vagrant_zones.kvm_check'))
        when 'illumos'
          uiinfo.info(I18n.t('vagrant_zones.illumos_check'))
        when 'bhyve'
          ## https://man.omnios.org/man5/bhyve
          ## Check for  bhhwcompat
          result = execute(true, "#{@pfexec} test -f /usr/sbin/bhhwcompat  ; echo $?")
          if result == 1
            bhhwcompaturl = 'https://downloads.omnios.org/misc/bhyve/bhhwcompat'
            execute(true, "#{@pfexec} curl -o /usr/sbin/bhhwcompat #{bhhwcompaturl}  && #{@pfexec} chmod +x /usr/sbin/bhhwcompat")
            result = execute(true, "#{@pfexec} test -f /usr/sbin/bhhwcompat  ; echo $?")
            raise Errors::MissingCompatCheckTool if result.zero?
          end

          # Check whether OmniOS version is lower than r30

          cutoff_release = '1510380'
          cutoff_release = cutoff_release[0..-2].to_i
          uiinfo.info(I18n.t('vagrant_zones.bhyve_check') + cutoff_release.to_s)
          release = File.open('/etc/release', &:readline)
          release = release.scan(/\w+/).values_at(-1)
          release = release[0][1..-2].to_i
          raise Errors::SystemVersionIsTooLow if release < cutoff_release

          # Check Bhyve compatability
          uiinfo.info(I18n.t('vagrant_zones.bhyve_compat_check'))
          result = execute(false, "#{@pfexec} bhhwcompat -s")
          raise Errors::MissingBhyve if result.length == 1
        end
      end

      # This helps us set up the networking of the VM
      def setup(machine, uiinfo)
        config = machine.provider_config
        ### network Configurations
        network(@machine, uiinfo, 'setup') if config.brand == 'bhyve'
      end

      # This helps up wait for the boot of the vm by using zlogin
      def waitforboot(machine, uiinfo)
        uiinfo.info(I18n.t('vagrant_zones.wait_for_boot'))
        name = @machine.name
        config = machine.provider_config
        responses = []
        case config.brand
        when 'bhyve'
          PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read, _zlogin_write, pid|
            if zlogin_read.expect(/Last login: /)
              uiinfo.info(I18n.t('vagrant_zones.booted_check_terminal_access'))
              Timeout.timeout(config.setup_wait) do
                loop do
                  zlogin_read.expect(/\n/) { |line| responses.push line }
                  break if responses[-1].to_s.match(/:~#/)

                  ## Code to try to login with username and password
                  uiinfo.info(I18n.t('vagrant_zones.booted_check_terminal_access_auto_login')) if responses[-1].to_s.match(/login: /)
                end
              end
            end
            Process.kill('HUP', pid)
          end
        when 'lx'
          unless user_exists?(machine, config.vagrant_user)
            zlogincommand(machine, %('echo nameserver 1.1.1.1 >> /etc/resolv.conf'))
            zlogincommand(machine, %('echo nameserver 1.0.0.1 >> /etc/resolv.conf'))
            zlogincommand(machine, 'useradd -m -s /bin/bash -U vagrant')
            zlogincommand(machine, 'echo "vagrant ALL=(ALL:ALL) NOPASSWD:ALL" \\> /etc/sudoers.d/vagrant')
            zlogincommand(machine, 'mkdir -p /home/vagrant/.ssh')
            key_url = 'https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant.pub'
            zlogincommand(machine, "curl #{key_url} -O /home/vagrant/.ssh/authorized_keys")

            id_rsa = 'https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant'
            command = "#{@pfexec} curl #{id_rsa}  -O id_rsa"
            Util::Subprocess.new command do |_stdout, stderr, _thread|
              uiinfo.rewriting do |ui|
                ui.clear_line
                ui.info(I18n.t('vagrant_zones.importing_vagrant_key'), new_line: false)
                ui.report_progress(stderr, 100, false)
              end
            end
            uiinfo.clear_line
            zlogincommand(machine, 'chown -R vagrant:vagrant /home/vagrant/.ssh')
            zlogincommand(machine, 'chmod 600 /home/vagrant/.ssh/authorized_keys')
          end
        end
      end

      # This checks if the user exists on the VM, usually for LX zones
      def user_exists?(machine, user = 'vagrant')
        name = machine.name
        ret  = execute(true, "#{@pfexec} zlogin #{name} id -u #{user}")
        return true if ret.zero?

        false
        # return false
      end

      # This gives us a  console to the VM for the user
      def zlogincommand(machine, cmd)
        name = machine.name
        execute(false, "#{@pfexec} zlogin #{name} #{cmd}")
      end

      # This gives us a console to the VM
      def zlogin(machine, cmd)
        name = machine.name
        responses = []
        PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read, zlogin_write, pid|
          zlogin_read.expect(/\n/) { zlogin_write.printf("#{cmd} \; echo \"Error Code: $?\"\n") }
          Timeout.timeout(30) do
            loop do
              zlogin_read.expect(/\r\n/) { |line| responses.push line }
              break if responses[-1].to_s.match(/Error Code: 0/)

              errormessage = "==> #{name} ==> Command ==> #{cmd} \nFailed with ==> #{responses[-1]}"
              raise errormessage if responses[-1].to_s.match(/Error Code: \b(?!0\b)\d{1,4}\b/)
            end
          end
          Process.kill('HUP', pid)
        end
      end

      # This filters the vagrantuser
      def user(machine)
        config = machine.provider_config
        user = config.vagrant_user unless config.vagrant_user.nil?
        user = 'vagrant' if config.vagrant_user.nil?
        user
      end

      # This filters the userprivatekeypath
      def userprivatekeypath(machine)
        config = machine.provider_config
        userkey = config.vagrant_user_private_key_path.to_s
        if config.vagrant_user_private_key_path.to_s.nil?
          id_rsa = 'https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant'
          file = './id_rsa'
          command = "#{@pfexec} curl #{id_rsa}  -O #{file}"
          Util::Subprocess.new command do |_stdout, stderr, _thread|
            uiinfo.rewriting do |ui|
              ui.clear_line
              ui.info(I18n.t('vagrant_zones.importing_vagrant_key'), new_line: false)
              ui.report_progress(stderr, 100, false)
            end
          end
          uiinfo.clear_line
          userkey = './id_rsa'
        end
        userkey
      end

      # This filters the sshport
      def sshport(machine)
        config = machine.provider_config
        sshport = '22'
        sshport = config.sshport.to_s unless config.sshport.to_s.nil? || config.sshport.to_i.zero?
        sshport
      end

      # This filters the rdpport
      def rdpport(machine)
        config = machine.provider_config
        config.rdpport.to_s unless config.rdpport.to_s.nil?
      end

      # This filters the vagrantuserpass
      def vagrantuserpass(machine)
        config = machine.provider_config
        config.vagrant_user_pass unless config.vagrant_user_pass.to_s.nil?
      end

      # This helps us create ZFS Snapshots
      def zfs(machine, uiinfo, job, dataset, snapshot_name)
        name = machine.name
        case job
        when 'list'
          uiinfo.info(I18n.t('vagrant_zones.zfs_snapshot_list'))
          zfs_snapshots = execute(false, "#{@pfexec} zfs list -t snapshot | grep #{name}")
          zfssnapshots = zfs_snapshots.split(/\n/)
          snapshotrun = 0
          header = "Snapshot\tUsed\tAvailable\tRefer\tName"
          zfssnapshots.each do |snapshot|
            attributes = snapshot.gsub(/\s+/m, ' ').strip.split
            puts "Drive Mounted at: #{header} #{attributes[4]}" if !attributes[4].nil? && attributes[4] != '-'
            # data = "##{snapshotrun}\t\t#{attributes[1]}\t#{attributes[2]}\t\t#{attributes[3]}\t#{attributes[0]}"
            snapshotrun += 1
          end
        when 'create'
          uiinfo.info(I18n.t('vagrant_zones.zfs_snapshot_create'))
          execute(false, "#{@pfexec} zfs snapshot #{dataset}@#{snapshot_name}")
        when 'destroy'
          uiinfo.info(I18n.t('vagrant_zones.zfs_snapshot_destroy'))
          execute(false, "#{@pfexec} zfs destroy  #{dataset}@#{snapshot_name}")
        end
      end

      # Halts the Zone, first via shutdown command, then a halt.
      def halt(machine, uiinfo)
        name = machine.name
        config = machine.provider_config

        ## Check state in zoneadm
        vm_state = execute(false, "#{@pfexec} zoneadm -z #{name} list -p | awk -F: '{ print $3 }'")
        uiinfo.info(I18n.t('vagrant_zones.graceful_shutdown'))
        begin
          Timeout.timeout(config.clean_shutdown_time) do
            execute(false, "#{@pfexec} zoneadm -z #{name} shutdown") if vm_state == 'running'
          end
        rescue Timeout::Error
          uiinfo.info(I18n.t('vagrant_zones.graceful_shutdown_failed') + config.clean_shutdown_time.to_s)
          begin
            Timeout.timeout(60) do
              execute(false, "#{@pfexec} zoneadm -z #{name} halt")
            end
          rescue Timeout::Error
            raise "==> #{name}: VM failed to halt in alloted time 60 after waiting to shutdown for #{config.clean_shutdown_time}"
          end
        end
      end

      # Destroys the Zone configurations and path
      def destroy(machine, id)
        name = machine.name

        id.info(I18n.t('vagrant_zones.leaving'))
        id.info(I18n.t('vagrant_zones.destroy_zone'))

        ## Check state in zoneadm
        vm_state = execute(false, "#{@pfexec} zoneadm -z #{name} list -p | awk -F: '{ print $3 }'")

        ## If state is installed, uninstall from zoneadm and destroy from zonecfg
        if vm_state == 'installed'
          id.info(I18n.t('vagrant_zones.bhyve_zone_config_uninstall'))
          execute(false, "#{@pfexec} zoneadm -z #{name} uninstall -F")
          id.info(I18n.t('vagrant_zones.bhyve_zone_config_remove'))
          execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
        end

        ## If state is configured or incomplete, uninstall from destroy from zonecfg
        if %w[incomplete configured].include?(vm_state)
          id.info(I18n.t('vagrant_zones.bhyve_zone_config_remove'))
          execute(false, "#{@pfexec} zonecfg -z #{name} delete -F")
        end

        ### Nic Configurations
        state = 'delete'
        network(machine, id, state)
      end
    end
  end
end
