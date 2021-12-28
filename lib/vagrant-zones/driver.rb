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

      # Execute System commands
      def execute(*cmd, **opts, &block)
        @executor.execute(*cmd, **opts, &block)
      end

      ## Begin installation for zone
      def install(machine, uiinfo)
        config = machine.provider_config
        name = @machine.name
        case config.brand
        when 'lx'
          box = "#{@machine.data_dir}/#{@machine.config.vm.box}"
          results = execute(false, "#{@pfexec} zoneadm -z #{name} install -s #{box}")
          raise 'You appear to not have the LX Package installed in this Machine' if results.include? 'unknown brand'
        when 'bhyve'
          results = execute(false, "#{@pfexec} zoneadm -z #{name} install")
          raise 'You appear to not have the bhyve Package installed in this Machine' if results.include? 'unknown brand'
        when 'kvm' || 'illumos'
          raise Errors::NotYetImplemented
        end
        uiinfo.info(I18n.t('vagrant_zones.installing_zone') + config.brand)
      end

      ## Control the zone from inside the zone OS
      def control(control)
        case control
        when 'restart'
          command = 'sudo shutdown -r'
          ssh_run_command(@machine, command)
        when 'shutdown'
          command = 'sudo init 0 || true'
          ssh_run_command(@machine, command)
        else
          puts 'No Command specified'
        end
      end

      ## Run commands over SSH instead of ZLogin
      def ssh_run_command(machine, command)
        ip = get_ip_address(machine)
        user = user(machine)
        key = userprivatekeypath(machine).to_s
        password = vagrantuserpass(machine).to_s
        port = sshport(machine).to_s
        port = 22 if sshport(machine).to_s.nil?
        puts "#{password} not used for this connection at this time"
        execute(true, "#{@pfexec} pwd && ssh -o 'StrictHostKeyChecking=no' -p #{port} -i #{key} #{user}@#{ip} '#{command}' ")
      end

      ## Function to provide console, vnc, or webvnc access
      def console(machine, command, ip, port, exit)
        detach = exit[:detach]
        kill = exit[:kill]
        name = machine.name
        config = machine.provider_config
        if port.nil?
          port = if config.consoleport.nil?
                   ''
                 else
                   config.consoleport
                 end
        end
        ip = ('0.0.0.0' unless ip =~ Resolv::IPv4::Regex ? true : false)
        netport = "#{ip}:#{port}"
        pid = 0
        if File.exist?('console.pid')
          pid = File.readlines('console.pid')[0].strip
          ctype = File.readlines('console.pid')[1].strip
          time_started = File.readlines('console.pid')[2].strip
          vmname = File.readlines('console.pid')[3].strip
          nport = File.readlines('console.pid')[4].strip
          puts "VM is running with PID: #{pid} since: #{time_started} as console type: #{ctype} served at: #{nport}" if vmname[name.to_s]
          if kill == 'yes'
            File.delete('console.pid') if File.exist?('console.pid')
            Process.kill 'TERM', pid.to_i
            Process.detach pid.to_i
            puts 'Session Terminated'
          end
        else
          case command
          when 'webvnc'
            run = "pfexec zadm webvnc #{netport} #{name}"
            pid = spawn(run)
            Process.wait pid if detach == 'no'
            Process.detach(pid) if detach == 'yes'
            time = Time.new.strftime('%Y-%m-%d-%H:%M:%S')
            File.write('console.pid', "#{pid}\n#{command}\n#{time}\n#{name}\n#{netport}") if detach == 'yes'
            puts "VM is running with PID: #{pid} as console type: #{command} served at: #{netport}" if detach == 'yes'
          when 'vnc'
            run = "pfexec zadm vnc #{netport} #{name}"
            pid = spawn(run)
            Process.wait pid if detach == 'no'
            Process.detach(pid) if detach == 'yes'
            time = Time.new.strftime('%Y-%m-%d-%H:%M:%S')
            File.write('console.pid', "#{pid}\n#{command}\n#{time}\n#{name}\n#{netport}") if detach == 'yes'
            puts "VM is running with PID: #{pid} as console type: #{command} served at: #{netport}" if detach == 'yes'
          when 'zlogin'
            run = "#{@pfexec} zadm console #{name}"
            exec(run)
          end
        end
      end

      ## Boot the Machine
      def boot(machine, uiinfo)
        name = machine.name
        uiinfo.info(I18n.t('vagrant_zones.starting_zone'))
        execute(false, "#{@pfexec} zoneadm -z #{name} boot")
      end

      # This filters the firmware
      def vtype(machine)
        config = machine.provider_config
        case config.vm_type
        when /template/
          '1'
        when /development/
          '2'
        when /production/
          '3'
        when /firewall/
          '4'
        when /other/
          '5'
        end
      end

      def get_ip_address(machine)
        config = machine.provider_config
        name = @machine.name
        machine.config.vm.networks.each do |adaptertype, opts|
          responses = []
          nictype = if opts[:nictype].nil?
                      'external'
                    else
                      opts[:nictype]
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
          if opts[:dhcp] && opts[:managed] && adaptertype.to_s == 'public_network'
            vnic_name = "vnic#{nic_type}#{vtype(machine)}_#{config.partition_id}_#{opts[:nic_number]}"
            PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read, zlogin_write, pid|
              command = "ip -4 addr show dev #{vnic_name} | head -n -1 | tail -1 | awk '{ print $2 }' | cut -f1 -d\"/\" \n"
              zlogin_read.expect(/\n/) { zlogin_write.printf(command) }
              Timeout.timeout(config.clean_shutdown_time) do
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
          elsif (opts[:dhcp] == false || opts[:dhcp].nil?) && opts[:managed] && adaptertype.to_s == 'public_network'
            ip = opts[:ip].to_s
            return nil if ip.empty?

            return ip.gsub(/\t/, '')
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
          zlogin(machine, 'rm -rf /etc/netplan/*.yaml')
        end
        machine.config.vm.networks.each do |adaptertype, opts|
          next unless adaptertype.to_s == 'public_network'

          ip = opts[:ip].to_s
          defrouter = opts[:gateway].to_s
          allowed_address = "#{ip}/#{IPAddr.new(opts[:netmask].to_s).to_i.to_s(2).count('1')}"
          ip = if ip.empty?
                 nil
               else
                 ip.gsub(/\t/, '')
               end
          regex = /^(?:[[:xdigit:]]{2}([-:]))(?:[[:xdigit:]]{2}\1){4}[[:xdigit:]]{2}$/
          mac = opts[:mac] unless opts[:mac].nil?
          mac = 'auto' unless mac.match(regex)
          dns = config.dns
          dns = [{ 'nameserver' => '1.1.1.1' }, { 'nameserver' => '8.8.8.8' }] if config.dns.nil?
          servers = []
          unless dns&.nil?
            dns.each do |server|
              servers.append(server)
            end
          end
          nictype = if opts[:nictype].nil?
                      'external'
                    else
                      opts[:nictype]
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
          vnic_name = "vnic#{nic_type}#{vtype(machine)}_#{config.partition_id}_#{opts[:nic_number]}"
          case state
          # Create the VNIC
          when 'create'
            if opts[:vlan].nil?
              execute(false, "#{@pfexec} dladm create-vnic -l #{opts[:bridge]} -m #{mac} #{vnic_name}")
            else
              vlan = opts[:vlan]
              uiinfo.info(I18n.t('vagrant_zones.creating_vnic') + vnic_name)
              execute(false, "#{@pfexec} dladm create-vnic -l #{opts[:bridge]} -m #{mac} -v #{vlan} #{vnic_name}")
            end
          # Delete the VNIC
          when 'delete'
            vnic_configured = execute(false, "#{@pfexec} dladm show-vnic | grep #{vnic_name} | awk '{ print $1 }' ")
            uiinfo.info(I18n.t('vagrant_zones.removing_vnic') + vnic_name) if vnic_configured == vnic_name.to_s
            execute(false, "#{@pfexec} dladm delete-vnic #{vnic_name}") if vnic_configured == vnic_name.to_s
            uiinfo.info(I18n.t('vagrant_zones.no_removing_vnic')) unless vnic_configured == vnic_name.to_s
          # Set Zonecfg Settings
          when 'config'
            uiinfo.info(" #{I18n.t('vagrant_zones.vnic_setup')}#{vnic_name}")
            strt = "#{@pfexec} zonecfg -z #{name} "
            case config.brand
            when 'lx'
              shrtstr1 = %(set allowed-address=#{allowed_address}; add property (name=gateway,value="#{defrouter}"); )
              shrtstr2 = %(add property (name=ips,value="#{allowed_address}"); add property (name=primary,value="true"); end;)
              execute(false, %(#{strt}"add net; set physical=#{vnic_name}; set global-nic=auto; #{shrtstr1} #{shrtstr2}"))
            when 'bhyve'
              execute(false, %(#{strt}"add net; set physical=#{vnic_name}; set allowed-address=#{allowed_address}; end;"))
            end
          # Setup Interface in the VM
          when 'setup'
            uiinfo.info(I18n.t('vagrant_zones.configure_interface_using_vnic') + vnic_name)
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
      addresses: [#{ip}/#{IPAddr.new(opts[:netmask].to_s).to_i.to_s(2).count('1')}]
      gateway4: #{defrouter}
      nameservers:
        addresses: [#{servers[0]['nameserver']} , #{servers[1]['nameserver']}] )
            cmd = "echo '#{netplan}' > /etc/netplan/#{vnic_name}.yaml"
            infomessage = I18n.t('vagrant_zones.netplan_applied_static') + "/etc/netplan/#{vnic_name}.yaml"
            uiinfo.info(infomessage) if zlogin(machine, cmd)
            ## Apply the Configuration
            uiinfo.info(I18n.t('vagrant_zones.netplan_applied')) if zlogin(machine, 'netplan apply')
          end
        end
      end

      # This helps us create all the datasets for the zone
      def create_dataset(machine, uiinfo)
        config = machine.provider_config
        name = machine.name
        bootconfigs = config.boot
        datasetpath = "#{bootconfigs['array']}/#{bootconfigs['dataset']}/#{name}"
        datasetroot = "#{datasetpath}/#{bootconfigs['volume_name']}"
        sparse = '-s ' if bootconfigs['sparse']
        sparse = '' unless bootconfigs['sparse']
        uiinfo.info(I18n.t('vagrant_zones.begin_create_datasets'))
        ## Create Boot Volume
        case config.brand
        when 'lx'
          uiinfo.info(I18n.t('vagrant_zones.lx_zone_dataset') + datasetroot)
          execute(false, "#{@pfexec} zfs create -o zoned=on -p #{datasetroot}")
        when 'bhyve'
          ## Create root dataset
          uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_root') + datasetpath)
          execute(false, "#{@pfexec} zfs create #{datasetpath}")

          # Create boot volume
          cinfo = "#{datasetroot}, #{bootconfigs['size']}"
          uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_boot') + cinfo)
          execute(false, "#{@pfexec} zfs create #{sparse} -V #{bootconfigs['size']} #{datasetroot}")

          ## Import template to boot volume
          uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_boot_volume') + datasetroot)
          commandtransfer = "#{@pfexec} pv -n #{@machine.box.directory.join('box.zss')} | #{@pfexec} zfs recv -u -v -F #{datasetroot} "
          uiinfo.info(I18n.t('vagrant_zones.template_import_path') + @machine.box.directory.join('box.zss').to_s)
          Util::Subprocess.new commandtransfer do |_stdout, stderr, _thread|
            uiinfo.rewriting do |uiprogress|
              uiprogress.clear_line
              uiprogress.info(I18n.t('vagrant_zones.importing_box_image_to_disk') + "#{datasetroot} ", new_line: false)
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
        return if config.additional_disks.nil?

        config.additional_disks.each do |disk|
          shrtpath = "#{disk['array']}/#{disk['dataset']}/#{name}"
          dataset = "#{shrtpath}/#{disk['volume_name']}"
          sparse = '-s '
          sparse = '' unless disk['sparse']
          ## If the root data set doesn't exist create it
          addsrtexists = execute(false, "#{@pfexec} zfs list | grep #{shrtpath} | awk '{ print $1 }' | head -n 1 || true")
          cinfo = shrtpath.to_s
          uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_additional_volume_root') + cinfo) unless addsrtexists == shrtpath.to_s
          ## Create the Additional volume
          execute(false, "#{@pfexec} zfs create #{shrtpath}") unless addsrtexists == shrtpath.to_s
          cinfo = "#{dataset}, #{disk['size']}"
          uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_additional_volume') + cinfo)
          execute(false, "#{@pfexec} zfs create #{sparse} -V #{disk['size']} #{dataset}")
        end
      end

      # This helps us delete any associated datasets of the zone
      def delete_dataset(machine, uiinfo)
        config = machine.provider_config
        name = machine.name
        # datadir = machine.data_dir
        bootconfigs = config.boot
        datasetpath = "#{bootconfigs['array']}/#{bootconfigs['dataset']}/#{name}"
        datasetroot = "#{datasetpath}/#{bootconfigs['volume_name']}"
        uiinfo.info(I18n.t('vagrant_zones.delete_disks'))

        ## Check if Boot Dataset exists
        zp = datasetpath.delete_prefix('/').to_s
        dataset_boot_exists = execute(false, "#{@pfexec} zfs list | grep #{datasetroot} | awk '{ print $1 }' || true")

        ## Destroy Boot dataset
        uiinfo.info(I18n.t('vagrant_zones.destroy_dataset') + datasetroot.to_s) if dataset_boot_exists == datasetroot.to_s
        execute(false, "#{@pfexec} zfs destroy -r #{datasetroot}") if dataset_boot_exists == datasetroot.to_s
        ## Insert Error Checking Here in case disk is busy
        uiinfo.info(I18n.t('vagrant_zones.boot_dataset_nil')) unless dataset_boot_exists == datasetroot.to_s

        ## Destroy Additional Disks
        unless config.additional_disks.nil?
          disks = config.additional_disks
          disks.each do |disk|
            diskpath = "#{disk['array']}/#{disk['dataset']}/#{name}"
            addataset = "#{diskpath}/#{disk['volume_name']}"
            cinfo = addataset.to_s
            dataset_exists = execute(false, "#{@pfexec} zfs list | grep #{addataset} | awk '{ print $1 }' || true")
            uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_dataset_additional_volume_destroy') + cinfo) if dataset_exists == addataset
            execute(false, "#{@pfexec} zfs destroy -r #{addataset}") if dataset_exists == addataset
            uiinfo.info(I18n.t('vagrant_zones.additional_dataset_nil')) unless dataset_exists == addataset
            cinfo = diskpath.to_s
            addsrtexists = execute(false, "#{@pfexec} zfs list | grep #{diskpath} | awk '{ print $1 }' | head -n 1 || true")
            uiinfo.info(I18n.t('vagrant_zones.addtl_volume_destroy_root') + cinfo) if addsrtexists == diskpath && addsrtexists != zp.to_s
            execute(false, "#{@pfexec} zfs destroy #{diskpath}") if addsrtexists == diskpath && addsrtexists != zp.to_s
          end
        end

        ## Check if root dataset exists
        dataset_root_exists = execute(false, "#{@pfexec} zfs list | grep #{zp} | awk '{ print $1 }' | grep -v path || true")
        uiinfo.info(I18n.t('vagrant_zones.destroy_root_dataset') + zp) if dataset_root_exists == zp.to_s
        execute(false, "#{@pfexec} zfs destroy -r #{zp}") if dataset_root_exists == zp.to_s
        uiinfo.info(I18n.t('vagrant_zones.root_dataset_nil')) unless dataset_root_exists == zp.to_s
      end

      ## zonecfg function for bhyve
      def zonecfgbhyve(uiinfo, name, config, zcfg)
        bootconfigs = config.boot
        datasetpath = "#{bootconfigs['array']}/#{bootconfigs['dataset']}/#{name}"
        datasetroot = "#{datasetpath}/#{bootconfigs['volume_name']}"
        return unless config.brand == 'bhyve'

        execute(false, %(#{zcfg}"create ; set zonepath=/#{datasetpath}/path"))
        execute(false, %(#{zcfg}"set brand=#{config.brand}"))
        execute(false, %(#{zcfg}"set autoboot=#{config.autoboot}"))
        execute(false, %(#{zcfg}"set ip-type=exclusive"))
        execute(false, %(#{zcfg}"add attr; set name=acpi; set value=#{config.acpi}; set type=string; end;"))
        execute(false, %(#{zcfg}"add attr; set name=ram; set value=#{config.memory}; set type=string; end;"))
        execute(false, %(#{zcfg}"add attr; set name=bootrom; set value=#{firmware(config)}; set type=string; end;"))
        execute(false, %(#{zcfg}"add attr; set name=hostbridge; set value=#{config.hostbridge}; set type=string; end;"))
        execute(false, %(#{zcfg}"add attr; set name=diskif; set value=#{config.diskif}; set type=string; end;"))
        execute(false, %(#{zcfg}"add attr; set name=netif; set value=#{config.netif}; set type=string; end;"))
        execute(false, %(#{zcfg}"add attr; set name=bootdisk; set value=#{datasetroot.delete_prefix('/')}; set type=string; end;"))
        execute(false, %(#{zcfg}"add attr; set name=type; set value=#{config.os_type}; set type=string; end;"))
        execute(false, %(#{zcfg}"add device; set match=/dev/zvol/rdsk/#{datasetroot}; end;"))
        uiinfo.info(I18n.t('vagrant_zones.bhyve_zone_config_gen'))
      end

      ## zonecfg function for lx
      def zonecfglx(uiinfo, name, config, zcfg)
        bootconfigs = config.boot
        datasetpath = "#{bootconfigs['array']}/#{bootconfigs['dataset']}/#{name}"
        datasetroot = "#{datasetpath}/#{bootconfigs['volume_name']}"
        return unless config.brand == 'lx'

        uiinfo.info(I18n.t('vagrant_zones.lx_zone_config_gen'))
        machine.config.vm.networks.each do |adaptertype, opts|
          next unless adaptertype.to_s == 'public_network'

          @ip = opts[:ip].to_s
          cinfo = "#{opts[:ip]}/#{opts[:netmask]}"
          @network = NetAddr.parse_net(cinfo)
          @defrouter = opts[:gateway]
        end
        execute(false, %(#{zcfg}"create ; set zonepath=/#{datasetpath}/path"))
        execute(false, %(#{zcfg}"set brand=#{config.brand}"))
        execute(false, %(#{zcfg}"set autoboot=#{config.autoboot}"))
        execute(false, %(#{zcfg}"add attr; set name=kernel-version; set value=#{config.kernel}; set type=string; end;"))
        cmss = ' add capped-memory; set physical='
        execute(false, %(#{zcfg + cmss}"#{config.memory}; set swap=#{config.kernel}; set locked=#{config.memory}; end;"))
        execute(false, %(#{zcfg}"add dataset; set name=#{datasetroot}; end;"))
        execute(false, %(#{zcfg}"set max-lwps=2000"))
      end

      ## zonecfg function for KVM
      def zonecfgkvm(_uiinfo, name, config, _zcfg)
        return unless config.brand == 'kvm'

        bootconfigs = config.boot
        datasetpath = "#{bootconfigs['array']}/#{bootconfigs['dataset']}/#{name}"
        datasetroot = "#{datasetpath}/#{bootconfigs['volume_name']}"
        puts datasetroot
        ###### RESERVED ######
      end

      ## zonecfg function for Shared Disk Configurations
      def zonecfgshareddisks(uiinfo, _name, config, zcfg)
        return unless config.shared_disk_enabled

        uiinfo.info(I18n.t('vagrant_zones.setting_alt_shared_disk_configurations') + path.path)
        execute(false, %(#{zcfg}"add fs; set dir=/vagrant; set special=#{config.shared_dir}; set type=lofs; end;"))
      end

      ## zonecfg function for CPU Configurations
      def zonecfgcpu(_uiinfo, _name, config, zcfg)
        if config.cpu_configuration == 'simple' && (config.brand == 'bhyve' || config.brand == 'kvm')
          execute(false, %(#{zcfg}"add attr; set name=vcpus; set value=#{config.cpus}; set type=string; end;"))
        elsif config.cpu_configuration == 'complex' && (config.brand == 'bhyve' || config.brand == 'kvm')
          hash = config.complex_cpu_conf[0]
          cstring = %(sockets=#{hash['sockets']},cores=#{hash['cores']},threads=#{hash['threads']})
          execute(false, %(#{zcfg}'add attr; set name=vcpus; set value="#{cstring}"; set type=string; end;'))
        end
      end

      ## zonecfg function for CDROM Configurations
      def zonecfgcdrom(uiinfo, _name, config, zcfg)
        return if config.cdroms.nil?

        cdroms = config.cdroms
        cdrun = 0
        cdroms.each do |cdrom|
          cdname = 'cdrom'
          uiinfo.info(I18n.t('vagrant_zones.setting_cd_rom_configurations') + cdrom['path'])
          cdname += cdrun.to_s if cdrun.positive?
          cdrun += 1
          shrtstrng = 'set type=lofs; add options nodevices; add options ro; end;'
          execute(false, %(#{zcfg}"add attr; set name=#{cdname}; set value=#{cdrom['path']}; set type=string; end;"))
          execute(false, %(#{zcfg}"add fs; set dir=#{cdrom['path']}; set special=#{cdrom['path']}; #{shrtstrng}"))
        end
      end

      ## zonecfg function for PCI Configurations
      def zonecfgpci(_uiinfo, _name, _config, _zcfg)
        ##### RESERVED
      end

      ## zonecfg function for AdditionalDisks
      def zonecfgadditionaldisks(uiinfo, name, config, zcfg)
        return if config.additional_disks.nil?

        disks = config.additional_disks
        diskrun = 0
        disks.each do |disk|
          diskname = 'disk'
          dset = "#{disk['array']}/#{disk['dataset']}/#{name}/#{disk['volume_name']}"
          cinfo = "#{dset}, #{disk['size']}"
          uiinfo.info(I18n.t('vagrant_zones.setting_additional_disks_configurations') + cinfo)
          diskname += diskrun.to_s if diskrun.positive?
          diskrun += 1
          execute(false, %(#{zcfg}"add device; set match=/dev/zvol/rdsk/#{dset}; end;"))
          execute(false, %(#{zcfg}"add attr; set name=#{diskname}; set value=#{dset}; set type=string; end;"))
        end
      end

      ## zonecfg function for Console Access
      def zonecfgconsole(uiinfo, _name, config, zcfg)
        return if config.console.nil?

        return unless config.console != 'disabled'

        port = if %w[console].include?(config.console) && config.consoleport.nil?
                 'socket,/tmp/vm.com1'
               elsif %w[webvnc].include?(config.console) || %w[vnc].include?(config.console)
                 config.console = 'vnc'
                 'on'
               else
                 config.consoleport
               end
        port += ',wait' if config.console_onboot
        cp = config.consoleport
        ch = config.consolehost
        cb = config.console_onboot
        ct = config.console
        cinfo = "Console type: #{ct}, State: #{port}, Port: #{cp},  Host: #{ch}, Wait: #{cb}"
        uiinfo.info(I18n.t('vagrant_zones.setting_console_access') + cinfo)
        execute(false, %(#{zcfg}"add attr; set name=#{ct}; set value=#{port}; set type=string; end;"))
      end

      ## zonecfg function for Cloud-init
      def zonecfgcloudinit(uiinfo, _name, config, zcfg)
        return unless config.cloud_init_enabled

        cloudconfig = config.cloud_init_conf.to_s
        cloudconfig = 'on' if config.cloud_init_conf.nil? || config.cloud_init_conf
        uiinfo.info(I18n.t('vagrant_zones.setting_cloud_init_access') + cloudconfig.to_s)
        execute(false, %(#{zcfg}"add attr; set name=cloud-init; set value=#{cloudconfig}; set type=string; end;"))

        ccid = config.cloud_init_dnsdomain
        uiinfo.info(I18n.t('vagrant_zones.setting_cloud_dnsdomain') + ccid.to_s) unless ccid.nil?
        execute(false, %(#{zcfg}"add attr; set name=dns-domain; set value=#{ccid}; set type=string; end;")) unless ccid.nil?

        ccip = config.cloud_init_password
        uiinfo.info(I18n.t('vagrant_zones.setting_cloud_password') + ccip.to_s) unless ccip.nil?
        execute(false, %(#{zcfg}"add attr; set name=password; set value=#{ccip}; set type=string; end;")) unless ccip.nil?

        cclir = config.cloud_init_resolvers
        uiinfo.info(I18n.t('vagrant_zones.setting_cloud_resolvers') + cclir.to_s) unless cclir.nil?
        execute(false, %(#{zcfg}"add attr; set name=resolvers; set value=#{cclir}; set type=string; end;")) unless cclir.nil?

        ccisk = config.cloud_init_sshkey
        uiinfo.info(I18n.t('vagrant_zones.setting_cloud_ssh_key') + ccisk.to_s) unless ccisk.nil?
        execute(false, %(#{zcfg}"add attr; set name=sshkey; set value=#{ccisk}; set type=string; end;")) unless ccisk.nil?
      end

      # This helps us set the zone configurations for the zone
      def zonecfg(uiinfo)
        name = @machine.name
        config = @machine.provider_config
        zcfg = "#{@pfexec} zonecfg -z #{name} "
        ## Seperate commands out to individual functions like Network, Dataset, and Emergency Console
        ## Function to create LX zonecfg
        zonecfglx(uiinfo, name, config, zcfg)
        ## Function to create bhyve zonecfg
        zonecfgbhyve(uiinfo, name, config, zcfg)
        ## Function to create kvm zonecfg
        zonecfgkvm(uiinfo, name, config, zcfg)
        ## Shared Disk Configurations
        zonecfgshareddisks(uiinfo, name, config, zcfg)
        ## CPU Configurations
        zonecfgcpu(uiinfo, name, config, zcfg)
        ## CDROM Configurations
        zonecfgcdrom(uiinfo, name, config, zcfg)
        ### Passthrough PCI Devices
        zonecfgpci(uiinfo, name, config, zcfg)
        ## Additional Disk Configurations
        zonecfgadditionaldisks(uiinfo, name, config, zcfg)
        ## Console access configuration
        zonecfgconsole(uiinfo, name, config, zcfg)
        ## Cloud-init settings
        zonecfgcloudinit(uiinfo, name, config, zcfg)
        ## Nic Configurations
        uiinfo.info(I18n.t('vagrant_zones.networking_int_add'))
        network(@machine, uiinfo, 'config')
        uiinfo.info(I18n.t('vagrant_zones.exporting_bhyve_zone_config_gen'))
      end

      # This ensures the zone is safe to boot
      def check_zone_support(machine, uiinfo)
        uiinfo.info(I18n.t('vagrant_zones.preflight_checks'))
        config = machine.provider_config
        ## Detect if Virtualbox is Running
        ## LX, KVM, and Bhyve cannot run conncurently with Virtualbox:
        ### https://illumos.topicbox-beta.com/groups/omnios-discuss/Tce3bbd08cace5349-M5fc864e9c1a7585b94a7c080
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
          ## Check for bhhwcompat
          result = execute(true, "#{@pfexec} test -f /usr/sbin/bhhwcompat ; echo $?")
          if result == 1
            bhhwcompaturl = 'https://downloads.omnios.org/misc/bhyve/bhhwcompat'
            execute(true, "#{@pfexec} curl -o /usr/sbin/bhhwcompat #{bhhwcompaturl} && #{@pfexec} chmod +x /usr/sbin/bhhwcompat")
            result = execute(true, "#{@pfexec} test -f /usr/sbin/bhhwcompat ; echo $?")
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
        uiinfo.info(I18n.t('vagrant_zones.network_setup')) if config.brand == 'bhyve' && config.cloud_init_enabled == 'off'
        network(@machine, uiinfo, 'setup') if config.brand == 'bhyve' && config.cloud_init_enabled == 'off'
      end

      # This helps up wait for the boot of the vm by using zlogin
      def waitforboot(machine, uiinfo)
        uiinfo.info(I18n.t('vagrant_zones.wait_for_boot'))
        name = @machine.name
        config = machine.provider_config
        responses = []
        case config.brand
        when 'bhyve'
          return if config.cloud_init_enabled

          PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read, zlogin_write, pid|
            bcheck = 'Last login: ' if config.bcheck_string.nil?
            zlogin_write.printf("\n")
            if zlogin_read.expect(/#{bcheck}/)
              uiinfo.info(I18n.t('vagrant_zones.booted_check_terminal_access') + "'#{config.bcheck_string}'")
              Timeout.timeout(config.setup_wait) do
                loop do
                  zlogin_read.expect(/\n/) { |line| responses.push line }
                  break if responses[-1].to_s.match(/:~#/)

                  ## Code to try to login with username and password
                  almatch = config.almatchstring
                  almatch = 'login: ' if config.almatchstring.nil?
                  uiinfo.info(I18n.t('vagrant_zones.booted_check_terminal_access_auto_login')) if responses[-1].to_s.match(/#{almatch}/)
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
            command = "#{@pfexec} curl #{id_rsa} -O id_rsa"
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
        ret = execute(true, "#{@pfexec} zlogin #{name} id -u #{user}")
        return true if ret.zero?

        false
        # return false
      end

      # This gives the user a terminal console
      def zlogincommand(machine, cmd)
        name = machine.name
        execute(false, "#{@pfexec} zlogin #{name} #{cmd}")
      end

      # This gives us a console to the VM
      def zlogin(machine, cmd)
        name = machine.name
        config = machine.provider_config
        responses = []
        PTY.spawn("pfexec zlogin -C #{name}") do |zlogin_read, zlogin_write, pid|
          zlogin_read.expect(/\n/) { zlogin_write.printf("#{cmd} \; echo \"Error Code: $?\"\n") }
          Timeout.timeout(config.setup_wait) do
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
          command = "#{@pfexec} curl #{id_rsa} -O #{file}"
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

      # This filters the firmware
      def firmware(config)
        ft = case config.firmware_type
             when /compatability/
               'BHYVE_RELEASE_CSM'
             when /UEFI/
               'BHYVE_RELEASE'
             when /BIOS/
               'BHYVE_CSM'
             when /BHYVE_DEBUG/
               'UEFI_DEBUG'
             when /BHYVE_RELEASE_CSM/
               'BIOS_DEBUG'
             end
        ft.to_s
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

      ## List ZFS Snapshots
      def zfssnaplist(datasets, _config, opts, uiinfo, _name)
        uiinfo.info(I18n.t('vagrant_zones.zfs_snapshot_list'))
        datasets.each_with_index do |disk, index|
          puts "\n Disk Number: #{index}\n Disk Path: #{disk}"
          zfs_snapshots = execute(false, "#{@pfexec} zfs list -t snapshot | grep #{disk} || true")
          break if zfs_snapshots.nil?

          unless opts[:dataset].nil?
            selectdataset = opts[:dataset]
            next unless selectdataset.to_i == index

          end
          zfssnapshots = zfs_snapshots.split(/\n/)
          zfssnapshots = zfssnapshots.reverse
          zfssnapshots << "Snapshot\t\t\t\tUsed\tAvailable\tRefer\tPath"
          pml, rml, aml, uml, sml = 0
          zfssnapshots.reverse.each do |snapshot|
            ar = snapshot.gsub(/\s+/m, ' ').strip.split
            sml = ar[0].length.to_i if ar[0].length.to_i > sml.to_i
            uml = ar[1].length.to_i if ar[1].length.to_i > uml.to_i
            aml = ar[2].length.to_i if ar[2].length.to_i > aml.to_i
            rml = ar[3].length.to_i if ar[3].length.to_i > rml.to_i
            pml = ar[4].length.to_i if ar[4].length.to_i > pml.to_i
          end
          zfssnapshots.reverse.each_with_index do |snapshot, si|
            ar = snapshot.gsub(/\s+/m, ' ').strip.split
            strg1 = "%<sym>5s %<s>-#{sml}s %<u>-#{uml}s %<a>-#{aml}s %<r>-#{rml}s %<p>-#{pml}s"
            strg2 = "%<si>5s %<s>-#{sml}s %<u>-#{uml}s %<a>-#{aml}s %<r>-#{rml}s %<p>-#{pml}s"
            if si.zero?
              puts format strg1.to_s, sym: '#', s: ar[0], u: ar[1], a: ar[2], r: ar[3], p: ar[4]
            else
              puts format strg2.to_s, si: si - 2, s: ar[0], u: ar[1], a: ar[2], r: ar[3], p: ar[4]
            end
          end
        end
      end

      ## Create ZFS Snapshots
      def zfssnapcreate(datasets, _config, opts, uiinfo, _name)
        if opts[:dataset] == 'all'
          datasets.each do |disk|
            uiinfo.info(I18n.t('vagrant_zones.zfs_snapshot_create') + "#{disk}@#{opts[:snapshot_name]}")
            execute(false, "#{@pfexec} zfs snapshot #{disk}@#{opts[:snapshot_name]}")
          end
        else
          uiinfo.info(I18n.t('vagrant_zones.zfs_snapshot_create'))
          ## Specify the Dataset by path
          execute(false, "#{@pfexec} zfs snapshot #{opts[:dataset]}@#{opts[:snapshot_name]}") if datasets.include?(opts[:dataset])
          ## Specify the dataset by number
          datasets.each_with_index do |disk, index|
            execute(false, "#{@pfexec} zfs snapshot #{disk}@#{opts[:snapshot_name]}") if opts[:dataset].to_i == index.to_i
          end
        end
      end

      ## Destroy ZFS Snapshots
      def zfssnapdestroy(datasets, _config, opts, uiinfo, _name)
        if opts[:dataset].to_s == 'all'
          datasets.each do |disk|
            uiinfo.info(I18n.t('vagrant_zones.zfs_snapshot_destroy'))
            output = execute(false, "#{@pfexec} zfs list -t snapshot -o name | grep #{disk}")
            ## Never delete the source when doing all
            output = output.split(/\n/).drop(1)
            output.reverse.each do |snaps|
              execute(false, "#{@pfexec} zfs destroy #{snaps}")
              uiinfo.info(I18n.t('vagrant_zones.zfs_snapshot_destroy'))
            end
          end
        else
          uiinfo.info(I18n.t('vagrant_zones.zfs_snapshot_destroy'))
          ## Specify the dataset by number
          datasets.each_with_index do |disk, dindex|
            next unless dindex.to_i == opts[:dataset].to_i

            output = execute(false, "#{@pfexec} zfs list -t snapshot -o name | grep #{disk}")
            output = output.split(/\n/).drop(1)
            output.each_with_index do |snaps, spindex|
              if opts[:snapshot_name].to_i == spindex && opts[:snapshot_name].to_s != 'all'
                puts "\t#{spindex}\t#{snaps}\t"
                execute(false, "#{@pfexec} zfs destroy #{snaps}")
                uiinfo.info(I18n.t('vagrant_zones.zfs_snapshot_destroy'))
              end
              if opts[:snapshot_name].to_s == 'all'
                puts "\t#{spindex}\t#{snaps}\t"
                execute(false, "#{@pfexec} zfs destroy #{snaps}")
              end
            end
          end
          ## Specify the Dataset by path
          cmd = "#{@pfexec} zfs destroy #{opts[:dataset]}@#{opts[:snapshot_name]}"
          execute(false, cmd) if datasets.include?("#{opts[:dataset]}@#{opts[:snapshot_name]}")
        end
      end

      ## This will list Cron Jobs for Snapshots to take place
      def zfssnapcronlist(_datasets, _config, opts, _uiinfo, cronjobs)
        if opts[:list] == 'all'
          puts cronjobs[:hourly] unless cronjobs[:hourly].nil?
          puts cronjobs[:daily] unless cronjobs[:daily].nil?
          puts cronjobs[:weekly] unless cronjobs[:weekly].nil?
          puts cronjobs[:monthly] unless cronjobs[:monthly].nil?
        else
          puts cronjobs[:hourly] if opts[:list] == 'hourly'
          puts cronjobs[:daily] if opts[:list] == 'daily'
          puts cronjobs[:weekly] if opts[:list] == 'weekly'
          puts cronjobs[:monthly] if opts[:list] == 'monthly'
        end
      end

      ## This will delete Cron Jobs for Snapshots to take place
      def zfssnapcrondelete(_datasets, _config, opts, _uiinfo, cronjobs)
        removecron = ''
        sc = "#{@pfexec} crontab"
        rmcr = "#{sc} -l | grep -v "
        if opts[:delete] == 'all'
          removecron = "#{rmcr}'#{cronjobs[:hourly].gsub(/\*/, '\*')}' | #{sc}" unless cronjobs[:hourly].nil?
          puts removecron unless cronjobs[:hourly].nil?
          execute(false, removecron) unless cronjobs[:hourly].nil?
          removecron = "#{rmcr}'#{cronjobs[:daily].gsub(/\*/, '\*')}' | #{sc} crontab" unless cronjobs[:daily].nil?
          puts removecron unless cronjobs[:daily].nil?
          execute(false, removecron) unless cronjobs[:daily].nil?
          removecron = "#{rmcr}'#{cronjobs[:weekly].gsub(/\*/, '\*')}' | #{sc}" unless cronjobs[:weekly].nil?
          puts removecron unless cronjobs[:weekly].nil?
          execute(false, removecron) unless cronjobs[:weekly].nil?
          removecron = "#{rmcr}'#{cronjobs[:monthly].gsub(/\*/, '\*')}' | #{sc}" unless cronjobs[:monthly].nil?
          puts removecron unless cronjobs[:monthly].nil?
          execute(false, removecron) unless cronjobs[:monthly].nil?
        else
          removecron = "#{rmcr}'#{cronjobs[:hourly].gsub(/\*/, '\*')}' | #{sc}" if cronjobs[:hourly] && opts[:delete] == 'hourly'
          removecron = "#{rmcr}'#{cronjobs[:daily].gsub(/\*/, '\*')}' | #{sc}" if cronjobs[:daily] && opts[:delete] == 'daily'
          removecron = "#{rmcr}'#{cronjobs[:weekly].gsub(/\*/, '\*')}' | #{sc}" if cronjobs[:weekly] && opts[:delete] == 'weekly'
          removecron = "#{rmcr}'#{cronjobs[:monthly].gsub(/\*/, '\*')}' | #{sc}" if cronjobs[:monthly] && opts[:delete] == 'monthly'
          puts removecron
          execute(false, removecron)
        end
      end

      ## This will set Cron Jobs for Snapshots to take place
      def zfssnapcronset(disk, config, opts, name, cronjobs)
        spshtr = config.snapshot_script.to_s
        hourlytrn = 24
        dailytrn = 8
        weeklytrn = 5
        monthlytrn = 1
        shrtcr = "( #{@pfexec} crontab -l; echo "
        sfr = opts[:set_frequency_rtn]
        hourlycron = "0 1-23 * * * #{spshtr} -p hourly -r -n #{hourlytrn} #{disk} # #{name}"
        dailycron = "0 0 * * 0-5 #{spshtr} -p daily -r -n #{dailytrn} #{disk} # #{name}"
        weeklycron = "0 0 * * 6 #{spshtr} -p weekly -r -n #{weeklytrn} #{disk} # #{name}"
        monthlycron = "0 0 1 * * #{spshtr} -p monthly -r -n #{monthlytrn} #{disk} # #{name}"
        if opts[:set_frequency] && opts[:set_frequency] == 'all'
          hourlycron = "0  1-23  *  *  *  #{spshtr} -p hourly -r -n #{sfr} #{disk} # #{name}" unless sfr.nil? || sfr == 'defaults'
          dailycron = "0  0  *  *  0-5  #{spshtr} -p daily -r -n #{sfr} #{disk} # #{name}" unless sfr.nil? || sfr == 'defaults'
          weeklycron = "0  0  *  *  6   #{spshtr} -p weekly -r -n #{sfr} #{disk} # #{name}" unless sfr.nil? || sfr == 'defaults'
          monthlycron = "0  0  1  *  *   #{spshtr} -p monthly -r -n #{sfr} #{disk} # #{name}" unless sfr.nil? || sfr == 'defaults'
          setcron = "#{shrtcr}'#{hourlycron}' ) | #{@pfexec} crontab" if cronjobs[:hourly].nil?
          puts setcron if cronjobs[:hourly].nil?
          execute(false, setcron) if cronjobs[:hourly].nil?
          setcron = "#{shrtcr}'#{dailycron}' ) | #{@pfexec} crontab" if cronjobs[:daily].nil?
          puts setcron if cronjobs[:daily].nil?
          execute(false, setcron) if cronjobs[:daily].nil?
          setcron = "#{shrtcr}'#{weeklycron}' ) | #{@pfexec} crontab" if cronjobs[:weekly].nil?
          puts setcron if cronjobs[:weekly].nil?
          execute(false, setcron) if cronjobs[:weekly].nil?
          setcron = "#{shrtcr}'#{monthlycron}' ) | #{@pfexec} crontab" if cronjobs[:monthly].nil?
          puts setcron if cronjobs[:monthly].nil?
          execute(false, setcron) if cronjobs[:monthly].nil?
        elsif opts[:set_frequency]
          hourlycron = "0  1-23  *  *  *  #{spshtr} -p hourly -r -n #{sfr} #{disk} # #{name}" unless sfr.nil? || sfr == 'defaults'
          dailycron = "0  0  *  *  0-5  #{spshtr} -p daily -r -n #{sfr} #{disk} # #{name}" unless sfr.nil? || sfr == 'defaults'
          weeklycron = "0  0  *  *  6   #{spshtr} -p weekly -r -n #{sfr} #{disk} # #{name}" unless sfr.nil? || sfr == 'defaults'
          monthlycron = "0  0  1  *  *   #{spshtr} -p monthly -r -n #{sfr} #{disk} # #{name}" unless sfr.nil? || sfr == 'defaults'
          setcron = "#{shrtcr}'#{hourlycron}' ) | #{@pfexec} crontab" if cronjobs[:hourly].nil? && opts[:set_frequency] == 'hourly'
          setcron = "#{shrtcr}'#{dailycron}' ) | #{@pfexec} crontab" if cronjobs[:daily].nil? && opts[:set_frequency] == 'daily'
          setcron = "#{shrtcr}'#{weeklycron}' ) | #{@pfexec} crontab" if cronjobs[:weekly].nil? && opts[:set_frequency] == 'weekly'
          setcron = "#{shrtcr}'#{monthlycron}' ) | #{@pfexec} crontab" if cronjobs[:monthly].nil? && opts[:set_frequency] == 'monthly'
          puts setcron
          execute(false, setcron)
        end
      end

      ## Configure ZFS Snapshots Crons
      def zfssnapcron(datasets, config, opts, uiinfo, name)
        crons = execute(false, "#{@pfexec} crontab -l").split("\n")

        rtnregex = '-p (weekly|monthly|daily|hourly)'
        opts[:dataset] = 'all' if opts[:dataset].nil?

        ## Insert Verification Check here that Dataset is in Zoneconfiguration
        datasets.each do |disk|
          uiinfo.info(I18n.t('vagrant_zones.zfs_snapshot_cron') + disk.to_s)
          cronjobs = {}
          crons.each do |tasks|
            next if tasks.empty?

            case tasks[/#{rtnregex}/, 1]
            when 'hourly'
              hourly = tasks if tasks[/#{name}/] && tasks[/#{disk}/]
              cronjobs.merge!(hourly: hourly)
            when 'daily'
              daily = tasks if tasks[/#{name}/] && tasks[/#{disk}/]
              cronjobs.merge!(daily: daily)
            when 'weekly'
              weekly = tasks if tasks[/#{name}/] && tasks[/#{disk}/]
              cronjobs.merge!(weekly: weekly)
            when 'monthly'
              monthly = tasks if tasks[/#{name}/] && tasks[/#{disk}/]
              cronjobs.merge!(monthly: monthly)
            end
          end
          zfssnapcronlist(disk, config, opts, name, cronjobs)
          zfssnapcrondelete(disk, config, opts, name, cronjobs)
          zfssnapcronset(disk, config, opts, name, cronjobs)
        end
      end

      # This helps us create ZFS Snapshots
      def zfs(machine, uiinfo, job, opts)
        name = machine.name
        ## get disks configurations
        config = machine.provider_config
        bootconfigs = config.boot
        datasetroot = "#{bootconfigs['array']}/#{bootconfigs['dataset']}/#{name}/#{bootconfigs['volume_name']}"
        datasets = []
        datasets << datasetroot.to_s
        config.additional_disks&.each do |disk|
          ## Check if Parent Dataset exists
          additionaldataset = "#{disk['array']}/#{disk['dataset']}/#{name}/#{disk['volume_name']}"
          datasets << additionaldataset.to_s
        end

        case job
        when 'list'
          zfssnaplist(datasets, config, opts, uiinfo, name)
        when 'create'
          zfssnapcreate(datasets, config, opts, uiinfo, name)
        when 'destroy'
          zfssnapdestroy(datasets, config, opts, uiinfo, name)
        when 'cron'
          zfssnapcron(datasets, config, opts, uiinfo, name)
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
            Timeout.timeout(config.clean_shutdown_time) do
              execute(false, "#{@pfexec} zoneadm -z #{name} halt")
            end
          rescue Timeout::Error
            raise "==> #{name}: VM failed to halt in alloted time #{config.setup_wait} after waiting for #{config.clean_shutdown_time}"
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
        id.info(I18n.t('vagrant_zones.networking_int_remove'))
        network(machine, id, state)
      end
    end
  end
end
