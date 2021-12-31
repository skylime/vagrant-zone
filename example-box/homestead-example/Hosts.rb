# coding: utf-8
class Hosts
    def Hosts.configure(config, settings)
  
      # Configure scripts path variable
      scriptsPath = File.dirname(__FILE__) + '/scripts'
  
      config.vm.provider = 'zone'

      # Main loop to configure VM
      settings['hosts'].each_with_index do |host, index|
        autostart = host.has_key?('autostart') && host['autostart']
        config.vm.define "#{host['partition_id']}--#{host['name']}", autostart: autostart do |server|
          server.vm.box = host['box']       
          server.vm.boot_timeout = 900
  
          # Setup SSH and Prevent TTY errors
          server.ssh.shell = "bash -c 'BASH_ENV=/etc/profile exec bash'"
          server.ssh.forward_agent = true
          server.ssh.forward_x11 = true
          server.ssh.username = host['vagrant_user']
          server.ssh.private_key_path = host['vagrant_user_private_key_path']
          server.ssh.password = host['vagrant_user_pass']
          server.ssh.insert_key = host['vagrant_insert_key']
          server.vm.provider = 'zone'
          if  s.has_key?('boxes')
            boxes = settings['boxes']
            if boxes.has_key?(server.vm.box)
              server.vm.box_url = settings['boxes'][server.vm.box]
            end
          end

          ## Note Do not place two IPs in the same subnet on both nics at the same time, They must be different subnets or on a different network segment(ie VLAN, physical seperation for Linux VMs)
          if host.has_key?('networks')
            host['networks'].each_with_index do |network, netindex|
                server.vm.network "public_network", ip: network['address'], dhcp: network['dhcp4'], dhcp6: network['dhcp6'], bridge: network['bridge'], auto_config: false, :netmask => network['netmask'], :mac => network['mac'], gateway: network['gateway'], nictype: network['type'], nic_number: netindex, managed: network['is_control'], vlan: network['vlan'] if network['type'] == 'external'
                server.vm.network "private_network", ip: network['address'], dhcp: network['dhcp4'], dhcp6: network['dhcp6'], bridge: network['bridge'], auto_config: false, :netmask => network['netmask'], :mac => network['mac'], gateway: network['gateway'], nictype: network['type'], nic_number: netindex, managed: network['is_control'], vlan: network['vlan'] if network['type'] == 'hostonly'
            end
          end

          # Nameservers
          if host.has_key?('dns')
            dservers = []
            host['dns'].each do |ns|
              dservers.append(ns['nameserver'])
            end
          end

          # Vagrant-Zone machine configuration
          server.vm.provider :zone do |vm|
                  vm.brand                                = host['brand']
                  vm.vagrant_cloud_creator                = host['cloud_creator']
                  vm.boxshortname                         = host['boxshortname']
                  vm.autoboot                             = host['autostart']
                  vm.partition_id                         = host['partition_id']
                  vm.setup_wait                           = host['setup_wait']
                  vm.memory                               = host['memory']
                  vm.cpus                                 = host['simple_vcpu_conf']
                  vm.cpu_configuration                    = host['cpu_configuration']
                  vm.complex_cpu_conf                     = host['complex_cpu_conf']
                  vm.console_onboot                       = host['console_onboot']
                  vm.consoleport                          = host['consoleport']
                  vm.consolehost                          = host['consolehost']
                  vm.console                              = host['console']
                  vm.dns                                  = host['dns']
                  vm.override                             = host['override']
                  vm.firmware_type                        = host['firmware_type']
                  vm.acpi                                 = host['acpi']
                  vm.shared_disk_enabled                  = host['shared_lofs_disk_enabled']
                  vm.shared_dir                           = host['shared_lofs_dir']
                  vm.os_type                              = host['os_type']
                  vm.diskif                               = host['diskif']
                  vm.netif                                = host['netif']
                  vm.hostbridge                           = host['hostbridge']
                  vm.clean_shutdown_time                  = host['clean_shutdown_time']
                  vm.vmtype                               = host['vmtype']
                  vm.vagrant_user_private_key_path        = host['vagrant_user_private_key_path']
                  vm.vagrant_user                         = host['vagrant_user']
                  vm.vagrant_user_pass                    = host['vagrant_user_pass']
                  vm.hostname                             = host['name']
                  vm.name                                 = "#{host['partition_id']}--#{host['name']}"
                  vm.lcheck                               = host['lcheck_string']
                  vm.alcheck                              = host['alcheck_string']
                  vm.debug_boot                           = host['debug_boot']
                  vm.debug                                = host['debug']
                  vm.cdroms                               = host['cdroms']
                  vm.additional_disks                     = host['additional_disks']
                  vm.boot                                 = host['boot']
                  vm.snapshot_script                      = host['snapshot_script']
                  vm.cloud_init_enabled                   = host['cloud_init_enabled']
                  vm.cloud_init_dnsdomain                 = host['cloud_init_dnsdomain']
                  vm.cloud_init_password                  = host['vagrant_user_pass']
                  vm.cloud_init_resolvers                 = dservers.join(',')
                  vm.cloud_init_sshkey                    = host['vagrant_user_private_key_path']
                  vm.cloud_init_conf                      = host['cloud_init_conf']
                  vm.safe_restart                         = host['safe_restart']
                  vm.safe_shutdown                        = host['safe_shutdown']
                  vm.setup_method                         = host['setup_method']            
          end

        end
      end
    end
  end

  