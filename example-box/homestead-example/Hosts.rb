class Hosts
    def Hosts.configure(config, settings)
  
      # Configure scripts path variable
      scriptsPath = File.dirname(__FILE__) + '/scripts'
  
  #    config.vm.provider = 'zone'
  
      # Main loop to configure VM
      settings['hosts'].each_with_index do |host, index|
        autostart = host.has_key?('autostart') && host['autostart']
        config.vm.define "#{host['parition_id']}-#{host['name']}", autostart: autostart do |server|
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
          if settings.has_key?('boxes')
            boxes = settings['boxes']
            if boxes.has_key?(server.vm.box)
              server.vm.box_url = settings['boxes'][server.vm.box]
            end
          end
  
          server.vm.network "public_network", ip: host['ip1'], bridge: host['bridge1'], auto_config: false, :netmask => host['netmask1'], :mac => host['mac1'], gateway: host['gateway1'], type: host['type1'], nic_number: "0", managed: host['managed1']#, vlan: host[''vlan2']
          server.vm.network "public_network", ip: host['ip2'], bridge: host['bridge2'], auto_config: false, :netmask => host['netmask2'], :mac => host['mac2'], gateway: host['gateway2'], type: host['type2'], nic_number: "1", managed: host['managed2']#, vlan: host[''vlan2']
          # Vagrant-Zone machine configuration
          server.vm.provider :zone do |vm|
                  vm.brand                                = host['brand']
                  vm.autoboot                             = host['autostart']
                  vm.parition_id                          = host['parition_id']
                  vm.zonepath                             = "#{host['zonepath']}/#{host['parition_id']}-#{host['name']}"
                  vm.zonepathsize                         = host['rootdisksize']
  #               vm.disk1                                = "rpool/#{vm.parition_id}-ubuntu2/disk1"
  #               vm.disk1_size                           = '50G'
                  vm.setup_wait                           = host['setup_wait']
                  vm.memory                               = host['memory']
                  vm.cpus                                 = host['cpus']
                  vm.vnc                                  = host['vnc']
                  vm.console                              = host['console']
                  vm.firmware_type                        = host['firmware_type']
                  vm.acpi                                 = host['acpi']
                  vm.dhcp                                 = host['dhcp']
  #               vm.shared_disk_enabled                  = host['shared_lofs_disk_enabled']
  #               vm.shared_dir                           = host['shared_lofs_dir']
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
                  vm.name                                 = "#{host['parition_id']}-#{host['name']}"
  #               vm.customize                            ['modifyvm', :id, '--ostype', 'RedHat_64']
  #               vm.customize                            ["modifyvm", :id, "--vrde", "on"]
  #               vm.customize                            ["modifyvm", :id, "--vrdeport", "3941"]
  #               vm.customize                            ["modifyvm", :id, "--vrdeaddress", "0.0.0.0"]
  #          if host.has_key?('provider')
  #            host['provider'].each do |param|
  #              vm.customize                             ['modifyvm', :id, "--#{param['directive']}", param['value']]
  #            end
  #          end
          end
  
          # Register shared folders
          if host.has_key?('folders')
            host['folders'].each do |folder|
              mount_opts = folder['type'] == 'rsync' ? ['actimeo=1'] : []
              server.vm.synced_folder folder['map'], folder ['to'],
                type: folder['type'],
                owner: folder['owner'] ||= host['vagrant_user'],
                group: folder['group'] ||= host['vagrant_user'],
                mount_options: mount_opts
              end
          end
  
          # Add Branch Files to Vagrant Share on VM
            if host.has_key?('branch') && host['shell_provision']
                server.vm.provision 'shell' do |s|
                  s.path = scriptsPath + '/add-branch.sh'
                  s.args = [host['branch'], host['git_url'] ]
                end
            end
  
          # Run the Shell Provisioner
          if host.has_key?('provision')  && host['shell_provision']
             host['shell_provision'].each do |file|
                 server.vm.provision 'shell', path: file
             end
          end
  
          # Run the Ansible Provisioner
          if host.has_key?('ansible_provision_scripts') && host['ansible_provision']
            host['ansible_provision_scripts'].each do |script|
              server.vm.provision :ansible do |ansible|
                ansible.playbook =  script
                ansible.compatibility_mode = "2.0"
                #ansible.install_mode = "pip"
                ansible.extra_vars = {ip:host['ip'], ansible_python_interpreter:"/usr/bin/python3"}
              end
            end
          end
        end
      end
    end
  end
  