Vagrant.configure("2") do |config|
  config.vm.define :debian do |debian|
    debian.vm.box        = 'debian.zss'
    debian.vm.network "public_network",
      ip: "192.168.122.28", bridge: "e1000g0", auto_config: false, :netmask => "255.255.255.0", gateway: "192.168.122.1"

    debian.vm.provision "shell",
      inline: "id > /home/vagrant/id"

    debian.vm.provision "ansible_local" do |ansible|
      ansible.playbook = "playbook.yml"
      ansible.install  = true
    end

    debian.vm.provider :zone do |vm|
      vm.brand      = 'lx'
      vm.kernel     = '4.10'
      vm.zonepath   = '/rpool/debian'
      vm.memory     = '512M'
    end
  end

  config.vm.define :centos do |centos|
    centos.vm.box        = '3dbbdcca-2eab-11e8-b925-23bf77789921'
    centos.vm.network "public_network",
      ip: "192.168.122.29", bridge: "e1000g0", auto_config: false, :netmask => "255.255.255.0", gateway: "192.168.122.1"
  
    centos.vm.provision "shell",
      inline: "id > /home/vagrant/id"
  
    centos.vm.provision "ansible_local" do |ansible|
      ansible.playbook = "playbook.yml"
      ansible.install  = true
    end
  
    centos.vm.provider :zone do |vm|
      vm.brand      = 'lx'
      vm.kernel     = '3.10.0'
      vm.zonepath   = '/rpool/centos'
      vm.memory     = '512M'
    end
  end
  
  config.vm.define :example do |example|
    example.vm.box        = 'example'
    example.vm.network "public_network",
      ip: "192.168.122.30", bridge: "e1000g0", auto_config: false, :netmask => "255.255.255.0", gateway: "192.168.122.1"

    example.vm.provider :zone do |vm|
      vm.brand      = 'lx'
      vm.zonepath   = '/rpool/example'
      vm.memory     = '512M'
    end
  end
end



Vagrant.configure("2") do |config|
        config.vm.define :ubuntu2 do |settings|
                settings.vm.box = 'Makr44/ubuntu2104-server'

                settings.vm.network "public_network", ip: "192.168.2.238", bridge: "igb0", auto_config: false, :netmask => "255.255.255.0", gateway: "192.168.2.1", type: "external" # vlan: "11"
                # ubuntu.vm.network "public_network", ip: "192.168.2.239", bridge: "igb0", auto_config: false, :netmask => "255.255.255.0", gateway: "192.168.2.1", # vlan: "11"
                # ubuntu.vm.network "public_network", ip: "192.168.2.239", bridge: "igb0", auto_config: false, :netmask => "255.255.255.0", gateway: "192.168.2.1", # vlan: "11"

                settings.ssh.username = 'vagrant'
#               settings.ssh.password = 'vagrant'
                settings.ssh.insert_key = false

                settings.vm.provider :zone do |vm|
                        vm.brand                                = 'bhyve'
                        vm.autoboot                             = true
                        vm.parition_id                          = '0000'
                        vm.array                                = 'rpool'
                        vm.zonepath                             = "/#{vm.array}/#{vm.parition_id}-ubuntu2"
                        vm.zonepathsize                         = '40G'
#                       vm.disk1                                = "#{vm.array}/#{vm.parition_id}-ubuntu2/disk1"
#                       vm.disk1_size                           = '50G'
                        vm.setup_wait                           = 30
                        vm.memory                               = '512M'
                        vm.cpus                                 = 4
                        vm.vnc                                  = false
                        vm.console                              = false
                        vm.firmware  			                      = 'compatability'
                        vm.acpi                                 = 'on'
                        vm.dhcp                                 = false
                        vm.shared_disk_enabled                  = true
                        vm.shared_dir                           = './share'
                        vm.os_type                              = 'generic'
                        vm.diskif                          			= 'virtio-blk'
                        vm.netif   		                        	= 'virtio-net-viona'
                        vm.hostbridge                       		= 'i440fx'
                        vm.clean_shutdown_time                  = '200'
                        vm.vmtype                          			= 'production'
                        vm.vagrant_user_private_key_path        = './id_rsa'
                        vm.vagrant_user                         = settings.ssh.username
                        vm.vagrant_user_pass                    = settings.ssh.password
                end
        end
end
