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
