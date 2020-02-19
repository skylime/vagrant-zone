Vagrant.configure("2") do |config|
  config.vm.box        = 'debian.zss'

  config.ssh.username = "root"

  config.vm.provider :zone do |vm|
    vm.brand      = 'lx'
    vm.kernel     = '4.10'
    vm.zonepath   = '/rpool/debian'
    vm.memory     = '512M'
  end
end
