Vagrant.configure("2") do |config|
  config.vm.box        = 'centos68.zss'

  config.vm.provider :zone do |vm|
    vm.brand      = 'lx'
    vm.kernel     = '2.6.32'
    vm.zonepath   = '/rpool/centos'
    vm.memory     = '512M'
  end
end
