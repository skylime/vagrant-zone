# frozen_string_literal: true

require 'vagrant'
## Do not Modify this File! Modify the Hosts.yml, Hosts.rb, or Vagrantfile!
module VagrantPlugins
  module ProviderZone
    # This is used define the variables for the project
    class Config < Vagrant.plugin('2', :config)
      # rubocop:disable Layout/LineLength
      attr_accessor :brand, :autoboot, :kernel, :zonepath, :zonepathsize, :diskif, :netif, :cdroms, :disk1path, :disk1size, :cpus, :cpu_configuration, :complex_cpu_conf, :memory, :vagrant_user, :vagrant_user_private_key_path, :setup_wait, :clean_shutdown_time, :dhcp, :vagrant_user_pass, :firmware_type, :firmware, :vm_type, :partition_id, :shared_disk_enabled, :shared_dir, :acpi, :os_type, :console, :consoleport, :console_onboot, :hostbridge, :sshport, :rdpport, :override, :additional_disks, :cloud_init_enabled, :dns, :box, :vagrant_cloud_creator

      # rubocop:enable Layout/LineLength

      def initialize
        # pkgsrc, lx, bhyve, kvm, illumos
        @brand = 'bhyve'
        @additional_disks = nil
        @autoboot = true
        @kernel = UNSET_VALUE
        @zonepath = '/rpool/myvm'
        @zonepathsize = '20G'
        @cdroms = nil
        @shared_dir = nil
        @os_type = 'generic'
        @shared_disk_enabled = true
        @consoleport = nil
        @console_onboot = 'false'
        @console = 'webvnc'
        @memory = '4G'
        @diskif = 'virtio-blk'
        @netif = 'virtio-net-viona'
        @cpus = 2
        @cpu_configuration = 'simple'
        @complex_cpu_conf = UNSET_VALUE
        @hostbridge = 'i440fx'
        @acpi = 'on'
        @setup_wait = 60
        @box = UNSET_VALUE
        @clean_shutdown_time = 300
        @dns = [{ 'nameserver' => '1.1.1.1' }, { 'nameserver' => '1.0.0.1' }]
        @vmtype = 'production'
        @partition_id = '0000'
        @sshport = '22'
        @rdpport = '3389'
        @vagrant_user = 'vagrant'
        @vagrant_user_pass = 'vagrant'
        @vagrant_user_private_key_path = './id_rsa'
        @override = false
        @cloud_init_enabled = false
        @vagrant_cloud_creator = UNSET_VALUE
        @firmware_type = 'compatability'
        @firmware = 'BHYVE_RELEASE_CSM'
        case
        when @firmware_type == "compatability" then @firmware = 'BHYVE_RELEASE_CSM'
        when @firmware_type == "UEFI" then @firmware = 'BHYVE_RELEASE'
        when @firmware_type == "BIOS" then @firmware = 'BHYVE_CSM'
        when @firmware_type ==  "BHYVE_DEBUG" then @firmware = 'UEFI_DEBUG'
        when @firmware_type == "BHYVE_RELEASE_CSM" then  @firmware = 'BIOS_DEBUG'
        end
        @vm_type = '3'
        case
        when @vmtype == 'template' then @vm_type = '1'
        when @vmtype == 'development' then @vm_type = '2'
        when @vmtypee == 'production' then @vm_type = '3'
        when @vmtype == 'firewall' then @vm_type = '4'
        when @vmtype == 'other' then @vm_type = '5'
        end
      end
    end
  end
end
