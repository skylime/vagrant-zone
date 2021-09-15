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
        super
        # pkgsrc, lx, bhyve, kvm, illumos
        @brand = 'bhyve'
        @additional_disks = UNSET_VALUE
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
        ft = @firmware_type
        case ft
        when :compatability
          @firmware = 'BHYVE_RELEASE_CSM'
        when :UEFI
          @firmware = 'BHYVE_RELEASE'
        when :BIOS
          @firmware = 'BHYVE_CSM'
        when :BHYVE_DEBUG
          @firmware = 'UEFI_DEBUG'
        when :BHYVE_RELEASE_CSM
          @firmware = 'BIOS_DEBUG'
        end

        case @vm_type
        when :template
          @vmtype = '1'
        when :development
          @vmtype = '2'
        when :production
          @vmtype = '3'
        when :firewall
          @vmtype = '4'
        when :other
          @vmtype = '5'
        end
      end
    end
  end
end
