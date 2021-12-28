# frozen_string_literal: true

require 'vagrant'
## Do not Modify this File! Modify the Hosts.yml, Hosts.rb, or Vagrantfile!
module VagrantPlugins
  module ProviderZone
    # This is used define the variables for the project
    class Config < Vagrant.plugin('2', :config)
      # rubocop:disable Layout/LineLength
      attr_accessor :brand, :autoboot, :boxshortname, :kernel, :bcheck_string, :snapshot_script, :diskif, :netif, :cdroms, :disk1path, :disk1size, :cpus, :cpu_configuration, :boot, :complex_cpu_conf, :memory, :vagrant_user, :vagrant_user_private_key_path, :setup_wait, :clean_shutdown_time, :dhcp, :vagrant_user_pass, :firmware_type, :vm_type, :partition_id, :shared_disk_enabled, :shared_dir, :acpi, :os_type, :console, :consolehost, :consoleport, :console_onboot, :hostbridge, :sshport, :rdpport, :override, :additional_disks, :cloud_init_resolvers, :cloud_init_enabled, :cloud_init_dnsdomain, :cloud_init_password, :cloud_init_sshkey, :cloud_init_conf, :dns, :box, :vagrant_cloud_creator

      # rubocop:enable Layout/LineLength

      def initialize
        super
        @brand = 'bhyve'
        @additional_disks = UNSET_VALUE
        @autoboot = true
        @kernel = UNSET_VALUE
        @boxshortname = UNSET_VALUE
        @cdroms = nil
        @shared_dir = nil
        @os_type = 'generic'
        @bcheck_string = 'Last login: '
        @shared_disk_enabled = true
        @consoleport = nil
        @consolehost = '0.0.0.0'
        @console_onboot = 'false'
        @console = 'webvnc'
        @memory = '4G'
        @diskif = 'virtio-blk'
        @netif = 'virtio-net-viona'
        @cpus = 2
        @cpu_configuration = 'simple'
        @complex_cpu_conf = UNSET_VALUE
        @boot = UNSET_VALUE
        @hostbridge = 'i440fx'
        @acpi = 'on'
        @setup_wait = 90
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
        @cloud_init_enabled = nil
        @cloud_init_conf = nil
        @cloud_init_dnsdomain = UNSET_VALUE
        @cloud_init_password = UNSET_VALUE
        @cloud_init_resolvers = UNSET_VALUE
        @cloud_init_sshkey = UNSET_VALUE
        @firmware_type = 'compatability'
        @vm_type = 'production'
        @snapshot_script = '/opt/vagrant/bin/Snapshooter.sh'
      end
    end
  end
end
