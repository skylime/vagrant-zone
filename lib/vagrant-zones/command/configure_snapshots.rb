# frozen_string_literal: true

module VagrantPlugins
  module ProviderZone
    module Command
      # This is used to configure snapshots for the zone
      class ConfigureSnapshots < Vagrant.plugin('2', :command)
        def execute
          options = {}
          opts = OptionParser.new do |o|
            o.banner = 'Usage: vagrant zone zfssnapshot list [options]'
            o.on('--dataset SNAPSHOTPATH', 'Specify path to enable snapshots on') do |p|
              options[:dataset] = p
            end
            frequencymessage = 'Set a policy with one of the available optional frequencies'
            o.on('--frequency <hourly/daily/weekly/monthly/default>', frequencymessage) do |p|
              options[:frequency] = p
            end
            frequency_rtnmsg = 'Number of snapshots to take for the frequency policy'
            o.on('--frequency_rtn <#>/default ', frequency_rtnmsg) do |p|
              options[:frequency_rtn] = p
            end
            deletemsg = 'Delete frequency policy'
            o.on('--delete  <hourly/daily/weekly/monthly/all>', deletemsg) do |p|
              options[:delete] = p
            end
            listmsg = 'Show Cron Policies'
            o.on('--list  <hourly/daily/weekly/monthly/all>', listmsg) do |p|
              options[:list] = p
            end
          end

          argv = parse_options(opts)
          return unless argv

          unless argv.length <= 4
            @env.ui.info(opts.help)
            return
          end

          with_target_vms(argv, provider: :zone) do |machine|
            driver = machine.provider.driver
            driver.zfs(machine, @env.ui, 'cron', options)
          end
        end
      end
    end
  end
end
