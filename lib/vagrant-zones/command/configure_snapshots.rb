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
            frequencymessage = 'Set a policy with one of the available optional frequencies, cannot use with the delete or list option'
            o.on('--frequency <hourly/daily/weekly/montly/default>', frequencymessage) do |p|
              options[:frequency] = p
            end
            frequency_retentionmsg = 'Number of snapshots to take for the frequency policy, cannot use with the delete or list option'
            o.on('--frequency_retention <#> ', frequency_retentionmsg) do |p|
              options[:frequency_retention] = p
            end
            deletemsg = 'Delete frequency policy, cannot use with the frequency or frequency_retention option'
            o.on('--delete  <hourly/daily/weekly/montly/all>', deletemsg) do |p|
              options[:delete] = p
            end
            listmsg = 'Show Cron Policies, cannot use with the frequency or frequency_retention option'
            o.on('--list  <hourly/daily/weekly/montly/all>', listmsg) do |p|
              options[:list] = p
            end
          end

          argv = parse_options(opts)
          return unless argv

          unless argv.length <= 4
            @env.ui.info(opts.help)
            return
          end

          options[:dataset] = 'all' if options[:dataset].nil?
          options[:frequency] = 'default' if options[:frequency].nil?

          @env.ui.info(opts.help) if options[:frequency] && options[:delete]
          @env.ui.info(opts.help) if options[:frequency] && options[:list]
          @env.ui.info(opts.help) if options[:frequency_retention] && options[:list]
          @env.ui.info(opts.help) if options[:frequency_retention] && options[:delete]
          @env.ui.info(opts.help) if options[:list] && options[:delete]
          return if options[:frequency] && options[:delete]
          return if options[:frequency] && options[:list]
          return if options[:frequency_retention] && options[:list]
          return if options[:frequency_retention] && options[:delete]
          return if options[:list] && options[:delete]

          with_target_vms(argv, provider: :zone) do |machine|
            driver = machine.provider.driver
            subcommanddata = [options[:list].to_s] if options[:list]
            subcommand = 'list' if options[:list]
            subcommanddata = [options[:delete].to_s] if options[:delete]
            subcommand = 'delete' if options[:delete]
            subcommanddata = [options[:frequency].to_s, options[:frequency_retention].to_s]
            subcommand = 'frequency' if options[:frequency]
            puts subcommanddata.inspect
            driver.zfs(machine, @env.ui, 'cron', options[:dataset], subcommanddata, subcommand)
          end
        end
      end
    end
  end
end
