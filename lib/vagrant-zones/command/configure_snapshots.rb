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
            o.on('--frequency <hourly/daily/weekly/montly/default>', 'Set a policy with one of the available optional frequencies') do |p|
              options[:frequency] = p
            end
            o.on('--frequency_retention <#> ', 'Number of snapshots to take for the frequency policy') do |p|
              options[:frequency_retention] = p
            end
            o.on('--delete  <hourly/daily/weekly/montly/all>', 'Delete frequency policy') do |p|
              options[:delete] = p
            end
            o.on('--list  <hourly/daily/weekly/montly/all>', 'Show Cron Policies') do |p|
              options[:list] = p
            end
          end

          argv = parse_options(opts)
          return unless argv

          unless argv.length <= 4
            @env.ui.info(opts.help)
            return
          end

          if options[:dataset].nil?
            options[:dataset] = 'all'
          end

          if options[:frequency].nil?
            options[:frequency] = 'default'
          end

          return if options[:frequency] && options[:delete]
          return if options[:frequency] && options[:list]
          return if options[:frequency_retention] && options[:list]
          return if options[:frequency_retention] && options[:delete]
          return if options[:list] && options[:delete]


          with_target_vms(argv, provider: :zone) do |machine|
            driver = machine.provider.driver
            subcommanddata = []
            subcommanddata =  [options[:list]] unless options[:delete] || options[:frequency]
            
            subcommand = "list" unless options[:delete] || options[:frequency]
            subcommanddata =  options[:delete] unless options[:list] || options[:frequency]
            subcommand = "delete" unless options[:list] || options[:frequency] || 
            if !options[:delete] && !options[:list]
                subcommanddata = ["#{options[:frequency]}","#{options[:frequency_retention]}"]
                puts subcommanddata
                puts "test"
                subcommand = "frequency" unless options[:delete] || options[:list]
            end
            puts subcommanddata.inspect
            driver.zfs(machine, @env.ui, 'cron', options[:dataset], subcommanddata , subcommand)
          end
        end
      end
    end
  end
end