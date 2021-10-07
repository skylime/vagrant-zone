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
            o.on('--frequency <hourly/daily/weekly/montly>', 'Set a policy with one of the available optional frequencies') do |p|
              options[:frequency] = p
            end
            o.on('--frequency_retention <#> ', 'Number of snapshots to take at this frequency') do |p|
              options[:frequency_retention] = p
            end
            o.on('--delete  <hourly/daily/weekly/montly>', 'Delete frequency policy') do |p|
              options[:delete] = p
            end
            o.on('--list  <hourly/daily/weekly/montly>', 'Show Cron Policies') do |p|
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

          if options[:snapshot_name].nil?
            t = Time.new
            dash = '-'
            colon = ':'
            datetime = t.year.to_s + dash + t.month.to_s + dash + t.day.to_s + dash + t.hour.to_s + colon + t.min.to_s + colon + t.sec.to_s
            options[:snapshot_name] = datetime
          end

          with_target_vms(argv, provider: :zone) do |machine|
            driver = machine.provider.driver
            driver.zfs(machine, @env.ui, 'cron', options[:dataset], options[:snapshot_name])
          end
        end
      end
    end
  end
end