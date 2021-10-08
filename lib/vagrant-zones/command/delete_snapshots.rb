# frozen_string_literal: true

module VagrantPlugins
  module ProviderZone
    module Command
      # This is used to delete zfs snapshots the zone
      class DeleteSnapshots < Vagrant.plugin('2', :command)
        def execute
          options = {}
          opts = OptionParser.new do |o|
            o.banner = 'Usage: vagrant zone zfssnapshot list [options]'
            o.on('--dataset SNAPSHOTPATH', 'Specify snapshot path') do |p|
              options[:dataset] = p
            end
            o.on('--snapshot_name @SNAPSHOTNAME', 'Specify snapshot name') do |p|
              options[:snapshot_name] = p
            end
          end

          argv = parse_options(opts)
          return unless argv

          unless argv.length <= 4
            @env.ui.info(opts.help)
            return
          end

          options[:dataset] = 'all' if options[:dataset].nil?
          options[:snapshot_name] = 'all' if options[:snapshot_name].nil?
          with_target_vms(argv, provider: :zone) do |machine|
            driver = machine.provider.driver
            subcommand = nil
            driver.zfs(machine, @env.ui, 'destroy', options[:dataset], options[:snapshot_name], subcommand)
          end
        end
      end
    end
  end
end
