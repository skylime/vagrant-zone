# coding: utf-8
require "vagrant/action/builder"
require 'log4r'

module VagrantPlugins
	module ProviderZone
		module Action
			# Include the built-in modules so we can use them as top-level things.
			include Vagrant::Action::Builtin
			@logger = Log4r::Logger.new('vagrant_zones::action')

			# This action is called to bring the box up from nothing.
			def self.action_up
				Vagrant::Action::Builder.new.tap do |b|
					b.use Call, IsCreated do |env, b2|
						re = env[:result]
						m = env[:machine].state.id
						ui = env[:ui]

						if !env[:result]
							#b2.use BoxUpdate
							b2.use Import
							b2.use Create
							b2.use Network
							b2.use Start							
							b2.use WaitTillBoot
							b2.use Setup
							b2.use WaitTillUp
							
							## Counter intuitive, but Provision must go before SyncFolders for some reason  . .
							b2.use Provision
							b2.use SyncedFolders
							b2.use SyncedFolderCleanup
							
						else
							env[:halt_on_error] = true
							b2.use action_start
						end
					end
				end
			end

			# Assuming VM is created, just start it. This action is not called
			# directly by any subcommand.
			def self.action_start
				Vagrant::Action::Builder.new.tap do |b|
					b.use Call, IsState, :running do |env, b1|
						if env[:result]
							b1.use Message, I18n.t('vagrant_zones.states.is_running')
							next
						end
						b1.use Call, IsState, :uncleaned do |env1, b2|
							if env1[:result]
								b2.use Cleanup
							end
						end

						b1.use Start
						b1.use WaitTillBoot
						#b1.use WaitTillUp
					end
				end
			end


			def self.action_restart
				Vagrant::Action::Builder.new.tap do |b|
					b.use Call, IsState, :running do |env, b1|
						if env[:result]
							b1.use Message, I18n.t('vagrant_zones.states.is_running')
							next
						end
						b1.use Call, IsState, :uncleaned do |env1, b2|
							if env1[:result]
								b2.use Cleanup
							end
						end

						b1.use WaitTillUp
						b1.use Restart
					end
				end
			end




			
			def self.action_shutdown
				Vagrant::Action::Builder.new.tap do |b|
						b.use Call, IsCreated do |env, b2|
							b2.use Call, IsState, :running do |env, b3|
								b3.use WaitTillUp
								b3.use Shutdown
							end
						end


					end
				end
			end


			# This is the action that is primarily responsible for halting the
			# virtual machine.
			def self.action_halt
				Vagrant::Action::Builder.new.tap do |b|
					b.use Call, IsCreated do |env, b2|
						unless env[:result]
							b2.use NotCreated
							next
						end

						if env[:result]
							# VM is running, halt it
							b2.use Halt
						end
					end
				end
			end

			# This action is called to SSH into the machine.
			def self.action_ssh
				Vagrant::Action::Builder.new.tap do |b|
					b.use SSHExec
				end
			end
			def self.action_ssh_run
				Vagrant::Action::Builder.new.tap do |b|
					b.use SSHRun
				end
			end

			# This action is called when you try to package an existing virtual
			# machine to an box image.
			def self.action_package
				Vagrant::Action::Builder.new.tap do |b|
					b.use Package
				end
			end

			# This is the action that is primarily responsible for completely
			# freeing the resources of the underlying virtual machine.
			def self.action_destroy
				Vagrant::Action::Builder.new.tap do |b|
					b.use Call, IsCreated do |env, b2|
						b2.use Destroy
					end
				end
			end

			# This action is called when `vagrant provision` is called.
			def self.action_provision
				Vagrant::Action::Builder.new.tap do |b|
					b.use Call, IsCreated do |env, b2|
						b2.use Call, IsState, :running do |env, b3|
							b3.use Provision
						end
					end
				end
			end

			# This is the action implements the reload command
			# It uses the halt and start actions
			def self.action_reload
				Vagrant::Action::Builder.new.tap do |b|
					b.use Call, IsCreated do |env, b2|
						unless env[:result]
							b2.use NotCreated
							next
						end
						b2.use action_halt
						b2.use action_start
					end
				end
			end


			def self.action_create_zfs_snapshots
				Vagrant::Action::Builder.new.tap do |b|
				  # b.use ConfigValidate # is this per machine?
				  b.use CreateSnapshots
				end
			end

			def self.action_delete_zfs_snapshots
				Vagrant::Action::Builder.new.tap do |b|
				  # b.use ConfigValidate # is this per machine?
				  b.use DeleteSnapshots
				end
			end

			def self.action_configure_zfs_snapshots
				Vagrant::Action::Builder.new.tap do |b|
				  # b.use ConfigValidate # is this per machine?
				  b.use ConfigureSnapshots
				end
			end

			action_root = Pathname.new(File.expand_path('../action', __FILE__))
			##autoload :BoxUpdate, action_root.join('box_update')
			autoload :Import, action_root.join('import')
			autoload :Create, action_root.join('create')
			autoload :Network, action_root.join('network')
			autoload :Setup, action_root.join('setup')
			autoload :Start, action_root.join('start')
			autoload :IsCreated, action_root.join('is_created')
			autoload :NotCreated, action_root.join('not_created')
			autoload :CreateSnapshots, action_root.join('create_zfs_snapshots')
			autoload :DeleteSnapshots, action_root.join('delete_zfs_snapshots')
			autoload :ConfigureSnapshots, action_root.join('configure_zfs_snapshots')
			autoload :Halt, action_root.join('halt')
			autoload :Destroy, action_root.join('destroy')
			autoload :WaitTillBoot, action_root.join('wait_till_boot')
			autoload :WaitTillUp, action_root.join('wait_till_up')
			autoload :Restart, action_root.join('restart')
			autoload :Shutdown, action_root.join('shutdown')
			autoload :PrepareNFSValidIds, action_root.join('prepare_nfs_valid_ids.rb')
			autoload :Package, action_root.join('package.rb')
		end
	end
end
