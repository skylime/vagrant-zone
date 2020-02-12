require "vagrant/action/builder"
require 'log4r'

module VagrantPlugins
	module ProviderZone
		module Action
			# Include the built-in modules so we can use them as top-level things.
			include Vagrant::Action::Builtin
			@logger = Log4r::Logger.new('vagrant_zone::action')

			# This action is called to bring the box up from nothing.
			def self.action_up
				Vagrant::Action::Builder.new.tap do |b|
					b.use Call, IsCreated do |env, b2|
						re = env[:result]
						m = env[:machine].state.id

						if !env[:result]
							b2.use Import
							b2.use Create
							b2.use Provision
						else
							env[:halt_on_error] = true
							b2.use action_start
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

			action_root = Pathname.new(File.expand_path('../action', __FILE__))
			autoload :Import, action_root.join('import')
			autoload :Create, action_root.join('create')
			autoload :IsCreated, action_root.join('is_created')
		end
	end
end
