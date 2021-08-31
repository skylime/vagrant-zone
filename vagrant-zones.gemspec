# coding: utf-8
require File.expand_path('../lib/vagrant-zones/version', __FILE__)

Gem::Specification.new do |spec|
  spec.name          = "vagrant-zones"
  spec.version       = VagrantPlugins::ProviderZone::VERSION
  spec.authors       = ["Mark Gilbert"]
  spec.email         = ["mark.gilbert@prominic.net"]
  spec.summary       = %q{Vagrant provider plugin to support zones}
  spec.description   = spec.summary
  spec.homepage      = "https://github.com/makr91/vagrant-zones"
  spec.license       = "AGPLv3"
  spec.metadata = {
    "bug_tracker_uri" => "https://github.com/Makr91/issues",
    "changelog_uri" => "https://github.com/Makr91/blob/main/CHANGELOG.md",
    "documentation_uri" => "http://rubydoc.info/gems/vagrant-zones",
    "source_code_uri" => "https://github.com/Makr91"
  }

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = ">= 2.4.0"
  spec.required_rubygems_version = ">= 1.3.6"

  spec.add_runtime_dependency "ruby_expect"
  spec.add_runtime_dependency "netaddr"
  spec.add_runtime_dependency 'i18n', '>= 1.0'
  spec.add_runtime_dependency 'log4r', '>= 1.1'
  spec.add_runtime_dependency "iniparse", '>= 1.0'
  spec.add_runtime_dependency 'nokogiri'
  
  spec.add_development_dependency "ruby-progressbar", ">= 1.11.0"  
  spec.add_development_dependency "bundler", ">= 2.2.25"
  spec.add_development_dependency "rake", ">= 13.0.6"
  spec.add_development_dependency "rspec", ">= 3.4"
  spec.add_development_dependency 'rspec-core', '>= 3.4'
  spec.add_development_dependency 'rspec-expectations', '>= 3.10.0'
  spec.add_development_dependency 'rubocop-rake', '>= 0.6.0'
  spec.add_development_dependency 'rubocop-rspec', '>= 2.4.0'

  Encoding.default_external = Encoding::UTF_8
  Encoding.default_internal = Encoding::UTF_8

  spec.add_development_dependency 'rspec-mocks', '>= 3.10.0'
  spec.add_development_dependency 'rubocop', '>= 1.0'
  spec.add_development_dependency 'code-scanning-rubocop', '>= 0.5.0'
end
