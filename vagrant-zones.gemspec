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

  spec.required_ruby_version = ">= 2.0"
  spec.required_rubygems_version = ">= 1.3.6"

  spec.add_runtime_dependency "ruby_expect"
  spec.add_runtime_dependency "netaddr"
  spec.add_runtime_dependency 'i18n', '~> 1.0'
  spec.add_runtime_dependency 'log4r', '~> 1.1'
  spec.add_runtime_dependency "iniparse", '> 1.0'
  spec.add_runtime_dependency 'nokogiri', '~> 1.6'

  spec.add_development_dependency "bundler", "~> 2.2.25"
  spec.add_development_dependency "rake", "~> 12.3.3"
  spec.add_development_dependency "rspec", "~> 3.4"
  spec.add_development_dependency 'rspec-core', '~> 3.4'
  spec.add_development_dependency 'rspec-expectations', '~> 3.10.0'
  spec.add_development_dependency 'rspec-mocks', '~> 2.12.1'
  spec.add_development_dependency 'rubocop', '~> 0.32.1'
  spec.add_development_dependency 'code-scanning-rubocop', '~> 0.5'

end
