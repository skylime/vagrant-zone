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
  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.required_ruby_version = ">= 2.0"
  spec.required_rubygems_version = ">= 1.3.6"
  spec.add_development_dependency "bundler", "~> 2.2.25"
  spec.add_development_dependency "rake", "~> 12.3.3"
  spec.add_development_dependency "rspec"
  spec.add_runtime_dependency "ruby_expect"
  spec.add_runtime_dependency "netaddr"
  spec.metadata = {
    "bug_tracker_uri" => "https://github.com/Makr91/issues",
    "changelog_uri" => "https://github.com/Makr91/blob/main/CHANGELOG.md",
    "documentation_uri" => "http://rubydoc.info/gems/vagrant-zones",
    "source_code_uri" => "https://github.com/Makr91"
  }
end
