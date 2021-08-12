# coding: utf-8
require File.expand_path('../lib/vagrant-zone/version', __FILE__)

Gem::Specification.new do |spec|
  spec.name          = "vagrant-zone"
  spec.version       = VagrantPlugins::ProviderZone::VERSION
  spec.authors       = ["Thomas Merkel", "Mark Gilbert"]
  spec.email         = ["thomas.merkel@skylime.net", "mark.gilbert@prominic.net"]

  spec.summary       = %q{Vagrant provider plugin to support zones}
  spec.description   = spec.summary
  spec.homepage      = "https://github.com/makr91/vagrant-zone"
  spec.license       = "AGPLv3"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 2.2.25"
  spec.add_development_dependency "rake", "~> 12.3.3"
  spec.add_development_dependency "rspec"
  spec.add_runtime_dependency "ruby_expect"
  spec.add_runtime_dependency "netaddr"
end
