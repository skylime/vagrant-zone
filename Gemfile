source 'https://rubygems.org'
Encoding.default_external = Encoding::UTF_8
Encoding.default_internal = Encoding::UTF_8
group :development do
  # We depend on Vagrant for development, but we don't add it as a
  # gem dependency because we expect to be installed within the
  # Vagrant environment itself using `vagrant plugin`.
  gem 'vagrant', github: 'mitchellh/vagrant', ref: 'v2.2.18'
end

group :plugins do
  gemspec
end
