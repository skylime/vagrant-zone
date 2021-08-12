# vagrant-zone
Vagrant Plugin which can be used to managed Bhyve, LX and native zones on illumos (OmniOSce)

- [Status](#status)
  - [Functions](#functions)
  - [Boxes](#boxes)
- [Test](#test)
  - [Setup environment](#setup-environment)
  - [Create a box](#create-a-box)
  - [Add the box](#add-the-box)
  - [Run the box](#run-the-box)
  - [SSH into the box](#ssh-into-the-box)
  - [Shutdown the box and cleanup](#shutdown-the-box-and-cleanup)
- [Known Issues](#known-issues)
- [Installation](#installation)

## Status

### Functions

| Function                  | Status
| :----------               | :-----
| Box format                | Defined
| Check bhyve support       | Work in Progress
| Cloning	                  | Work in Progress
| Network                   | Working
| SSH/SSH run               | Working -- Key Based Only use the Key provided in the Template that you use
| Graceful shutdown         | Working
| ACPI shutdown             | Working
| Destroying                | Working
| Provision                 | Work in Progress
| Booting (UEFI	and BIOS )  | Working
| Port forwarding           | Work in Progress
| Suspend                   | Not supported by bhyve yet
| Resume                    | Not supported by bhyve yet

### Boxes

Collecting status of boxes from [Atlas](https://atlas.hashicorp.com/boxes/search) other than those provided by [FreeBSD](https://atlas.hashicorp.com/freebsd)

| Function										| Status
| :---------------------------------------------------------------------------------	| :------
| [Makr44/ubuntu2104-desktop](https://app.vagrantup.com/Makr44/boxes/ubuntu2104-desktop)			| Working with work


## Test

### Setup vagrant development environment

    $ git clone https://github.com/hashicorp/vagrant.git
    $ cd /path/to/your/vagrant/clone
    $ bundle install
    $ bundle --binstubs exec

### Setup environment

    $ git clone https://github.com/Makr91/vagrant-zone.git
    $ cd vagrant-bhyve
    $ bundle install --path vendor/bundle --binstubs

### Create a box

### Convert a box

Thanks to [Steve Wills](https://github.com/swills)'s work, now you can convert a VirtualBox box to a bhyve one with [vagrant-mutate](https://github.com/sciurus/vagrant-mutate).

### Run the box

After a box is created, you should create another Vagrantfile.

```ruby
Vagrant.configure("2") do |config|
  config.vm.box = "boxname"
end
```

then execute this command to start the box with bhyve

    $ /path/to/vagrant-zone/bin/vagrant up --provider=zone

### SSH into the box

After the box is booted(uped), you can ssh into by executing this command. 

    $ /path/to/vagrant-zone/bin/vagrant ssh

### Shutdown the box and cleanup

This command will shutdown the booted VM and clean up environment

    $ /path/to/vagrant-zone/bin/vagrant halt

### Destroy the box

    $ /path/to/vagrant-zone/vagrant destroy

## Known Issues

### Synced folder is not working correctlly

I met this issue when I try to use vagrant-bhyve to boot `centos/7` box.
Vagrant uses NFS as default synced folder type. When it fails on your
machine and box, you can:
* Add `config.vm.synced_folder ".", "/vagrant", type: "rsync"` to your
  Vagrantfile to ensure that rsync type is used. Vagrant core will raise an
  error to inform you when there is not rsync find in PATH
* Run `vagrant plugin install vagrant-sshfs` to enable vagrant-sshfs


## Installation

Now this gem has NOT YET been published on [rubygems.org](https://rubygems.org/gems/vagrant-zone). You can install it through `vagrant plugin install vagrant-zone`
to install it in a normal Vagrant environment

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/Makr91/vagrant-zone.


## License

This project is licensed under the AGPL v3 License - see the [LICENSE](LICENSE) file for details

## Built With
* [Vagrant](https://www.vagrantup.com/) - Portable Development Environment Suite.
* [VirtualBox](https://www.virtualbox.org/wiki/Downloads) - Hypervisor.
* [Ansible](https://www.ansible.com/) - Virtual Manchine Automation Management.

## Contributing Sources
* [vagrant-bhyve](https://github.com/jesa7955/vagrant-bhyve) - A Vagrant plugin for FreeBSD to spin up Bhyve Guests.
* [vagrant-zone](https://github.com/skylime/vagrant-zone) - A Vagrant plugin to spin up LXZones.
* 

## Contributing

Please read [CONTRIBUTING.md](https://www.prominic.net) for details on our code of conduct, and the process for submitting pull requests to us.

## Authors
* **Thomas Merkel** - *Initial work* - [Skylime](https://github.com/skylime)
* **Mark Gilbert** - *Takeover* - [Makr91](https://github.com/Makr91)

See also the list of [contributors](https://github.com/Makr91/Vagrant-Guacamole-CentOS-8.1/graphs/contributors) who participated in this project.

## Acknowledgments

* Hat tip to anyone whose code was used
