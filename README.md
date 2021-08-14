# vagrant-zones
Vagrant Plugin which can be used to managed Bhyve, LX and native zones on illumos (OmniOSce)

- [Status](#status)
  - [Functions](#functions)
  - [Boxes](#boxes)
- [Development](#Development)
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

| Function                    | Status
| :----------                 | :-----
| Box format                  | Defined
| Emergency Console           | Working -- zlogin -C -- VNC switch(wip)
| Check Bhyve support         | Working
| Packaging                   | Working
| Networking                  | Working -- via zlogin -C -- cloud-init cominig
| SSH/SSH run                 | Working -- key based only
| Graceful shutdown           | Work in Progress
| Halt                        | Working
| Destroying                  | Working
| Convert                     | Work in Progress
| Provision                   | Working -- key based only -- cloud-init cominig
| Booting (UEFI	and BIOS)     | Working
| Port forwarding             | Work in Progress
| Vagrant Cloud Support       | Working -- Types: Zones,Virtualbox(wip)
| Snapshots                   | Work in Progress
| Bhyve Zone Support          | Working
| LX Zone Support             | Working
| Shared Folders              | Working -- Rsync, SSHFS, NFS(wip), LOFS(tbd)
| Suspend                     | Not supported by bhyve
| Resume                      | Not supported by bhyve

### Boxes

Collecting status of boxes from [Vagrant Cloud](https://app.vagrantup.com/)

| Box                                                             										         | OS             | Status
| :---------------------------------------------------------------------------------	         |:------         | :------
| [Makr44/ubuntu2104-server](https://app.vagrantup.com/Makr44/boxes/ubuntu2104-server)		     | Ubuntu 20.04  	| Working 


## Development Installation Instructions

### Setup OS for Development

  * ooce/library/libarchive
  * system/bhyve
  * system/bhyve/firmware
  * ooce/application/vagrant
  * ruby-26
  * ooce/system/mbuffer

### Setup vagrant development environment

    $ git clone https://github.com/hashicorp/vagrant.git
    $ cd /path/to/your/vagrant/clone
    $ bundle install
    $ bundle --binstubs exec

### Setup vagrant-zones environment

    $ git clone https://github.com/Makr91/vagrant-zones.git
    $ cd vagrant-bhyve
    $ bundle install --path vendor/bundle --binstubs


### Create a box from an existing box

For LX Zones you can use a Joyent UUID, for Bhyve Zones, you can use a ZSS file or a image from the Vagrant Cloud with the Zone provider. There may be future work to convert existing images to a Zone provider type.

Once you have setup your a box with an existing box, you can create a box from that with:

```
vagrant package --output test4.box
```

### Convert a box

Thanks to [Steve Wills](https://github.com/swills)'s work, now you can convert a VirtualBox box to a bhyve one with [vagrant-mutate](https://github.com/sciurus/vagrant-mutate).

### Run the box

After a box is created, you should create another Vagrantfile.

```ruby
Vagrant.configure("2") do |config|
  config.vm.box = "boxname"
end
```

then execute this command to start the box with bhyve ( '--provider=zone' may be neccessary if not defined in Vagrantfile) 

    $ /path/to/vagrant-zones/bin/vagrant up 

### SSH into the box

After the box is booted(uped), you can ssh into by executing this command. 

    $ /path/to/vagrant-zones/bin/vagrant ssh

### Shutdown the box and cleanup

This command will shutdown the booted VM and clean up environment

    $ /path/to/vagrant-zones/bin/vagrant halt

### Destroy the box

    $ /path/to/vagrant-zones/vagrant destroy

## Known Issues

| Box                                                             										         | OS             | Status
| :---------------------------------------------------------------------------------	         |:------         | :------
| `centos/7`                                                                                   | CentOS 7       | NFS Synced Folders Fail

### NFS Synced Folders Fail

Vagrant uses NFS as default synced folder type. When it fails on your
machine and box, you can:
* Add `config.vm.synced_folder ".", "/vagrant", type: "rsync"` to your
  Vagrantfile to ensure that rsync type is used. Vagrant core will raise an
  error to inform you when there is not rsync find in PATH
* Run `vagrant plugin install vagrant-sshfs` to enable vagrant-sshfs

## Installation

Now this gem has been published on [rubygems.org](https://rubygems.org/gems/vagrant-zones).

### Setup OS Installation

  * ooce/library/libarchive
  * system/bhyve
  * system/bhyve/firmware
  * ooce/application/vagrant
  * ruby-26
  * ooce/system/mbuffer

### Setup vagrant-zones

 To install it in a standard vagrant environment:
 
 `vagrant plugin install vagrant-zones`

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/Makr91/vagrant-zones.


## License

This project is licensed under the AGPL v3 License - see the [LICENSE](LICENSE) file for details

## Built With
* [Vagrant](https://www.vagrantup.com/) - Portable Development Environment Suite.
* [VirtualBox](https://www.virtualbox.org/wiki/Downloads) - Hypervisor.
* [Ansible](https://www.ansible.com/) - Virtual Manchine Automation Management.

## Contributing Sources
* [vagrant-bhyve](https://github.com/jesa7955/vagrant-bhyve) - A Vagrant plugin for FreeBSD to spin up Bhyve Guests.
* [vagrant-zone](https://github.com/skylime/vagrant-zone) - A Vagrant plugin to spin up LXZones.


## Contributing

Please read [CONTRIBUTING.md](https://www.prominic.net) for details on our code of conduct, and the process for submitting pull requests to us.

## Authors
* **Thomas Merkel** - *Initial work* - [Skylime](https://github.com/skylime)
* **Mark Gilbert** - *Takeover* - [Makr91](https://github.com/Makr91)

See also the list of [contributors](https://github.com/Makr91/vagrant-zones/graphs/contributors) who participated in this project.

## Acknowledgments

* Hat tip to anyone whose code was used
