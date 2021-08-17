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
| Reload                      | Working
| VLANs                       | Working
| Multiple Nics               | Working
| DHCP Address                | Work in Progress
| Multiple Disks              | Partially Working (single disk only)
| Start VNC Server            | Work in Progress
| Networking                  | Working -- via zlogin -C -- cloud-init cominig
| SSH/SSH run                 | Working -- key based only
| Graceful shutdown           | Working
| Halt                        | Working
| Destroy                     | Working
| Packer Support              | Untested
| Convert                     | Work in Progress
| Find                        | Work in Progress
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

| Box                                                             										     | Version   | OS           | Purpose    | Status
| :---------------------------------------------------------------------------------	     | :------   |:------       | :------    | :------
| [Makr44/ubuntu2104-server](https://app.vagrantup.com/Makr44/boxes/ubuntu2104-server)		 |  v.0.08   | Ubuntu 21.04 | Multi      | Working 
| [Makr44/ubuntu2104-desktop](https://app.vagrantup.com/Makr44/boxes/ubuntu2104-desktop)	 |  v.0.20   | Ubuntu 21.04 | Desktop    | Work in Progress 
| [Makr44/ubuntu2004-server](https://app.vagrantup.com/Makr44/boxes/ubuntu2004-server)		 |  v.0.05   | Ubuntu 20.04 | Multi      | Work in Progress 
| [Makr44/ubuntu2004-desktop](https://app.vagrantup.com/Makr44/boxes/ubuntu2004-desktop)	 |  v.0.07   | Ubuntu 20.04 | Desktop    | Work in Progress  
| [Makr44/Alma84-server](https://app.vagrantup.com/Makr44/boxes/Alma84-server)	    	     |  v.0.03   | Alma 8.4     | Multi      | Work in Progress 
| [Makr44/ubuntu2104-server](https://app.vagrantup.com/Makr44/boxes/ubuntu2104-server)		 |           | Ubuntu 20.04 |            | Work in Progress  
| [Makr44/ubuntu2104-server](https://app.vagrantup.com/Makr44/boxes/ubuntu2104-server)		 |           | Ubuntu 20.04 |            | Work in Progress 
| [Makr44/ubuntu2104-server](https://app.vagrantup.com/Makr44/boxes/ubuntu2104-server)		 |           | Ubuntu 20.04 |            | Work in Progress 



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

The plan is to incorporate the above code to allow people to import existing virtualbox boxes from vagrant cloud (and local installations) and automatically convert them to bhyve.

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

| Box                 | OS             | Status
| :--------------     |:------         | :------
| `centos/7`          | CentOS 7       | NFS Synced Folders Fail
| All                 | All            | Cannot Detect OS Boot
| All                 | All            | global-status incorrectly reports states -- [Known Bug](https://github.com/hashicorp/vagrant/issues/4360) in Vagrant 

### NFS Synced Folders Fail

Vagrant uses NFS as default synced folder type. When it fails on your
machine and box, you can:
* Add `config.vm.synced_folder ".", "/vagrant", type: "rsync"` to your
  Vagrantfile to ensure that rsync type is used. Vagrant core will raise an
  error to inform you when there is not rsync find in PATH
* Run `vagrant plugin install vagrant-sshfs` to enable vagrant-sshfs

### NFS Synced Folders Fail

After certain Vagrant commands or outside zone influence global-status becomes stale.

### Cannot Detect OS Boot

Currently this plugin uses Ruby to parse the output of they TTYS0 console output of the VM. It waits until it detects "Last Login:".

This is expected to be adjusted once cloud-init properly works in a future release of bhyve.

This is assuming that your VM is set to auto-login the root user, and enable the console output on TTYS0. On Ubuntu 20.04 this can be done by setting it as follows:

1) Create a directory /etc/systemd/system/serial-getty@ttyS0.service.d
2) Create a file /etc/systemd/system/serial-getty@ttyS0.service.d
    a) add the following content:
        ```
        [Service]
        ExecStart=
        ExecStart=/sbin/agetty --autologin root -8 --keep-baud 115200,38400,9600 ttyS0 $TERM
        ```
3) In Grub add the following configuration:
        ```
        GRUB_CMDLINE_LINUX="console=ttyS0,115200n8 tsc=reliable earlyprintk"
        ```

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
