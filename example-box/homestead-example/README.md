<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/Makr91/vagrant-zones/">
    <img src="conf/wiki/images/Prom.jpg" alt="Logo" width="200" height="100">
  </a>

  <h3 align="center">vagrant-zones</h3>

  <p align="center">
    An README to jumpstart your build of the vagrant-zones
    <br />
    <a href="https://github.com/Makr91/vagrant-zones/"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/Makr91/vagrant-zones/">View Demo</a>
    ·
    <a href="https://github.com/Makr91/vagrant-zones/issues">Report Bug</a>
    ·
    <a href="https://github.com/Makr91/vagrant-zones/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About the Project](#vagrant-zones)
  * [Built With](#built-with)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#downloading-docova-project-to-a-local-folder)
    * [Mac OS X](https://github.com/Makr91/vagrant-zones/blob/master/MacMojaveReadme.md) -- Quick Start
    * [Windows](https://github.com/Makr91/vagrant-zones/blob/master/Win10ReadMe.md) -- Quick Start
* [Rebuilding](#rebuilding-the-project)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#authors)
* [Acknowledgements](#acknowledgments)



# vagrant-zones
Primary goal is to use Vagrant on Solaris to deploy the latest bhyve, kvm, lx and other zone types for multiple purposes. Vagrant and Customer Specific Variables will be passed along to provisioning scripts to allow for automated application installations after the zone is provisioned. 

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes, as well as what will power the build process of the VMs at Prominic.NET. You MUST have the Vagrant, Virtualbox and Git installed on your machine. Please follow the instructions below for setting up your VM with the pre-requistes. 

### Prerequisites

You will need some software on your PC or Mac:

```
git
Vagrant
vagrant-zones
```

See Requisites in the main [README](https://github.com/hashicorp/vagrant) as well.


## Downloading the Docova Project to a Local folder

Open up a terminal and perform the following git command in order to save the Project to a local folder:

```shell
git clone https://github.com/Makr91/vagrant-zones.git

```
### Configuring the Environment
Once you have navigated into the projects directory. You will need to modify the Hosts.yml to your specific Environment.
Please set the configuration file with the correct, Network and Memory and CPU settings your host machine will allow, as these may vary from system to system, I cannot predict your Machines CPU and Network Requirements. You will need to make sure that you do not over allocate CPU, and RAM. In regards to Networking, you MUST change the networking, you will need to set the IP to that of one that is not in use by any other machine on your network.

If you want to change to a different branch for different Application Builds, change the branch variable to that of an existing branch in this repo, in the Hosts.yml

```
cd vagrant-zones/example-box/homestead-example
vi Hosts.yml
```

#### Commonly Changed Parameters:

* ip: Use any IP on your Internal Network that is NOT in use by any other machine.
* gateway: This is the IP of your Router
* identifier: This is the Hostname of the VM, make sure this is a Fully Qualified Domain Name
* mac: This is your machines Network unique identifier, if you run more than one instance on a network, randonmize this. [Mac Generator](https://www.miniwebtool.com/mac-address-generator/)
* netmask: Set this to the subnet you have your network configured to. This is normally: 255.255.255.0
* name: The Vagrant unique identifier
* cpu: The number of cores you are allocating to this machine. Please beware and do not over allocate. Overallocation may cause instability
* memory: The amount of Memory you are allocating to the machine.  Please beware and do not over allocate. Overallocation may cause instability


Once you have configured the Hosts.yml file. You should now be set to go on getting the VM up and running.

### Starting the VM
The installation process is estimated to take about 15 - 30 Minutes. 

```
vagrant up
```

## Rebuilding the Project

There are times that the the project may be misconfigured by a typo or wrong value in the Hosts.yml or due to networking issues. As a result of this the VM may not be setup correctly. 

Vagrant commands are highly dependent on the path that your run the commands in. When you run *vagrant up*, you must be inside of the Project folder. If you need to restart the VM, you can do so by running *vagrant reload* however, for this to work, you must be inside of the Vagrant Project folder.


| Common vagrant commands | Modifiers and Options | Default Action                                                  | With Option                                                   |
|-------------------------|-----------------------|-----------------------------------------------------------------|---------------------------------------------------------------|
| vagrant up              | --provision           | Boots the VM, First run Provisions, Subsequent runs simply boot | If the VM has already been created, will run the provisioners |
| vagrant reload          | --provision           | Restarts the VM without Provisioning                            | Restarts the VM runs the provisioners                         |
| vagrant destroy         | -f                    | Vagrant Asks to Destroy VM                                      | Vagrant Destroys the VM                                       |
| vagrant global-status   | --prune               | Lists all VMs and their project paths                           | Lists all VM and their project paths and removes corrupt VMs  |
| vagrant halt            |                       | Shuts down the VM                                               |                                                               |
## Roadmap

See the [open issues](https://github.com/Makr91/vagrant-zones/issues) for a list of proposed features (and known issues).

## Built With
* [Vagrant](https://www.vagrantup.com/) - Portable Development Environment Suite.
* [VirtualBox](https://www.virtualbox.org/wiki/Downloads) - Hypervisor.
* [Ansible](https://www.ansible.com/) - Virtual Manchine Automation Management.
* [Vagrant](https://github.com/hashicorp/vagrant) - Vagrant 


## Contributing

Please read [CONTRIBUTING.md](https://www.prominic.net) for details on our code of conduct, and the process for submitting pull requests to us.

## Authors

* **Mark Gilbert** - *Initial work* - [Makr91](https://github.com/Makr91)

See also the list of [contributors](https://github.com/Makr91/vagrant-zones/graphs/contributors) who participated in this project.

## License

This project is licensed under the SSLP v3 License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Hat tip to anyone whose code was used
