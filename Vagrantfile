# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "ubuntu-1410-cloud"

  config.vm.synced_folder "conf.d", "/home/vagrant/conf.d"

  config.vm.provision "shell" do |s|
      s.path = "provision/setup.sh"
      s.privileged = true
  end

  config.vm.provider "virtualbox" do |v|
     v.memory = 738
     v.cpus = 2
  end


  config.vm.network "forwarded_port", guest: 5151, host: 5151
end
