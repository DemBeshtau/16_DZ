# -*- mode: ruby -*-
# vi: set ft=ruby :


Vagrant.configure("2") do |config|
  config.vm.box = "centos/7"
  config.vm.provider :virtualbox do |v|
    #v.memory = 1512
    v.memory = 2048
    v.cpus = 2
  end

  boxes = [
    { :name => "web",
      :ip => "192.168.56.10",
    },
    { :name => "log",
      :ip => "192.168.56.15",
    },
    { :name => "elk",
      :ip => "192.168.56.11",
    },
  ]

  boxes.each do |opts|
    config.vm.synced_folder ".","/vagrant", disabled: false 
    config.vm.define opts[:name] do |config|
      config.vm.hostname = opts[:name]
      config.vm.network "private_network", ip: opts[:ip]
      config.vm.provision "shell", inline: <<-SHELL
       sudo sed -i 's/\#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config
       sudo systemctl restart sshd   
      SHELL
    end
  end

  config.vm.provision "ansible" do |ansible|
    ansible.playbook = "provisioning/playbook.yml"
    ansible.become = "true"
    ansible.limit = "all"
    #ansible.groups = {
    #  "webservers" => ["web"],
    #  "rsyslogservers" => ["log", "elk"],
    #}
  end
end
