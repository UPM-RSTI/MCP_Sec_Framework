Vagrant.configure("2") do |config|
 
  if Vagrant.has_plugin?("vagrant-vbguest")
    config.vbguest.auto_update = false
  end
 
  # =========================
  # VARIABLES
  # =========================
 
  WAZUH_SERVER_IP = "192.168.56.110"
 
  DASHBOARD_PORT = 5602
  FLASK_PORT     = 5011
 
  WZ_VERSION = "v4.14.0"
  WZ_REPO    = "https://github.com/wazuh/wazuh-docker.git"
 
  config.vm.synced_folder "./shared", "/home/vagrant/shared", create: true
 
  # =========================
  # VM: WAZUH SERVER
  # Solo corre el SIEM (Wazuh docker-compose).
  # El MCP server corre en el host como contenedor Docker
  # apuntando a esta VM en 192.168.56.110.
  # =========================
  config.vm.define "wazuh-server" do |s|
    s.vm.box      = "ubuntu/jammy64"
    s.vm.hostname = "wazuh-server"
 
    s.vm.network "private_network", ip: WAZUH_SERVER_IP
    s.vm.network "forwarded_port",
                 guest: 443,
                 host:  DASHBOARD_PORT,
                 auto_correct: true
 
    s.vm.provider "virtualbox" do |vb|
      vb.name   = "Wazuh-server"
      vb.memory = 8192
      vb.cpus   = 4
      vb.gui    = false
    end
 
    # Provisiona solo el SIEM de Wazuh
    s.vm.provision "shell",
      privileged: true,
      path: "provision/wazuh_server_provision.sh",
      args: "#{WZ_REPO} #{WZ_VERSION} #{FLASK_PORT} #{WAZUH_SERVER_IP}"
 
  end
 
end
 