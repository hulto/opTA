echo "[all:vars]
ansible_connection=winrm
ansible_user=whiteteam
ansible_password=Passw0rd-123
ansible_become_password=Passw0rd-123
ansible_winrm_server_cert_validation=ignore
ansible_become_method=runas
ansible_become_user=whiteteam
ansible_become=yes

[all]" > inventory.ini

nmap -v 10.2.$1.0/24 -n -p 5986 -oG - | awk '/open/{print $2}' | tee -a gen_inventory.ini

