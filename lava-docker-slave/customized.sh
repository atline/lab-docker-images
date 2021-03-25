service udev start
service ser2net start
service tftpd-hpa start
rpcbind
service nfs-kernel-server start
update-ca-certificates
sed -i "s/\"coordinator_hostname\": .*/\"coordinator_hostname\": \"$master\"/g" /etc/lava-coordinator/lava-coordinator.conf
