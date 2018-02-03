#!/bin/bash
cyan='\e[0;36m'
green='\e[0;34m'
okegreen='\033[92m'
lightgreen='\e[1;32m'
white='\e[1;37m'
red='\e[1;31m'
yellow='\e[1;33m'
BlueF='\e[1;34m'

# go to root
cd

echo -e $yellow""
echo "----------------- MELIHAT DAFTAR LOGIN ----------------"
echo ""
echo "#######################################################"
echo "#                SCRYPT MBAH SHONDONG                 #"
echo "#            http://www.mbahshondong.com              #"
echo "#-----------------------------------------------------#"
echo "#                     HAWOK JOZZ                      #"
echo "#      https://www.facebook.com/groups/pokoemelu      #"
echo "#-----------------------------------------------------#"
echo "#         [== INTERNET GRATIS SAK MODARRE ==]         #"
echo "#######################################################"
echo -e $White""            

data=( `ps aux | grep -i dropbear | awk '{print $2}'`);
echo -e $white"-----------------------------------"
echo "Checking Dropbear login";
echo "-----------------------------------"
for PID in "${data[@]}"
do
	#echo "check $PID";
	NUM=`cat /var/log/auth.log | grep -i dropbear | grep -i "Password auth succeeded" | grep "dropbear\[$PID\]" | wc -l`;
	USER=`cat /var/log/auth.log | grep -i dropbear | grep -i "Password auth succeeded" | grep "dropbear\[$PID\]" | awk '{print $10}'`;
	IP=`cat /var/log/auth.log | grep -i dropbear | grep -i "Password auth succeeded" | grep "dropbear\[$PID\]" | awk '{print $12}'`;
	if [ $NUM -eq 1 ]; then
		echo "$PID - $USER - $IP";
	fi
done

echo "";

data=( `ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'`);
echo "-----------------------------------"
echo "Checking OpenSSH login";
echo "-----------------------------------"
for PID in "${data[@]}"
do
	#echo "check $PID";
	NUM=`cat /var/log/auth.log | grep -i sshd | grep -i "Accepted password for" | grep "sshd\[$PID\]" | wc -l`;
	USER=`cat /var/log/auth.log | grep -i sshd | grep -i "Accepted password for" | grep "sshd\[$PID\]" | awk '{print $9}'`;
	IP=`cat /var/log/auth.log | grep -i sshd | grep -i "Accepted password for" | grep "sshd\[$PID\]" | awk '{print $11}'`;
	if [ $NUM -eq 1 ]; then
		echo "$PID - $USER - $IP";
	fi
done

echo "";

echo "-----------------------------------"
echo "Checking OpenVPN TCP login";
echo "-----------------------------------"
cat /etc/openvpn/server-tcp.log

echo "";

echo "-----------------------------------"
echo "Checking OpenVPN UDP login";
echo "-----------------------------------"
cat /etc/openvpn/server-udp.log

echo "";

echo "-----------------------------------"
echo "Checking PPTP login";
echo "-----------------------------------"
last | grep ppp | grep still

echo "";

#Melihat Riwayat Login User
echo "-----------------------------------"
echo "Checking PPTP Login History";
echo "-----------------------------------"
last | grep ppp

echo "";
echo "----------------------------------------------------------------"
echo " Kalau ada Multi Login Kill Aja "
echo " Tetap Multi Login Ganti Passnya baru Kill Lagi "
echo " Caranya pake Kill nomor PID "
echo "----------------------------------------------------------------"
                                                                                                
cd ~/
