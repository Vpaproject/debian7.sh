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

if [ $1 ]; then
	port_dropbear=$1
	log=/var/log/auth.log
	loginsukses='Password auth succeeded'
	echo ' '
	echo -e $cyan' '
	echo "               Dropbear Users Login Monitor                    "
	echo "---------------------------------------------------------------"
	echo "    Date-time    |  PID      |  User Name      |  From Host    "
	echo "---------------------------------------------------------------" 
	echo -e $white' '
	pids=`ps ax |grep dropbear |grep  " $port_dropbear" |awk -F" " '{print $1}'`
	for pid in $pids
	do
		pidlogs=`grep $pid $log |grep "$loginsukses" |awk -F" " '{print $3}'`
		i=0
		for pidend in $pidlogs
		do
			let i=i+1
		done
		
		if [ $pidend ]; then
			login=`grep $pid $log |grep "$pidend" |grep "$loginsukses"`
			PID=$pid
			user=`echo $login |awk -F" " '{print $10}' | sed -r "s/'/ /g"`
			waktu=`echo $login |awk -F" " '{print $2,$3}'`
			while [ ${#waktu} -lt 13 ]
			do
				waktu=$waktu" "
			done
			
			while [ ${#user} -lt 16 ]
			do
				user=$user" "
			done
			
			while [ ${#PID} -lt 8 ]
			do
				PID=$PID" "
			done

			fromip=`echo $login |awk -F" " '{print $12}' |awk -F":" '{print $1}'`
			echo "  $waktu|  $PID | $user|  $fromip "
		fi
	done
	
	echo -e $lightgreen""
	echo "------------------------------------------------------"
	echo " Ingin tendang user? Ketik kill -9 (angka PID)"
	echo " Misal: kill -9 1234 [enter]"
	echo "-------------------------------------------------------"
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
	echo ""
	echo "-------------------------------------------------------"
	echo ""
else
	echo "  Gunakan perintah ./dropmon [port]"
	echo "  Contoh : ./dropmon 443"
	echo ""
fi

exit 0

cd ~/
