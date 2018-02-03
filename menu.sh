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

while :
do
	#MYIP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
	#if [ "$MYIP" = "" ]; then
		#MYIP=$(wget -qO- ipv4.icanhazip.com)
	#fi

	clear

	echo -e $white"==========================================================="
	echo -e $white">>Fitur Menu Debian 7 - IP VPS Anda: $MYIP "
	echo -e $lightgreen"Edited By : MBAH SHONDONG"
	echo -e $lightgreen"www.mbahshondong.com"
	echo ""
	cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo )
	cores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
	freq=$( awk -F: ' /cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo )
	tram=$( free -m | awk 'NR==2 {print $2}' )
	swap=$( free -m | awk 'NR==4 {print $2}' )
	up=$(uptime|awk '{ $1=$2=$(NF-6)=$(NF-5)=$(NF-4)=$(NF-3)=$(NF-2)=$(NF-1)=$NF=""; print }')

	echo -e $white"CPU model :$cname"
	echo -e $white"Number of cores : $cores"
	echo -e $white"CPU frequency : $freq MHz"
	echo -e $white"Total amount of ram :$tram MB"
	echo -e $white"Total amount of swap :$swap MB"
	echo -e $white"System uptime :$up"
	echo -e $white"---------------------------------"
	echo -e $yellow"Mau Pilih Yang Mana ?"
	echo -e $yellow "1]"$white" Buat Akun SSH/VPN"
	echo -e $yellow "2]"$white" Buat Akun OpenVPN"
	echo -e $yellow "3]"$white" Kunci Akun Nakal"
	echo -e $yellow "4]"$white" Buka Kunci Akun Nakal"
	echo -e $yellow "5]"$white" Buat Akun Acak SSH/OpenVPN"
	echo -e $yellow "6]"$white" Ganti Sandi Akun SSH/OpenVPN"
	echo -e $yellow "7]"$white" Tambah Masa Aktif Akun SSH/OpenVPN"
	echo -e $yellow "8]"$white" Hapus Akun SSH/OpenVPN"
	echo -e $yellow "9]"$white" Buat Akun PPTP VPN"
	echo -e $yellow"10]"$white" Monitoring Dropbear"
	echo -e $yellow"11]"$white" Cek Login Dropbear, OpenSSH, PPTP VPN,OpenVPN"
	echo -e $yellow"12]"$white" Kill Multi Login Manual (1-2 Login)"
	echo -e $yellow"13]"$white" Daftar Semua Akun Aktif dan Kadaluwarsa"
	echo -e $yellow"14]"$white" Daftar Akun Aktif"
	echo -e $yellow"15]"$white" Daftar Akun Kadaluwarsa"
	echo -e $yellow"16]"$white" Matikan Akun Kadaluwarsa"
	echo -e $yellow"17]"$white" Hapus Semua Akun Kadaluwarsa"
	echo -e $yellow"18]"$white" Penggunaan Memori"
	echo -e $yellow"19]"$white" Tes Kecepatan VPS"
	echo -e $yellow"20]"$white" Benchmark"
    echo -e $yellow"21]"$white" Perbarui Script"
	echo -e $yellow"22]"$red" Reboot Server"
	echo ""
	echo -e $white" x) Exit"
	echo ""
	echo     "TTD. Mbah Shondong"
	read -p  "Ketik No Yang Anda Mau,,Tekan Enter √: " option1
	case $option1 in
		1)
		clear
		user-add
		exit
		;;
		2)
		clear
		user-add-vpn
		exit
		;;
		3)
		clear
		user-banned
		exit
		;;
		4)
		clear
		unbanned-user
		exit
		;;
		5)
		clear
		user-gen
		exit
		;;
		6)
		clear
		user-pass
		exit
		;;
		7)
		clear
		user-renew
		exit
		;;
		8)
		clear
		user-del
		exit
		;;
		9)
		clear
		user-add-pptp
		exit
		;;
		10)
		clear
		read -p "Isikan Port Dropbear yang akan dimonitor: " PORT
		dropmon $PORT
		exit
		;;
		11)
		clear
		user-login
		exit
		;;
		12)
		clear
		read -p "Isikan Maximal Login (1-2): " MULTILOGIN
		user-limit $MULTILOGIN
		exit
		;;
		13)
		clear
		user-active-list
		exit
		;;
		14)
		clear
		user-list
		exit
		;;
		15)
		clear
		user-expire-list
		exit
		;;
		16)
		clear
		user-expire
		exit
		;;
		17)
		clear
		delete-user-expire
		exit
		;;
		18)
		clear
		ps-mem
		exit
		;;
		19)
		clear
		speedtest --share
		exit
		;;
		20)
		clear
		benchmark
		exit
       ;;
       21)
       clear
       wget https://raw.githubusercontent.com/Mbah-Shondong/Debian732/master/update.sh
       chmod +x update.sh
      ./update.sh
       exit
		;;
		22)
		clear
		reboot
		exit
		;;
		x)
		clear
		exit
		;;
	esac
done

cd ~/
