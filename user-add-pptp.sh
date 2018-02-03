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
echo "----------------- MEMBUAT AKUN PPTP VPN ---------------"
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

read -p "Isikan username baru: " USER
read -p "Isikan password akun [$USER]: " PASS

echo "$USER pptpd $PASS *" >> /etc/ppp/chap-secrets

echo ""
echo "-----------------------------------"
echo "Data Login PPTP VPN:"
echo "-----------------------------------"
echo "Host/IP: $MYIP"
echo "Username: $USER"
echo "Password: $PASS"
echo "-----------------------------------"

cd ~/
