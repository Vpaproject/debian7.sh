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
echo "---------- DAFTAR AKUN AKTIF DAN KADALUWARSA ----------"
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
echo "-------------------------------------------------------"

echo "USERNAME                EXP DATE     "
echo "-------------------------------------------------------"
cat /root/expireduser.txt
cat /root/activeuser.txt
echo ""
JUMLAH="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"

echo "-------------------------------------------------------"
echo "Jumlah Akun : $JUMLAH Akun"
echo "-------------------------------------------------------"
echo ""
                
cd ~/
