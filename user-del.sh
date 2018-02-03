# go to root
cd

echo -e $yellow""
echo "------------------ HAPUS AKUN SSH/VPN -----------------" | lolcat
echo ""
echo "#######################################################" | lolcat
echo "#                SCRYPT MBAH SHONDONG                 #" | lolcat
echo "#            http://www.mbahshondong.com              #" | lolcat
echo "#-----------------------------------------------------#" | lolcat
echo "#                     HAWOK JOZZ                      #" | lolcat
echo "#      https://www.facebook.com/groups/pokoemelu      #" | lolcat
echo "#-----------------------------------------------------#" | lolcat
echo "#         [== INTERNET GRATIS SAK MODARRE ==]         #" | lolcat
echo "#######################################################" | lolcat
echo -e $White""            

# begin of user-list
echo -e $lightgreen"-----------------------------------" | lolcat
echo "USERNAME              EXP DATE     " | lolcat
echo "-----------------------------------" | lolcat

while read expired
do
	AKUN="$(echo $expired | cut -d: -f1)"
	ID="$(echo $expired | grep -v nobody | cut -d: -f3)"
	exp="$(chage -l $AKUN | grep "Account expires" | awk -F": " '{print $2}')"
	if [[ $ID -ge 1000 ]]; then
		printf "%-21s %2s\n" "$AKUN" "$exp"
	fi
done < /etc/passwd
echo "-----------------------------------"
echo ""
# end of user-list

read -p "Isikan username: " USER

egrep "^$USER" /etc/passwd >/dev/null
if [ $? -eq 0 ]; then
	echo ""
	read -p "Apakah Anda benar-benar ingin menghapus akun [$USER] [y/n]: " -e -i y REMOVE
	if [[ "$REMOVE" = 'y' ]]; then
		userdel $USER
		echo ""
		echo "Akun [$USER] berhasil dihapus!"
	else
		echo ""
		echo "Penghapusan akun [$USER] dibatalkan!"
	fi
else
	echo "Username [$USER] belum terdaftar!"
	exit 1
fi

cd ~/
