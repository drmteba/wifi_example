import os
import subprocess
from threading import Thread
from signal import SIGINT
from time import sleep

intfmon = 'wlan0'


class Channel_Hopping(Thread):
    def __init__(self, interface, wait=4):
        Thread.__init__(self)
        Thread.daemon = False
        self.wait = wait
        self.iface = interface
        self.HOPPause = False
        # dwell for 3 time slices on 1 6 11
        # default is 3/10 of a second
        self.channellist = [1, 6, 11, 14, 2, 7, 3, 8, 4, 9, 5, 10,
                            36, 38, 40, 42, 44, 46, 52, 56, 58, 60, 100, 104, 108, 112,
                            116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
        self.hopList = []
        self.check_channels()

    def check_channels(self):
        """ try setting 802.11ab channels first
        this may not work depending on 5ghz dfs
        reverse, so we start with 5ghz channels first"""
        for i in self.channellist:
            try:
                subprocess.run(['iwconfig', self.iface, 'channel', str(i)], check=True)
                check = True
            except subprocess.CalledProcessError:
                os.kill(os.getpid(), SIGINT)
                check = False
            if check:
                self.hopList.append(i)

    @staticmethod
    def Set_Channel(channels):
        print('[*] Switching channel to %s' % channels)
        try:
            subprocess.run(["iwconfig", intfmon, "channel", str(channels)], check=True)
        except subprocess.CalledProcessError:
            print('Could not execute iwconfig!')
            os.kill(os.getpid(), SIGINT)
            return False

    def run(self):
        print("Available channel for hopping")
        print(self.hopList)
        while True:
            if not self.hopList:
                break
            for ch in self.hopList:
                if self.HOPPause:
                    continue
                self.Set_Channel(ch)
                if ch in [1, 6, 11, 13]:
                    sleep(.5)
                else:
                    sleep(.3)


if __name__ == '__main__':
    Channel_Hopping(intfmon).start()
