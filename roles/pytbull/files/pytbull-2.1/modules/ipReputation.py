#!/usr/bin/env python
import ConfigParser
import urllib2

class IpReputation():
    def __init__(self, target, cnf):
        # Read configuration
        self.config = ConfigParser.RawConfigParser()
        self.config.read(cnf)

        self._target = target
        self.payloads = []
        self.lowreputation = []

        # Proxy settings / initialization
        if self.config.get('CLIENT','useproxy')=='1':
            proxyinfo = {
                'proxyuser' : self.config.get('CLIENT','proxyuser'),
                'proxypass' : self.config.get('CLIENT','proxypass'),
                'proxyhost' : self.config.get('CLIENT','proxyhost'),
                'proxyport' : int(self.config.get('CLIENT','proxyport'))
            }
            try:
                # build a new opener that uses a proxy requiring authorization
                proxy_support = urllib2.ProxyHandler({"http" : \
                "http://%(proxyuser)s:%(proxypass)s@%(proxyhost)s:%(proxyport)d" % proxyinfo})
                opener = urllib2.build_opener(proxy_support, urllib2.HTTPHandler)
                # install it
                urllib2.install_opener(opener)
            except Exception, err:
                print "***ERROR in proxy initialization: %s" % err
                print "Check your proxy settings in config.cfg"
                sys.exit()

        iplist = ["103.129.98.17",
                "103.253.73.77",
                "103.83.81.144",
                "104.18.36.98",
                "107.175.64.210",
                "108.171.216.194",
                "110.4.45.119",
                "184.168.221.43",
                "185.104.45.20",
                "185.174.100.116",
                "185.193.38.74",
                "192.138.20.112",
                "217.174.152.68",
                "50.63.202.57",
                "62.173.145.104",
                "69.167.178.28",
                "79.96.191.147",
                "79.98.28.30",
                "85.93.145.251",
                "91.189.114.7",
"94.23.64.40"]
        for ip in iplist:
            if not ip.startswith('\n') and not ip.startswith('//'):
                self.lowreputation.append(ip.split('\n')[0])


    def getPayloads(self):

        for i in range(int(self.config.get('TESTS_PARAMS','ipreputationnbtests'))):
            self.payloads.append([
                "IP Reputation %s" % self.lowreputation[i],
                "scapy",
                """send(IP(src="%s",dst="%s")/TCP(sport=80)/"fake.exe", verbose=0)""" % (self.lowreputation[i], self._target),
                "(?i)rbn"
                ])

        return self.payloads

if __name__ == "__main__":
    print IpReputation("192.168.100.48", 'config.cfg').getPayloads()
