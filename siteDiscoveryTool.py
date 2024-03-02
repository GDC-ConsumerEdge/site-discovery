import os
import platform
import dns.resolver
import yaml
from typing import TextIO
from multiprocessing.pool import ThreadPool
import shutil
import re
from utils import *


class SiteDiscoveryTool:

    def __init__(self):
        # check OS type, currently for windows and linux
        self.osType = platform.system().upper()
        self.osPlatform = platform.platform()
        try:
            assert self.osType in ['WINDOWS', 'LINUX']
        except:
            print(f'[ERROR] {self.osType} NOT supported')
            print(f'[INFO] {self.osPlatform}')
        # check the available shell, get the executable path
        self.shPath = None
        self.shType = None
        self.isRoot = True  # only for Linux
        if self.osType == 'WINDOWS':
            for sh in ['pwsh', 'powershell']:
                self.shPath = shutil.which(sh)
                if self.shPath is not None:
                    self.shType = 'powershell'
                    break
        elif self.osType == 'LINUX':
            if os.geteuid():
                self.isRoot = False
            for sh in ['bash']:
                self.shPath = shutil.which(sh)
                if self.shPath is not None:
                    self.shType = 'bash'
                    break
        try:
            assert self.shType
        except:
            print(f'[ERROR] Cannot find shell on {self.osType}')
            print(f'[INFO] {self.osPlatform}')
            print('[INFO] only Windows powershell and Linux bash are supported')
        self.playbook: dict = {}
        self.threadPool = None
        self.localNetwork = {}
        self.results = {}

    def get_local_network_info(self):
        r"""
        Get the local interface IPv4, default gateway, and DNS server
        dns could be None if not detected
        :return: None. result are saved to self.localNetwork
        """
        self.localNetwork = {'ip': None, 'gw': None, 'dns': None}
        # Windows PowerShell
        if self.shType == 'powershell':
            # Get the IPv4 default gateway.
            # If multiple gw, take the one with the least RouteMetric + InterfaceMetric
            cmd = 'Get-NetRoute -AddressFamily IPv4 0.0.0.0/0'
            lst_gw = os.popen(f'{self.shPath} ({cmd}).NextHop').read().strip().splitlines()
            if len(lst_gw) == 0:
                print(f'[MAJOR] Cannot get local network config => {self.shType}')
                return
            for gw in lst_gw:
                if is_ipv4_unicast(gw):
                    self.localNetwork['gw'] = gw
                    break
            if self.localNetwork['gw'] is None:
                print(f'[MAJOR] Cannot execute command to get local network config => {cmd}')
                return
            lst_if_idx = os.popen(f'{self.shPath} ({cmd}).ifIndex').read().strip().splitlines()
            lst_rm = os.popen(f'{self.shPath} ({cmd}).RouteMetric').read().strip().splitlines()
            lst_im = os.popen(f'{self.shPath} ({cmd}).InterfaceMetric').read().strip().splitlines()
            lst_res = [dict(zip(['gw', 'ifIdx', 'rm', 'im', 'metric'], [a, b, int(c), int(d), int(c) + int(d)])
                            ) for a, b, c, d, in zip(lst_gw, lst_if_idx, lst_rm, lst_im)]
            lst_res.sort(key=lambda x: x['metric'])
            tmp_ret = lst_res[0]
            self.localNetwork['gw'] = tmp_ret['gw']
            # PS pipeline cannot be connected when call from python
            # cmd = ( "Get-NetRoute -AddressFamily IPv4|"
            #         "WHERE {$_.NextHop -ne '0.0.0.0'}|"
            #         "SORT {$_.RouteMetric + $_.interfaceMetric}|"
            #         "SELECT -first 1")

            # get IP of the egress interface towards the default gateway
            cmd = f"Get-NetIPAddress -AddressFamily IPv4 -ifIndex {tmp_ret['ifIdx']} -type UNICAST"
            lst_ip = os.popen(f'{self.shPath} ({cmd}).IPAddress').read().strip().splitlines()
            if len(lst_ip):
                self.localNetwork['ip'] = lst_ip[0]

            # get local DNS Server
            # if ret['gw'] is not None:
            #     cmd = f"(Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex {tmp_ret['ifIdx']})"
            #     lst_dns = os.popen(f'{self.shPath} ({cmd}).ServerAddresses').read().strip().splitlines()
            #     ret['dns'] = [x for x in lst_dns if is_ipv4_unicast(x)]

        # Linux Bash
        elif self.shType == 'bash':
            # check 'netstat', 'route', or 'ip' command
            if shutil.which('ip'):
                # $ ip route show 0.0.0.0/0
                # default via 192.168.0.1 dev ens4 proto dhcp src 192.168.12.215 metric 100
                # $ ip route show 0.0.0.0/0
                # default via 100.115.92.193 dev eth0
                res = os.popen('ip route show 0.0.0.0/0').read().strip().splitlines()
                if len(res):
                    res = res[0].split()[1:]  # exclude the 1st token to make k-v pairs
                    res = dict(zip(*[iter(res)] * 2))
                    # res = dict(zip(res[::2], res[1::2]))
                    if 'src' not in res.keys():
                        # need to get interface ip with 'ip address show <interface name> up', e.g.
                        # $ ip address show eth0 up
                        # 5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
                        #     link/ether 00:16:3e:17:c0:2b brd ff:ff:ff:ff:ff:ff link-netnsid 0
                        #     inet 100.115.92.205/28 brd 100.115.92.207 scope global eth0
                        #        valid_lft forever preferred_lft forever
                        #     inet6 fe80::216:3eff:fe17:c02b/64 scope link
                        #        valid_lft forever preferred_lft forever
                        for line in os.popen(f"ip address show {res['dev']} up").read().splitlines():
                            if re.search('^inet ', line.strip()):
                                ip_str = line.split()[1]
                                if is_ipv4_unicast(ip_str):
                                    res['src'] = ipaddress.IPv4Interface(ip_str).ip.exploded
                                    break
                if 'via' in res.keys():
                    self.localNetwork['gw'] = res['via']
                if 'src' in res.keys():
                    self.localNetwork['ip'] = res['src']
            elif shutil.which('netstat') or shutil.which('route'):
                # $ route -n
                # Kernel IP routing table
                # Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
                # 0.0.0.0         192.168.0.1     0.0.0.0         UG    100    0        0 ens4
                # 192.168.0.1     0.0.0.0         255.255.255.255 UH    100    0        0 ens4
                #
                # $ netstat -rn
                # Kernel IP routing table
                # Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
                # 0.0.0.0         192.168.0.1     0.0.0.0         UG        0 0          0 ens4
                # 192.168.0.1     0.0.0.0         255.255.255.255 UH        0 0          0 ens4
                if shutil.which('netstat'):
                    res = os.popen('netstat -rn').read().splitlines()
                else:
                    res = os.popen('route -n').read().splitlines()
                # pick up the line whose Flags is 'UG'
                res = [x for x in res if x.split()[3] == 'UG']
                if len(res):
                    self.localNetwork['gw'] = res[0].split()[1]

        # use dnspython to get local DNS server config
        rsv = dns.resolver.Resolver()
        ns = [x for x in rsv.nameservers if is_ipv4_unicast(x)]
        if len(ns):
            self.localNetwork['dns'] = ns[0]

    def load_playbook(self, file_stream: TextIO):
        self.playbook = yaml.safe_load(file_stream)
        # yaml.safe_dump(self.playbook, sort_keys=False)

    def bind_thread_pool(self, thread_pool: ThreadPool):
        self.threadPool = thread_pool

    def run_playbook(self):
        if self.threadPool is None:
            self.run_playbook_single_tread()
        else:
            self.run_playbook_multi_thread()

    def verify_dns(self):
        # looking for key 'firewall'
        lst = [x for x in self.playbook.keys() if x.upper() == 'FIREWALL'][0]

    def run_playbook_single_tread(self):
        pass

    def run_playbook_multi_thread(self):
        pass

    def get_dns_result(self):
        pass
