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
        self.projDir = os.path.dirname(__file__)
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
                    # Requires Powershell Version >= 5
                    if int(os.popen(f'{self.shPath} (Get-Host).Version.Major').read().strip()) >= 5:
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
        self.artefactDir = os.path.join(self.projDir, 'artifacts', self.shType)
        self.playbook = {}
        self.threadPool = None
        self.localNetwork = {}
        self.results = {}
        self.dns_svr_lst = []
        self.logger = None

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
            ps1 = os.path.join(self.artefactDir, 'get_local_network.ps1')
            try:
                gw, ip, dns_svr = os.popen(f'{self.shPath} -F {ps1}').read().splitlines()
            except:
                print(f'[MAJOR] Cannot get local network config => {self.shType}')
                return
            if is_ipv4_unicast(gw):
                self.localNetwork['gw'] = gw
            if is_ipv4_unicast(ip):
                self.localNetwork['ip'] = ip
            if is_ipv4_unicast(dns_svr):
                self.localNetwork['dns'] = dns_svr
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

    def load_playbook(self, file_stream: TextIO) -> bool:
        try:
            self.playbook = yaml.safe_load(file_stream)
            # yaml.safe_dump(self.playbook, sort_keys=False)
        except:
            return False
        return True

    def _get_dns_svr_list(self):
        dns_svr_lst = []
        # print(f'===>0. self.playbook.keys() = {self.playbook.keys()}')
        if 'dns' in self.playbook.keys():
            dns_svr_lst += self.playbook['dns']
        else:
            dns_svr_lst |= ['8.8.8.8', '8.8.4.4']
        # print(f'===>1. dns_svr_lst = {dns_svr_lst}')
        if self.localNetwork['dns'] is not None:
            if self.localNetwork['dns'] not in dns_svr_lst:
                dns_svr_lst.append(self.localNetwork['dns'])
        # print(f'===>2. dns_svr_lst = {dns_svr_lst}')
        self.dns_svr_lst = dns_svr_lst

    def verify_playbook_dns(self):
        if len(self.localNetwork) == 0:
            print('Please call get_local_network_info() first')
            return
        elif len(self.playbook) == 0:
            print('Please call load_playbook() first')
            return
        self._get_dns_svr_list()
        # use qbone-us-east1.google.com as the testing target
        host = 'qbone-us-east1.google.com'
        port = 53
        self.results['dns'] = []
        for svr in self.dns_svr_lst:
            for p in ['UDP', 'TCP']:
                res = resolve_dns(host=host, dns_svr_lst=[svr], port=port, proto=p)
                self.results['dns'].append(res)
                self.log(f"DNS Server {svr}:{port}({p}) => {'OK' if res.bOK else 'FAIL'}")

    def verify_tcp_playbook(self):
        if 'tcp' not in self.playbook.keys():
            return
        for i in self.playbook['tcp']:
            try:
                host, port = i.split(':')
                port = int(port)
            except:
                continue
            res = resolve_dns(host=host, dns_svr_lst=self.dns_svr_lst)
            if res.bOK:
                self.log(f"{host} => {list(res.extracts)}")
                for k, ip in enumerate(res.extracts):
                    con = verify_tcp_connection(ip, port)
                    self.log_result(con)
            else:
                self.log_result(res)

    def bind_logger(self, logger: Logger):
        self.logger = logger

    def log(self, s: str, timestamp: bool = True, flush: bool = True):
        if self.logger is None:
            print(s)
        else:
            self.logger.print(s, timestamp, flush)

    def log_result(self, r: VerifyResults):
        s = r.cmd
        if r.bOK:
            s += ' => OK'
            if len(r.extracts):
                s += f' => {str(r.extracts)}'
        else:
            s += f' => FAIL => {r.errReason}'
        self.log(s)

    def bind_thread_pool(self, thread_pool: ThreadPool):
        self.threadPool = thread_pool

    def run_playbook(self):
        if self.threadPool is None:
            self.run_playbook_single_tread()
        else:
            self.run_playbook_multi_thread()

    def run_playbook_single_tread(self):
        pass

    def run_playbook_multi_thread(self):
        pass

