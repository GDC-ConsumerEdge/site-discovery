# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import yaml
import subprocess
import csv
import dns.resolver
from prettytable import PrettyTable
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
                    cmd = [self.shPath, '-Command', '(Get-Host).Version.Major']
                    res = subprocess.run(cmd, capture_output=True, text=True,check=True).stdout.strip()
                    try:
                        if int(res) >= 5:
                            self.shType = 'powershell'
                            break
                        else:
                            raise
                    except:
                        print(f'[WARN] Powershell version 5 is required, got {res}')
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
            print(f'System shell path is {self.shPath}')
        except:
            print(f'[ERROR] Cannot find shell on {self.osType}')
            print(f'[INFO] {self.osPlatform}')
            print('[INFO] only Windows powershell and Linux bash are supported')
            raise
        self.artefactDir = os.path.join(self.projDir, 'artifacts', self.shType)
        self.playbook = {}
        self.dns_mapper: GdceDnsMap | None = None
        self.iprr: GdceIpNetRanges | None = None
        self.localNetwork = {}
        self.results = {}
        self.dns_svr_lst = []
        self.logger = None
        self.reporter = sys.stdout

    def load_playbook(self, file_stream: TextIO) -> bool:
        try:
            self.playbook = yaml.safe_load(file_stream)
            # yaml.safe_dump(self.playbook, sort_keys=False)
        except:
            return False
        return True

    def load_dns_mapper(self, file_name: str) -> bool:
        try:
            self.dns_mapper = GdceDnsMap(file_name)
        except:
            return False
        return True

    def load_ip_address_ranges(self, file_name: str) -> str:
        try:
            self.iprr = GdceIpNetRanges(file_name)
        except:
            return False
        return True

    def get_local_network_info(self):
        r"""
        Get the local interface IPv4, default gateway, and DNS server
        dns could be None if not detected
        :return: None. result are saved to self.localNetwork
        """
        self.localNetwork = {'ip': None, 'gw': None, 'dns': None, 'intf_name': None}
        # Windows PowerShell
        if self.shType == 'powershell':
            # Get the IPv4 default gateway.
            # If multiple gw, take the one with the least RouteMetric + InterfaceMetric
            ps1 = os.path.join(self.artefactDir, 'get_local_network.ps1')
            r = VerifyResults()
            r.cmd = [self.shPath, "-File", ps1]
            try:
                r.response = subprocess.run(r.cmd, capture_output=True, text=True,check=True).stdout
                gw, ip, dns_svr, intf_name = r.response.splitlines()
                r.bOK = True
                self.log_result(r)
            except Exception as e:
                r.errReason = 'Cannot get local network config'
                self.log_result(r)
                print(f'[MAJOR] Cannot get local network config => {self.shType}')
                return
            if is_ipv4_unicast(gw):
                self.localNetwork['gw'] = gw
            if is_ipv4_unicast(ip):
                self.localNetwork['ip'] = ip
            if is_ipv4_unicast(dns_svr):
                self.localNetwork['dns'] = dns_svr
            self.localNetwork['intf_name'] = intf_name
        # Linux Bash
        elif self.shType == 'bash':
            # check 'netstat', 'route', or 'ip' command
            if shutil.which('ip'):
                # $ ip route show 0.0.0.0/0
                # default via 192.168.0.1 dev ens4 proto dhcp src 192.168.12.215 metric 100
                # $ ip route show 0.0.0.0/0
                # default via 100.115.92.193 dev eth0
                r = VerifyResults()
                r.cmd = 'ip route show 0.0.0.0/0'
                r.response = os.popen(r.cmd).read()
                res = r.response.strip().splitlines()
                if len(res):
                    r.bOK = True
                self.log_result(r)
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
                        r2 = VerifyResults()
                        r2.cmd = f"ip address show {res['dev']} up"
                        r2.response = os.popen(r2.cmd).read()
                        for line in r2.response.splitlines():
                            if re.search('^inet ', line.strip()):
                                ip_str = line.split()[1]
                                if is_ipv4_unicast(ip_str):
                                    res['src'] = ipaddress.IPv4Interface(ip_str).ip.exploded
                                    r2.bOK = True
                                    break
                        self.log_result(r2)
                if 'via' in res.keys():
                    self.localNetwork['gw'] = res['via']
                if 'src' in res.keys():
                    self.localNetwork['ip'] = res['src']
                if 'dev' in res.keys():
                    self.localNetwork['intf_name'] = res['dev']
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
                r3 = VerifyResults()
                if shutil.which('netstat'):
                    r3.cmd = 'netstat -rn'
                else:
                    r3.cmd = 'route -n'
                r3.response = os.popen(r3.cmd).read()
                res = r3.response.splitlines()
                # pick up the line whose Flags is 'UG'
                res = [x for x in res if x.split()[3] == 'UG']
                if len(res):
                    tokens = res[0].split()
                    if len(tokens) > 1:
                        self.localNetwork['gw'] = tokens[1]
                    if len(tokens) > 7:
                        self.localNetwork['intf_name'] = tokens[7]
                    r3.bOK = True
                self.log_result(r3)

        # use dnspython to get local DNS server config
        r = VerifyResults()
        r.cmd = 'dns.resolver.Resolver().nameservers'
        rsv = dns.resolver.Resolver()
        r.response = rsv.nameservers
        ns = [x for x in rsv.nameservers if is_ipv4_unicast(x)]
        if len(ns):
            r.bOK = True
            self.localNetwork['dns'] = ns[0]
        self.log_result(r)

    def verify_gateway(self) -> bool:
        ret = False
        if self.localNetwork['gw']:
            if 'gw' not in self.results.keys():
                self.results['gw'] = []
            ping_res = ping_host(self.localNetwork['gw'])
            arp_res = arp_cli(self.localNetwork['gw'])
            mac = 'FAIL'
            if arp_res.bOK:
                mac = arp_res.abstracts['mac']
            self.results['gw'].append({
                'ip': self.localNetwork['gw'],
                'ping': 'PASS' if ping_res.bOK else 'FAIL',
                'mac': mac
            })
            ret = ping_res.bOK and arp_res.bOK
        return ret

    def _get_dns_svr_list(self):
        dns_svr_lst = []
        if 'dns' in self.playbook.keys():
            dns_svr_lst += self.playbook['dns']
        if self.localNetwork['dns'] is not None:
            if self.localNetwork['dns'] not in dns_svr_lst:
                dns_svr_lst.append(self.localNetwork['dns'])
        # if no DNS server is configured nor configured/detect, using google dns servers
        if len(dns_svr_lst) == 0:
            dns_svr_lst = ['8.8.8.8', '8.8.4.4']
        self.dns_svr_lst = dns_svr_lst

    def verify_playbook_dns(self) -> bool:
        if len(self.localNetwork) == 0:
            print('Please call get_local_network_info() first')
            return False
        elif len(self.playbook) == 0:
            print('Please call load_playbook() first')
            return False
        self._get_dns_svr_list()
        try:
            assert len(self.dns_svr_lst) > 0
        except:
            return False
        # use qbone-us-east1.google.com as the testing target
        host = 'qbone-us-east1.google.com'
        port = 53
        self.results['dns'] = []
        ret = True
        for svr in self.dns_svr_lst:
            for p in ['UDP', 'TCP']:
                res = resolve_dns(host=host, dns_svr_lst=[svr], port=port, proto=p)
                self.results['dns'].append(res)
                self.log_result(res)
                if not res.bOK:
                    ret = False
        return ret

    def verify_playbook_ntp(self) -> bool:
        if 'ntp' not in self.playbook.keys():
            return False
        for ntp in self.playbook['ntp']:
            if 'ntp' not in self.results.keys():
                self.results['ntp'] = []
            ntp = ntp.strip()
            if not is_ipv4_unicast(ntp):  # resolve to ip, could be a list of ip
                res = resolve_dns(host=ntp, dns_svr_lst=self.dns_svr_lst)
                self.log_result(res)
                if res.bOK:
                    for ip in res.abstracts['ip']:
                        ntp_res = verify_ntp(ntp_svr=ntp, svr_ip=ip)
                        self.log_result(ntp_res)
                        self.results['ntp'].append(ntp_res)
                        self.iprr.record_tested_net(ip)
                else:
                    ntp_res = VerifyResults()
                    ntp_res.bOK = False
                    ntp_res.errReason = 'DNS Error'
                    ntp_res.abstracts = {'ntp_svr': ntp}
                    self.results['ntp'].append(ntp_res)
            else:  # ntp server is an IP, not need to resolve
                ntp_res = verify_ntp(ntp_svr=ntp)
                self.log_result(ntp_res)
                self.results['ntp'].append(ntp_res)
        ret = False
        if 'ntp' in self.results.keys():
            ret = True
            for res in self.results['ntp']:
                if not res.bOK:
                    ret = False
                    break
        return ret

    def verify_playbook_connection(self):
        for proto in ['tcp', 'ssl']:
            if proto not in self.playbook.keys():
                continue
            if proto not in self.results.keys():
                self.results[proto] = []
            total = len(self.playbook[proto])
            print(f'Verifying {proto.upper()} connections ... 0/{total}', end='')
            for i, line in enumerate(self.playbook[proto]):
                print(f'\rVerifying {proto.upper()} connections ... {i+1}/{total}', end='')
                try:
                    ori_host, port = line.split(':')
                    port = int(port)
                except:
                    continue
                # check if this host is bind to GDC endpoionts
                host = self.dns_mapper.map_dns(ori_host)
                if host != ori_host.lower():
                    # this generic google endpoint is mapped to gdc endpoint
                    res2 = VerifyResults(bOK=True, cmd=f'Rewrite endpoint {ori_host}', response=host)
                    self.log_result(res2)
                res = resolve_dns(host=host, dns_svr_lst=self.dns_svr_lst)
                self.log_result(res)
                if res.bOK:
                    for ip in res.abstracts['ip']:
                        if proto == 'tcp':
                            con = verify_tcp_connection(ip, port)
                            con.abstracts['host'] = ori_host
                        else:
                            con = verify_ssl_connection(ori_host, port, ip)
                        # check if ip address is in the IPRR range
                        if con.bOK and (not self.iprr.is_in_range(ip)):
                            con.bOK = False
                            con.errReason = 'Not in IPRR range'
                        self.log_result(con)
                        self.results[proto].append(con)
                        self.iprr.record_tested_net(ip)
                else:
                    con = VerifyResults()
                    con.abstracts['host'] = ori_host
                    con.abstracts['proto'] = proto.upper()
                    con.abstracts['port'] = port
                    con.errReason = 'DNS Error'
                    self.results[proto].append(con)
            print(f'\rVerifying {proto.upper()} connections ... {total}/{total}')

    def verify_playbook_qbone(self):
        proto = 'qbone'
        if proto not in self.playbook.keys():
            return False
        if proto not in self.results.keys():
            self.results[proto] = []
        total = len(self.playbook[proto])
        print(f'Verifying {proto.upper()} connections ... 0/{total}', end='')
        for i, line in enumerate(self.playbook[proto]):
            print(f'\rVerifying {proto.upper()} connections ... {i + 1}/{total}', end='')
            try:
                host, port = line.split(':')
                port = int(port)
            except:
                continue
            con = verify_quic_connection(host, port)
            self.log_result(con)
            self.results[proto].append(con)
            for ip_str in con.abstracts['ip']:
                self.iprr.record_tested_net(ip_str)
        print(f'\rVerifying {proto.upper()} connections ... {total}/{total}')

    def bind_logger(self, logger: Logger):
        self.logger = logger

    def log(self, s: str, timestamp: bool = True, flush: bool = True):
        if self.logger is None:
            print(s)
        else:
            self.logger.print(s, timestamp, flush)

    def log_result(self, r: VerifyResults):
        s = '-' * 60
        s += f'''
<cmd>{r.cmd}
<pass/fail> {'PASS' if r.bOK else 'FAIL'}
<response>{r.response}
<error>{r.errReason}
<extra>{r.abstracts}'''
        self.log(s)

    def bind_reporter(self, reporter: TextIO):
        self.reporter = reporter

    def create_report(self):
        self.print_local_network_table()
        self.print_gateway_table()
        self.print_dns_table()
        self.print_ntp_table()
        self.print_session_table('tcp')
        # self.print_session_table('udp')
        self.print_session_table('ssl')
        self.print_qbone_table()
        self.print_iprr_table()

    def print_local_network_table(self):
        table = PrettyTable()
        table.field_names = ["Interface", "Local IP", "Gateway", "Local DNS"]
        table.add_row([
            self.localNetwork['intf_name'],
            self.localNetwork['ip'],
            self.localNetwork['gw'],
            self.localNetwork['dns']
        ])
        print('Host Network Config', file=self.reporter)
        print(table, file=self.reporter)
        print('', file=self.reporter)

    def print_gateway_table(self):
        if 'gw' not in self.results.keys():
            return
        table = PrettyTable()
        table.field_names = ["Default Gateway", "Ping", "ARP"]
        for res in self.results['gw']:
            table.add_row([res['ip'], res['ping'], res['mac']])
        print('Default Gateway Verification', file=self.reporter)
        print(table, file=self.reporter)
        print('', file=self.reporter)

    def print_dns_table(self):
        if 'dns' not in self.results.keys():
            return
        table = PrettyTable()
        table.field_names = ['P/F', "DNS Server IP", "Port", "Proto", 'Target Hostname']
        # reg = re.compile(r'DNS lookup: ([.\w]+), Server: \[([^]]+)], Port: (\d+)\((\d+)\)')
        for res in self.results['dns']:
            # g = reg.search(res.cmd)
            table.add_row([
                'PASS' if res.bOK else 'FAIL',
                res.abstracts['dns'][0],
                res.abstracts['port'],
                res.abstracts['proto'],
                res.abstracts['host']
            ])
        print('DNS Server Verification', file=self.reporter)
        table.align["DNS Server IP"] = "l"
        table.align["Target Hostname"] = "l"
        print(table, file=self.reporter)
        print('', file=self.reporter)

    def print_ntp_table(self):
        if 'ntp' not in self.results.keys():
            return
        table = PrettyTable()
        table.field_names = ['P/F', 'Host', 'Resolved IP', 'TX Time', 'Err Msg']
        for res in self.results['ntp']:
            table.add_row([
                'PASS' if res.bOK else 'FAIL',
                res.abstracts['ntp_svr'],
                res.abstracts['ntp_svr_ip'] if 'ntp_svr_ip' in res.abstracts.keys() else '',
                res.abstracts['tx_time'] if res.bOK else '',
                res.errReason
            ])
        print('NTP Server Verification', file=self.reporter)
        table.align["HOST"] = "l"
        table.align["Resolved IP"] = "l"
        table.align["TX Time"] = "l"
        table.align["Err Msg"] = "l"
        print(table, file=self.reporter)
        print('', file=self.reporter)

    def print_session_table(self, name: str):
        if name not in self.results.keys():
            return
        table = PrettyTable()
        table.field_names = ['P/F', "Host", "Port", "Proto", 'Resolved IP', 'Err Msg']
        for res in self.results[name]:
            table.add_row([
                'PASS' if res.bOK else 'FAIL',
                res.abstracts['host'],
                res.abstracts['port'],
                res.abstracts['proto'],
                res.abstracts['ip'] if 'ip' in res.abstracts.keys() else '',
                res.errReason
            ])
            # print(type(res.abstracts['host']))
        print(f'{name.upper()} Connection Verification', file=self.reporter)
        table.align["HOST"] = "l"
        table.align["Resolved IP"] = "l"
        table.align["Err Msg"] = "l"
        print(table, file=self.reporter)
        print('', file=self.reporter)

    def print_qbone_table(self):
        if 'qbone' not in self.results.keys():
            return
        table = PrettyTable()
        table.field_names = ['P/F', "Host", "IP", "Port", "Proto", "HTTP CODE", 'Err Msg']
        for res in self.results['qbone']:
            table.add_row([
                'PASS' if res.bOK else 'FAIL',
                res.abstracts['host'],
                ','.join(res.abstracts['ip']),
                res.abstracts['port'],
                res.abstracts['proto'],
                res.abstracts['http_code'] if 'http_code' in res.abstracts.keys() else '',
                res.errReason
            ])
            # print(type(res.abstracts['host']))
        print(f'Qbone Connection Verification', file=self.reporter)
        table.align["HOST"] = "l"
        table.align["IP"] = "l"
        table.align["Err Msg"] = "l"
        print(table, file=self.reporter)
        print('', file=self.reporter)

    def print_iprr_table(self):
        table = PrettyTable()
        table.field_names = ['IPRR Network Range', "Test Covered"]
        for net_range in self.iprr.net_ranges:
            table.add_row([net_range['net_str'], net_range['tested']])
        print(f'IPRR Network Range Coverage', file=self.reporter)
        table.align["IPRR Network Range"] = "l"
        table.align["Test Covered"] = "c"
        print(table, file=self.reporter)
        print('', file=self.reporter)
