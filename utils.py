import platform
import os
import re
import shutil
from typing import TextIO
from datetime import datetime
from time import ctime
import ipaddress
import socket
import ssl
import dns.resolver
import dns.reversename
import ntplib
from dataclasses import dataclass, field
from http3_client import quic_client_request


class Logger:
    def __init__(self):
        self.output_list = set()

    def get_output_list(self):
        return list(self.output_list)

    def set_output_list(self, lst_output: list):
        self.output_list = set(lst_output)

    def add_output(self, out: TextIO):
        self.output_list |= {out}

    def remove_output(self, out: TextIO):
        self.output_list -= {out}

    def print(self, s: str, timestamp: bool = True, flush: bool = True):
        if timestamp:
            s = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]{s}"
        for o in self.output_list:
            print(s, file=o)
            if flush:
                o.flush()


@dataclass
class VerifyResults:
    bOK: bool = False
    errReason: str = ''
    cmd: str = ''
    response: str = ''
    abstracts: dict = field(default_factory=lambda: {})


def is_ipv4_unicast(ip_str: str) -> bool:
    r"""
    check if the ip string is a valid IPv4 unicast address,
    i.e. not 0, not multicast, not broadcast, not self address
    :param ip_str: ip address
    :return: True-Valid, False-Not Valid
    """
    try:
        ip = ipaddress.IPv4Interface(ip_str)
        ip_high = ipaddress.IPv4Address('224.0.0.0')
        ip_self_low = ipaddress.IPv4Address('127.0.0.0')
        ip_self_high = ipaddress.IPv4Address('127.255.255.255')
        ip_low = ipaddress.IPv4Address('0.0.0.0')
        assert ip_low < ip.ip < ip_self_low or ip_self_high < ip.ip < ip_high
        return True
    except:
        return False


def ping_host(dst_ip: str) -> VerifyResults:
    ret = VerifyResults()
    os_type = platform.system().upper()
    # If Windows system or Linux root user, use icmplib
    if os_type == 'WINDOWS' or (os_type == 'LINUX' and os.seteuid == 0):
        # use icmplib
        try:
            ret = ping_icmplib(dst_ip)
        except:  # maybe icmplib.SocketPermissionError ¯\_(ツ)_/¯
            ret.errReason = 'Failed to run icmplib.ping'
            ret2 = ping_cli(dst_ip)
            if not ret2.bOK:
                ret2.errReason = ret.errReason + '. ' + ret2.errReason
                ret = ret2
    else:  # use ping command
        ret = ping_cli(dst_ip)

    return ret


def ping_icmplib(dst_ip: str) -> VerifyResults:
    ret = VerifyResults()
    ret.abstracts['ip'] = dst_ip
    import icmplib
    cmd = f'icmplib.ping(address={dst_ip}, count=4, interval=0.2, timeout=1, privileged=False)'
    res = icmplib.ping(address=dst_ip, count=4, interval=0.2, timeout=1, privileged=False)
    ret.bOK = res.is_alive
    ret.cmd = cmd
    ret.response = str(res)
    ret.abstracts['loss_perc'] = res.packet_loss * 100
    if not ret.bOK:
        ret.errReason = f'{res.packet_loss * 100:.0f}% packet loss'
    return ret


def ping_cli(dst_ip: str) -> VerifyResults:
    ret = VerifyResults()
    ret.abstracts['ip'] = dst_ip
    os_type = platform.system().upper()
    if shutil.which('ping'):
        if os_type == 'WINDOWS':
            cmd = f'ping -w 1000 -n 4 {dst_ip}'
        elif os_type == 'LINUX':
            cmd = f'ping -i 0.2 -W 1 -c 4 {dst_ip}'
        else:
            ret.errReason = 'Unsupported OS'
            return ret
        res = os.popen(cmd).read()
        ret.cmd = cmd
        ret.response = res
        # Windows Ping Command =>
        # C:\>ping -n 3 -w 1000 8.8.8.8
        #
        # Pinging 8.8.8.8 with 32 bytes of data:
        # Reply from 8.8.8.8: bytes=32 time=2ms TTL=115
        # Reply from 8.8.8.8: bytes=32 time<1ms TTL=115
        # Reply from 8.8.8.8: bytes=32 time<1ms TTL=115
        #
        # Ping statistics for 8.8.8.8:
        #     Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
        # Approximate round trip times in milli-seconds:
        #     Minimum = 0ms, Maximum = 2ms, Average = 0ms
        if os_type == 'WINDOWS':
            g = re.search(r', Lost = \d+ \(([.\d]+)% loss\),', res)
        # Linux Ping Command =>
        # $ ping -i 0.2 -W 1 -c 4 8.8.8.8
        # PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
        # 64 bytes from 8.8.8.8: icmp_seq=1 ttl=55 time=21.8 ms
        # 64 bytes from 8.8.8.8: icmp_seq=2 ttl=55 time=21.9 ms
        # 64 bytes from 8.8.8.8: icmp_seq=3 ttl=55 time=23.2 ms
        # 64 bytes from 8.8.8.8: icmp_seq=4 ttl=55 time=18.3 ms
        #
        # --- 8.8.8.8 ping statistics ---
        # 4 packets transmitted, 4 received, 0% packet loss, time 602ms
        # rtt min/avg/max/mdev = 18.270/21.309/23.240/1.842 ms
        else:  # LINUX
            g = re.search(r',\s*([.\d]+)% packet loss,', res)

        if g:
            ret.abstracts['loss_perc'] = g[1]
            if float(g[1]) <= 50:
                ret.bOK = True  # Packet loss <= 50, consider the dst ip is alive
            else:
                ret.errReason = f'{g[1]}% packet loss'  # Packet loss > 50, consider fail
        else:
            ret.errReason = 'Unexpected command response'  # don't know what happened ¯\_(ツ)_/¯

    else:
        ret.errReason = 'Cannot find ping command'

    return ret


def arp_cli(ip_str: str) -> VerifyResults:
    ret = VerifyResults()
    os_type = platform.system().upper()
    if os_type == 'WINDOWS':
        cmd = 'arp -a'
    elif os_type == 'LINUX':
        cmd = 'arp -n'
    else:
        ret.errReason = 'Unsupported OS'
        return ret
    res = os.popen(cmd).read()
    ret.cmd = cmd
    ret.response = res
    if os_type == 'WINDOWS':
        # C:\>arp -a
        #
        # Interface: 192.168.32.64 --- 0x3
        #   Internet Address      Physical Address      Type
        #   169.254.169.254       42-01-c0-a8-00-01     dynamic
        #   192.168.0.1           42-01-c0-a8-00-01     dynamic
        #   224.0.0.22            01-00-5e-00-00-16     static
        #   224.0.0.251           01-00-5e-00-00-fb     static
        #   224.0.0.252           01-00-5e-00-00-fc     static
        #   239.255.255.250       01-00-5e-7f-ff-fa     static
        #   255.255.255.255       ff-ff-ff-ff-ff-ff     static
        mac_lst = [y[1] for y in [x.split() for x in res.splitlines() if len(x.split()) == 3] if y[0] == ip_str]
    else:  # LINUX
        # $ arp -n
        # Address                  HWtype  HWaddress           Flags Mask            Iface
        # 192.168.0.1              ether   42:01:c0:a8:00:01   C                     ens4
        mac_lst = [y[2] for y in [x.split() for x in res.splitlines() if len(x.split()) == 5] if y[0] == ip_str]
    if len(mac_lst) > 0:
        ret.bOK = True
        ret.abstracts['mac'] = ''.join(re.split('[-:]', mac_lst[0]))

    return ret


def resolve_dns(host: str, dns_svr_lst=None, port: int = 53, proto: str = 'UDP') -> VerifyResults:
    ret = VerifyResults()
    r = dns.resolver.Resolver()
    tcp_flag = True if proto.upper() == 'TCP' else False
    if dns_svr_lst is not None:
        r.nameservers = dns_svr_lst
    r.port = port
    ret.cmd = f"DNS lookup: {host}, Server: {dns_svr_lst if dns_svr_lst else 'host config'}, Port: {port}({proto})"
    ret.abstracts = {
        'host': host,
        'port': port,
        'proto': proto
    }
    if dns_svr_lst:
        ret.abstracts['dns'] = dns_svr_lst
    try:
        answers = r.resolve(qname=host, rdtype=dns.rdatatype.A, tcp=tcp_flag)
        ret.response = '\n'.join([rdata.to_text() for rdata in answers])
        ip_lst = [rdata.to_text() for rdata in answers if is_ipv4_unicast(rdata.to_text())]
        if len(ip_lst):
            ret.abstracts['ip'] = ip_lst
            ret.bOK = True
        else:
            ret.errReason = 'Cannot resolve to IPv4 address'
        # for rdata in answers:
        #     print(type(rdata))
        #     print(rdata.to_text())
    except Exception as e:
        ret.errReason = type(e).__name__
        ret.response = str(e)

    return ret


def reverse_dns(ip_str: str, dns_svr_list=None) -> str:
    ret = ''
    r = dns.resolver.Resolver()
    if dns_svr_list is None:
        dns_svr_list = ['8.8.8.8', '8.8.4.4']
    r.nameservers = dns_svr_list
    n = dns.reversename.from_address(ip_str)
    try:
        answer = r.resolve(qname=n, rdtype=dns.rdatatype.PTR)
        ret = str(answer[0])
    except:
        pass
    return ret


def verify_ntp(ntp_svr: str, svr_ip: str = None) -> VerifyResults:
    ret = VerifyResults()
    if is_ipv4_unicast(ntp_svr):
        ip = ntp_svr
    elif is_ipv4_unicast(svr_ip):
        ip = svr_ip
    else:
        ip = None
    if ip == ntp_svr or ip is None:
        svr_str = ntp_svr
    else:
        svr_str = f'{ntp_svr}<{ip}>'
    ret.cmd = f"ntplib.NTPClient.request({svr_str}, version=4)"
    ret.abstracts['ntp_svr'] = ntp_svr
    if ip:
        ret.abstracts['ntp_svr_ip'] = ip
    ntp_client = ntplib.NTPClient()
    try:
        ntp_reply = ntp_client.request(ip, version=4)
        ret.bOK = True
        ret.abstracts['tx_time'] = ctime(ntp_reply.tx_time)
        ret.abstracts['offset'] = ntp_reply.offset
        ret.abstracts['root_delay'] = ntp_reply.root_delay
        ret.response = ret.abstracts['tx_time']
    except Exception as e:
        ret.errReason = type(e).__name__
        ret.response = str(e)

    return ret


def verify_tcp_connection(ip: str, port: int) -> VerifyResults:
    ret = VerifyResults()
    ret.cmd = f'use socket to connect {ip}:{port}(TCP)'
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    ret.abstracts['host'] = ip
    ret.abstracts['proto'] = 'TCP'
    ret.abstracts['port'] = port
    try:
        s.connect((ip, port))
        ip_port = s.getpeername()
        ret.abstracts['ip'] = ip_port[0]
        ret.bOK = True
    except Exception as e:
        ret.errReason = type(e).__name__
        ret.response = str(e)
    s.settimeout(None)
    return ret


def verify_ssl_connection(host: str, port: int, ip: str = None) -> VerifyResults:
    ret = VerifyResults()
    ret.cmd = f'use ssl to connect {host}:{port}'
    ret.abstracts['host'] = host
    ret.abstracts['port'] = port
    ret.abstracts['proto'] = 'SSL'
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    context = ssl.create_default_context()
    try:
        if (not is_ipv4_unicast(host)) and is_ipv4_unicast(ip):
            s.connect((ip, port))
        else:
            s.connect((host, port))
        ip_port = s.getpeername()
        ret.abstracts['ip'] = ip_port[0]
        ss = context.wrap_socket(s, server_hostname=host)
        ret.bOK = True
        ret.abstracts['proto'] = ss.version()
        s.close()
    except Exception as e:
        ret.errReason = type(e).__name__
        ret.response = str(e)
    # s.settimeout(None)
    return ret


def verify_quic_connection(host: str, port: int) -> VerifyResults:
    ret = VerifyResults()
    ret.cmd = f'use quic to connect {host}:{port}'
    ret.abstracts['host'] = host
    ret.abstracts['port'] = port
    ret.abstracts['proto'] = 'QUIC'
    try:
        res = quic_client_request([f"https://{host}:{port}"], include=True, insecure=True)
        headers = res['headers'][0]
        content = res['contents'][0]
        ret.response = headers + content
        ret.abstracts['http_code'] = None
        g = re.search(r':status:\s*(\d+)', headers)
        if g:
            ret.abstracts['http_code'] = int(g[1])
            ret.bOK = True
    except Exception as e:
        ret.errReason = type(e).__name__
        ret.response = str(e)
    return ret


def parse_range(r: str) -> list:
    """
    used to parse the TCP/UDP port ranges, separated by '-' and ','
    :param r: e.g. 30000, 30004-30006, 31000 => 30000, 30004, 30005, 30006, 31000
    :return: list of number
    """
    ret = []
    for i in r.strip().split(','):
        r2 = i.strip().split('-')
        if len(r2) == 1:
            # a single value
            try:
                ret.append(int(r2[0]))
            except:
                pass
        elif len(r2) == 2:
            # a range
            try:
                low = int(r2[0].strip())
                high = int(r2[1].strip()) + 1
                ret += list(range(low, high))
            except:
                pass
        else:  # 3+ tokens
            # syntax error, play dumb ¯\_(ツ)_/¯
            pass
    return ret
