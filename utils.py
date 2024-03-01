import ipaddress


def is_ipv4_unicast(ip_str: str) -> bool:
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
