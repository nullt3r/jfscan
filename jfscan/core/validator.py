import ipaddress
import validators
import re

class Validator:
    @staticmethod
    def is_ipv6(addr):
        try:
            return type(ipaddress.ip_address(addr)) is ipaddress.IPv6Address
        except:
            return False

    @staticmethod
    def is_ipv4(addr):
        try:
            return type(ipaddress.ip_address(addr)) is ipaddress.IPv4Address
        except:
            return False

    @staticmethod
    def is_ipv6_cidr(addr):
        try:
            return type(ipaddress.ip_network(addr)) is ipaddress.IPv6Network
        except:
            return False

    @staticmethod
    def is_ipv4_cidr(addr):
        try:
            return type(ipaddress.ip_network(addr)) is ipaddress.IPv4Network
        except:
            return False

    @staticmethod
    def is_mac(mac) -> bool:
        is_valid_mac = re.match(r'([0-9A-F]{2}[:]){5}[0-9A-F]{2}|'
                                r'([0-9A-F]{2}[-]){5}[0-9A-F]{2}',
                                string=mac,
                                flags=re.IGNORECASE)
        try:
            return bool(is_valid_mac.group())
        except AttributeError:
            return False

    @staticmethod
    def is_url(url):
        if url.startswith("http://") or url.startswith("https://") is True:
            return True
        return False

    @staticmethod
    def is_domain(domain):
        return validators.domain(domain)