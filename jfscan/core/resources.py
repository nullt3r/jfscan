#!/usr/bin/env python3
import logging
import sqlite3
import ipaddress

from jfscan.core.validator import Validator

class Resources():
    def __init__(self, utils):
        self.logger = logging.getLogger(__name__)
        self.utils = utils
        self.scope_file = None

        try:
            self.conn = sqlite3.connect(":memory:")
        except Exception:
            self.logger.fatal("%s could not create database", bin)
            raise SystemExit(1)

        cur = self.conn.cursor()

        domains_to_scan = "CREATE TABLE domains_to_scan\
             (domain TEXT, ip_rowid INTEGER, UNIQUE(domain, ip_rowid))"

        ips_to_scan = "CREATE TABLE ips_to_scan\
             (ip TEXT, version INTEGER, UNIQUE(ip, version))"

        cidrs_to_scan = "CREATE TABLE cidrs_to_scan\
             (cidr TEXT, version, UNIQUE(cidr, version))"

        scan_results = "CREATE TABLE scan_results\
             (ip TEXT, port INTEGER, protocol TEXT, UNIQUE(ip, port, protocol))"

        cur.execute(domains_to_scan)
        cur.execute(ips_to_scan)
        cur.execute(cidrs_to_scan)
        cur.execute(scan_results)

        self.conn.commit()

    def report_port(self, ip, port, protocol):
        """Reports new port to the database

        Args:
            ip (str): IPv4 or IPv6 address
            port (int): port number
            protocol (str): tcp or udp
        """
        conn = self.conn
        cur = conn.cursor()

        cur.execute(
            "INSERT OR IGNORE INTO\
             scan_results(ip, port, protocol)\
                  VALUES(?, ?, ?)",
            (ip, port, protocol),
        )

        conn.commit()

    def add_cidr(self, cidr):
        """Adds CIDR to the database

        Args:
            cidr (str): IPv6 or IPv4 CIDR
        """
        logger = self.logger
        conn = self.conn
        scope_file = self.scope_file
        cur = conn.cursor()

        # Check if the CIDR is in scope
        if scope_file is not None:
            if self.target_in_scope(cidr) is False:
                logger.warning("%s is out of scope, skipping...", cidr)
                return

        cur.execute(
            "INSERT OR IGNORE INTO cidrs_to_scan(cidr, version) VALUES(?, ?)", (cidr, 4)
        )

        conn.commit()

    def add_domain(self, domain):
        """Adds domain to the database

        Args:
            domain (str): domain name
        """
        utils = self.utils
        ips = utils.resolve_host(domain)

        conn = self.conn
        cur = conn.cursor()

        if ips is None or len(ips) == 0:
            query = "INSERT OR IGNORE INTO domains_to_scan(domain) VALUES(?)"
            cur.execute(query, (domain,))
            conn.commit()

            return

        for ip in ips:
            self.add_ip(ip)

            cur.execute(
                "INSERT OR IGNORE INTO\
                 domains_to_scan(domain, ip_rowid) \
                     VALUES(?, (SELECT rowid FROM ips_to_scan where ip = ?))",
                (domain, ip),
            )

        conn.commit()

    def add_ip(self, ip):
        """Adds IP to database

        Args:
            ip (str): IPv4 or IPv6
        """
        logger = self.logger
        conn = self.conn
        scope_file = self.scope_file
        cur = conn.cursor()

        # Check if the IP is in scope before adding it to the database
        if scope_file is not None:
            if self.target_in_scope(ip) is False:
                logger.warning("%s is out of scope, skipping...", ip)
                return

        query = "INSERT OR IGNORE INTO ips_to_scan(ip, version) VALUES(?, ?)"

        if Validator.is_ipv4(ip):
            cur.execute(query, (ip, 4))
        elif Validator.is_ipv6(ip):
            cur.execute(query, (ip, 6))
        else:
            logger.warning("%s is not an valid IPv4 or IPv6 address, not scanning", ip)

        conn.commit()

    def get_ips(self):
        """Gets all IPs from database

        Returns:
            list: list of IP tuples
        """
        conn = self.conn
        cur = conn.cursor()

        ips = cur.execute("SELECT DISTINCT ip FROM ips_to_scan").fetchall()

        return ips

    def get_results_complex(self):
        """Gets results in complex format

        Returns:
            list: Returns list of lists such is [domain.com, domain-alternative.com], 1.1.1.1, [80, 443]
        """
        conn = self.conn
        cur = conn.cursor()
        ips = cur.execute("SELECT DISTINCT ip FROM scan_results").fetchall()
        results = []
        for ip, in ips:
            ports = cur.execute("SELECT DISTINCT port FROM scan_results WHERE ip = ?", (ip,)).fetchall()
            domains = cur.execute(
                "SELECT domain FROM domains_to_scan\
                 WHERE ip_rowid = (SELECT rowid FROM ips_to_scan WHERE ip = ?)",
                (ip,),
            ).fetchall()

            if len(domains) != 0:
                results.append(
                    ([domain for domain, in domains], ip, [port for port, in ports])
                )
            else:
                results.append(([], ip, [port for port, in ports]))

        return results


    def get_cidrs(self):
        """Gets all CIDRs from the database

        Returns:
            list: Returns list of cidrs in tuple format
        """
        conn = self.conn
        cur = conn.cursor()

        cidrs = cur.execute("SELECT DISTINCT cidr FROM cidrs_to_scan").fetchall()

        return cidrs

    def get_scan_results(self):
        """Generates scan results in format target:port

        Args:
            ips (bool, optional): True to show IP:port. Defaults to False.
            domains (bool, optional): True to show domain:port. Defaults to False.

        Returns:
            list: Returns list in (domain|ip):port format
        """
        conn = self.conn
        cur = conn.cursor()

        ips = []
        domains = []

        rows = cur.execute(
            "SELECT DISTINCT ip, port FROM scan_results"
        ).fetchall()
        for row in rows:
            ips.append(f"{row[0]}:{row[1]}")


        rows = cur.execute(
            "SELECT DISTINCT domain, ip, port FROM scan_results\
                JOIN domains_to_scan ON domain = domains_to_scan.domain WHERE domains_to_scan.ip_rowid = (SELECT rowid FROM ips_to_scan WHERE ip = scan_results.ip) ORDER BY domain"
        ).fetchall()

        for row in rows:
            domains.append(f"{row[0]}:{row[2]}")
        
        ips_unique = list(set(ips))
        domains_unique = list(set(domains))

        ips_unique.sort()
        domains_unique.sort()

        return ips_unique, domains_unique

    def count_ips(self):
        """Get number of all IPs to scan, including IPs in network ranges

        Returns:
            int: Number of IPs in database, including CIDRS
        """
        conn = self.conn
        cur = conn.cursor()
        logger = self.logger

        cidrs = cur.execute("SELECT DISTINCT cidr FROM cidrs_to_scan").fetchall()

        address_count = 0

        for (cidr,) in cidrs:
            if Validator.is_ipv6_cidr(cidr):
                address_count += (2 ** (128 - int(cidr.split("/")[1]))) - 2
            elif Validator.is_ipv4_cidr(cidr):
                address_count += (2 ** (32 - int(cidr.split("/")[1]))) - 2

        ips_count = cur.execute("SELECT count(DISTINCT ip) FROM ips_to_scan").fetchall()

        address_count += ips_count[0][0]

        return address_count

    def count_ports(self):
        """Gets number of discovered ports

        Returns:
            int: Number of ports
        """
        conn = self.conn
        cur = conn.cursor()

        port_count = cur.execute("SELECT count(*) FROM scan_results").fetchall()

        return port_count[0][0]

    def count_alive_ips(self):
        """Gets number of IPs that are "alive" - judging by the open ports

        Returns:
            int: Number of IPs alive
        """
        conn = self.conn
        cur = conn.cursor()

        port_count = cur.execute("SELECT count(DISTINCT ip) FROM scan_results").fetchall()

        return port_count[0][0]

    def target_in_scope(self, target):
        """Function to check if IP or CIDR is in scope (loaded from scope file)

        Args:
            ip (str): IP address or CIDR

        Returns:
            bool: Returns True if IP/CIDR is in scope, False if not
        """

        logger = self.logger
        file_path = self.scope_file

        if self.utils.file_is_empty(file_path):
            logger.fatal(
                "scope file is empty or does not exists: %s",
                file_path,
            )
            raise SystemExit(1)

        with open(file_path, "r", encoding='UTF-8') as scope:
            for scope_item in scope.readlines():

                scope_item = scope_item.strip()

                # If scope item is in CIDR notation
                if Validator.is_ipv6_cidr(scope_item):

                    # If checked target is just IP
                    if Validator.is_ipv6(target):
                        # We just ask if the target is part of network
                        if ipaddress.ip_address(target) in ipaddress.ip_network(scope_item):
                            return True

                    # If checked target is in CIDR notation
                    if Validator.is_ipv6_cidr(target):
                        # We ask if subnet is part of network
                        network = ipaddress.ip_network(scope_item)
                        if network.supernet_of(ipaddress.ip_network(target)) is True:
                            return True

                # If scope item is in CIDR notation
                if Validator.is_ipv4_cidr(scope_item):
                    # If checked target is just IP
                    if Validator.is_ipv4(target):
                        # We just ask if the target is part of network
                        if ipaddress.ip_address(target) in ipaddress.ip_network(scope_item):
                            return True

                    # If checked target is in CIDR notation
                    if Validator.is_ipv4_cidr(target):
                        # We ask if subnet is part of network
                        network = ipaddress.ip_network(scope_item)
                        if network.supernet_of(ipaddress.ip_network(target)) is True:
                            return True

                # If scope item is just IP
                elif target == scope_item:
                    return True

        # By default, we want to return False
        return False
