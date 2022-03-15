#!/usr/bin/env python3
import logging
import inspect
import tldextract

from jfscan.core.utils import Utils

class Resources:
    def __init__(self):
        self.resources = []
        self.cidrs = []
        self.excluded = []

    def add_domain(self, domain):
        ips = Utils.resolve_host(domain)
        resources = self.resources
        for r in resources:
            if r.get("domain") == domain and domain is not None:
                return

        if ips is not None:
            self.resources.append(
                {
                    "domain": domain,
                    "tcp": [{"ip": address, "ports": []} for address in ips],
                }
            )
        else:
            self.resources.append(
                {
                    "domain": domain,
                    "tcp": [],
                }
            )

    def add_cidr(self, cidr):
        if cidr is not None:
            self.cidrs.append(cidr)

    def add_ip(self, ip, domain=None):
        resources = self.resources
        for r in resources:
            if r.get("domain") == domain and domain is not None:
                r["tcp"].append({"ip": ip, "ports": []})
                break
        else:
            self.resources.append(
                {
                    "domain": domain,
                    "tcp": [{"ip": ip, "ports": []}],
                }
            )

    def add_port(self, ip, port):
        resources = self.resources
        """
        If the list is yet empty, lets create the structure.
        """
        if len(resources) == 0:
            self.resources.append(
                {
                    "domain": None,
                    "tcp": [{"ip": ip, "ports": [port]}],
                }
            )
            return

        for r in resources:
            for tcp in r.get("tcp"):
                if ip in tcp["ip"]:
                    tcp["ports"].append(port)
                    return
        """
        In case the IP does not already exists in the object, just add a new one.
        """
        self.resources.append(
            {
                "domain": None,
                "tcp": [{"ip": ip, "ports": [port]}],
            }
        )
    
        

    def get_ips(self):
        addresses = []
        for r in self.resources:
            for tcp in r.get("tcp"):
                addresses.append(tcp["ip"])
        return list(set(addresses))

    def get_domains_ips_and_ports(self):
        results = []
        for resource in self.resources:
            for tcp in resource.get("tcp"):
                for port in tcp.get("ports"):
                    results.append((resource.get('domain'), tcp['ip'], port))

        return list(set(results))

    def get_cidrs(self):
        if self.cidrs is not None and len(self.cidrs) != 0:
            return list(set(self.cidrs))
        else:
            return []

    def get_root_domains(self):
        domains = []
        for r in self.resources:
            try:
                parse = tldextract.extract(r.get("domain"))
            except:
                pass
            domains.append(f"{parse.domain}.{parse.suffix}")
        return list(set(domains))

    def get_all_domains(self):
        domains = []
        for r in self.resources:
            domains.append(r.get("domain"))
        return list(set(domains))

    def get(self):
        return self.resources

    def get_list(self, ips = False, domains = False):
        results = []
        for resource in self.resources:
            for tcp in resource.get("tcp"):
                if len(tcp.get("ports")) > 30:
                    if Utils.detect_firewall(tcp["ip"]):
                        logging.info(
                            "%s: firewall detected, excluding host %s",
                            inspect.stack()[0][3],
                            tcp["ip"],
                        )
                        self.excluded.append(tcp["ip"])
                    continue
                for port in tcp.get("ports"):
                    if domains == True:
                        if resource.get("domain") is not None:
                            results.append(f"{resource.get('domain')}:{port}")
                    if ips == True:
                        results.append(f"{tcp['ip']}:{port}")


        return list(set(results))