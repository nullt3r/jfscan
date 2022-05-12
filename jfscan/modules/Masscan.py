import logging
import os

class Masscan:
    def __init__(self, utils):
        self.logger = logging.getLogger(__name__)
        self.utils = utils

        self.rate = None
        self.wait = None
        self.ports = None
        self.top_ports = None
        self.interface = None
        self.router_ip = None
        self.source_ip = None
        self.router_mac = None
        self.router_mac_ipv6 = None

    def run(self, resources):
        """
        Description: Native module for identification of open ports, uses Masscan
        Author: nullt3r

        """
        logger = self.logger
        utils = self.utils

        interface = self.interface
        router_ip = self.router_ip
        source_ip = self.source_ip
        router_mac = self.router_mac
        router_mac_ipv6 = self.router_mac_ipv6
        top_ports = self.top_ports
        ports = self.ports
        rate = self.rate
        wait = self.wait

        logger.info("port scanning using masscan started")

        stream_output = bool(logging.INFO >= logging.root.level)

        ips = resources.get_ips()
        cidrs = resources.get_cidrs()

        if len(ips) == 0 and len(cidrs) == 0:
            logger.error("no resources were given, nothing to scan")
            raise SystemExit

        masscan_input = f"/tmp/_jfscan_{utils.random_string()}"

        with open(masscan_input, "a") as f:
            if len(ips) != 0:
                for (ip,) in ips:
                    f.write(f"{ip}\n")

            if len(cidrs) != 0:
                for (cidr,) in cidrs:
                    f.write(f"{cidr}\n")

        result = utils.handle_command(
            f"masscan{' --wait ' + str(wait) if wait is not None else ''}{' --interface ' + interface if interface is not None else ''}{' --source-ip ' + source_ip if source_ip is not None else ''}{' --router-mac ' + router_mac if router_mac is not None else ''}{' --router-mac-ipv6 ' + router_mac_ipv6 if router_mac_ipv6 is not None else ''}{' --router-ip ' + router_ip if router_ip is not None else ''}{' --ports ' + ports if top_ports is None else ' --top-ports ' + str(top_ports)} --open --max-rate {rate} -iL {masscan_input}",
            stream_output,
        )

        result_stderr = result.stderr.decode("utf-8")

        if "FAIL: could not determine default interface" in result_stderr:
            logger.fatal(
                "could not determine default interface, specify it using --interface <interface for scanning>"
            )
            raise SystemExit

        if "FAIL: scan range too large, max is" in result_stderr:
            logger.fatal(
                "scan range too large, are you trying to scan large IPv6 network?"
            )
            raise SystemExit

        if "FAIL: failed to detect IPv6 address of interface" in result_stderr:
            logger.fatal(
                "are you sure you have IPv6? Try to specify --router-mac-ipv6 <ipv6 router mac address> ($ ip neigh) or --source-ip <your ipv6>"
            )
            raise SystemExit

        if "BIOCSETIF failed: Device not configured" in result_stderr:
            logger.fatal(
                "interface %s does not exists or can't be used for scanning", interface
            )
            raise SystemExit

        if "FAIL: failed to detect IP of interface" in result_stderr:
            logger.fatal("interface %s has no IP address set", interface)
            raise SystemExit

        if (
            "FAIL: ARP timed-out resolving MAC address for router"
            in result_stderr
        ):
            logger.fatal(
                "can't resolve MAC address for router, please specify --router-ip <IP of your router>"
            )
            raise SystemExit
        
        result_stdout = result.stdout.decode("utf-8")

        if "Discovered open port " not in result_stdout:
            logger.info(
                "no open ports were discovered (maybe something went wrong with your connection?)"
            )
            raise SystemExit
        
        for line in result_stdout.splitlines():
            if line.startswith("Discovered open port "):
                items = line.split(" ")

                protocol = items[3].split("/")[1]
                port = items[3].split("/")[0]
                ip = items[5]

                resources.report_port(ip, port, protocol)
