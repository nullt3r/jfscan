import logging
import os
import json


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

    def run(self, resources):
        """
        Description: Native module for identification of open ports, uses Masscan
        Author: nullt3r

        """
        logger = self.logger
        utils = self.utils

        interface = self.interface
        router_ip = self.router_ip
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
        masscan_output = f"/tmp/_jfscan_{utils.random_string()}"

        with open(masscan_input, "a") as f:
            if len(ips) != 0:
                for (ip,) in ips:
                    f.write(f"{ip}\n")

            if len(cidrs) != 0:
                for (cidr,) in cidrs:
                    f.write(f"{cidr}\n")

        result = utils.handle_command(
            f"masscan{' --wait ' + str(wait) if wait is not None else ''}{' --interface ' + interface if interface is not None else ''}{' --router-ip ' + router_ip if router_ip is not None else ''}{' --ports ' + ports if top_ports is None else ' --top-ports ' + str(top_ports)} --open --max-rate {rate} -iL {masscan_input} -oJ {masscan_output}",
            stream_output,
        )

        if "FAIL: could not determine default interface" in result.stderr.decode(
            "utf-8"
        ):
            logger.error(
                "could not determine default interface, specify it using --interface <interface for scanning>"
            )
            raise SystemExit

        if "BIOCSETIF failed: Device not configured" in result.stderr.decode("utf-8"):
            logger.error(
                "interface %s does not exists or can't be used for scanning", interface
            )
            raise SystemExit

        if "FAIL: failed to detect IP of interface" in result.stderr.decode("utf-8"):
            logger.error("interface %s has no IP address set", interface)
            raise SystemExit

        if (
            "FAIL: ARP timed-out resolving MAC address for router"
            in result.stderr.decode("utf-8")
        ):
            logger.error(
                "can't resolve MAC address for router, please specify --router-ip <IP of your router>"
            )
            raise SystemExit

        if utils.file_is_empty(masscan_output):
            logger.info(
                "no open ports were discovered (maybe something went wrong with your connection?)"
            )
            try:
                os.remove(masscan_input)
                os.remove(masscan_output)
            except:
                pass

            raise SystemExit

        with open(masscan_output, "r") as masscan_results:
            try:
                masscan_results = json.load(masscan_results)
            except Exception as e:
                logger.fatal(
                    "output from masscan is not readable, expected valid json (masscan's bug?):\n%s",
                    e,
                )
                raise SystemExit

        for r in masscan_results:
            for port in r["ports"]:
                resources.add_port(r["ip"], port["port"], port["proto"])

        try:
            os.remove(masscan_input)
            os.remove(masscan_output)
        except:
            pass
