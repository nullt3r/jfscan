#!/usr/bin/env python3
import logging
import json
import validators
import os
import time
import requests
import multiprocessing

class Modules:
    def __init__(self, utils):
        self.logger = logging.getLogger(__name__)
        self.utils = utils

    def _run_single_nmap(self, _args):
        logger = self.logger
        utils = self.utils

        domains, host, ports, options, interface, output = _args

        if len(ports) == 0:
            return

        if len(ports) > 350:
            logger.error("host %s has %s of open ports, probably firewall messing with us - not scanning", host, len(ports))
            return

        ports = ",".join(map(str, ports))

        if output is not None:
            _nmap_output = f"/tmp/_jfscan_{utils.random_string()}.xml"
            result = utils.handle_command(
                f"nmap {'-e ' + interface if interface is not None else ''} --noninteractive -Pn {host} -p {ports} {options} -oX {_nmap_output}"
            )
        else:
            result = utils.handle_command(
                f"nmap {'-e ' + interface if interface is not None else ''} --noninteractive -Pn {host} -p {ports} {options}"
            )

        if "I cannot figure out what source address to use for device" in result.stderr.decode("utf-8"):
            logger.error(
                "interface does not exists or can't be used for scanning"
            )
            raise SystemExit

        if "Could not find interface" in result.stderr.decode("utf-8"):
            logger.error(
                "interface does not exists or can't be used for scanning"
            )
            raise SystemExit

        _stdout = result.stdout.decode("utf-8")

        if "Nmap done: 1 IP address (0 hosts up)" in _stdout:
            logger.error("host %s seems down now, your network connection is not able to handle the scanning, are you scanning over a wifi?", host)
        else:
            _stdout = "\r\n".join(_stdout.splitlines()[3:][:-2]) + "\r\n"

            if len(domains) == 0:
                f_host_domain = f" {host} "
            else:
                f_host_domain = f" {host} ({', '.join([domain for domain in domains])}) "

            terminal_columns = os.get_terminal_size().columns
            
            if terminal_columns < 93:
                hyphen_count = terminal_columns - 7
            else:
                hyphen_count = 93
            
            output_in_colors =  _stdout.replace(" open ", "\033[1m\033[92m open \033[0m")
            output_in_colors =  output_in_colors.replace(" filtered ", "\033[1m\033[93m filtered \033[0m")
            output_in_colors =  output_in_colors.replace(" closed ", "\033[1m\033[91m closed \033[0m")

            print("-------\033[1m" + f_host_domain + "\033[0m" + "".join(["-" for s in range(hyphen_count - len(f_host_domain))]) + "\n" + output_in_colors)

        if output is not None:
            if utils.file_is_empty(_nmap_output):
                return None
            else:
                return _nmap_output

    def scan_nmap(self, resources, nmap_options, interface = None, nmap_output = None, nmap_threads = 8):
        logger = self.logger

        logger.info("scanning started\n")

        nmap_input = resources.get_domains_ips_and_ports()

        if len(nmap_input) == 0:
            logger.error(
                "no resources were given, nothing to scan"
            )
            return


        processPool = multiprocessing.Pool(processes=nmap_threads)

        run = processPool.map(self._run_single_nmap, [target + (nmap_options, interface, nmap_output) for target in nmap_input])
        processPool.close()


        if nmap_output is not None:
            logger.info("generating report %s", nmap_output)

            host_report = []
            on_first_run = 0

            for xml_report in run:
                if xml_report is None:
                    continue
                with open(xml_report, "r") as thread_output:
                    _reader = thread_output.readlines()

                    if on_first_run == 0:
                        extract_stylesheet =_reader[2].split('"')[1]
                        on_first_run = 1

                    host_report.append("".join(_reader[8:][:-3]))

                    try:
                        os.remove(xml_report)
                    except:
                        pass

            report_header = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="{extract_stylesheet}" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap --noninteractive -Pn -p port {nmap_options} host" start="" startstr="" version="" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="" services=""/>
<verbose level="0"/>
<debugging level="0"/>"""

            report_end = f"""<runstats><finished time="" timestr="" summary="" elapsed="" exit="success"/><hosts up="" down="" total=""/>
</runstats>
</nmaprun>"""

            with open(nmap_output, "w") as output:
                output.write(report_header + "\n".join(host_report) + report_end)


    def scan_masscan(self, resources, ports, max_rate=30000, top_ports = None, interface = None, router_ip = None):
        """
        Description: Native module for identification of open ports, uses Masscan
        Author: nullt3r

        """
        logger = self.logger
        utils = self.utils

        logger.info("port scanning started")

        if logging.INFO >= logging.root.level:
            stream_output = True
        else:
            stream_output = False

        ips = resources.get_ips()
        cidrs = resources.get_cidrs()

        if len(ips) == 0 and len(cidrs) == 0:
            logger.error(
                "no resources were given, nothing to scan"
            )
            raise SystemExit

        masscan_input = f"/tmp/_jfscan_{utils.random_string()}"
        masscan_output = f"/tmp/_jfscan_{utils.random_string()}"

        with open(masscan_input, "a") as f:
            if len(ips) != 0:
                for ip, in ips:
                    f.write(f"{ip}\n")

            if len(cidrs) != 0:
                for cidr, in cidrs:
                    f.write(f"{cidr}\n")

        result = utils.handle_command(
            f"masscan {'--interface ' + interface if interface is not None else ''} {'--router-ip ' + router_ip if router_ip is not None else ''} --open {'--ports ' + ports if top_ports is None else '--top-ports ' + str(top_ports)} --max-rate {max_rate} -iL {masscan_input} -oJ {masscan_output}",
            stream_output
        )

        if "FAIL: could not determine default interface" in result.stderr.decode('utf-8'):
            logger.error(
                "could not determine default interface, specify it using --interface <interface for scanning>"
            )
            raise SystemExit

        if "BIOCSETIF failed: Device not configured" in result.stderr.decode('utf-8'):
            logger.error(
                "interface %s does not exists or can't be used for scanning",
                interface
            )
            raise SystemExit

        if "FAIL: failed to detect IP of interface" in result.stderr.decode("utf-8"):
            logger.error(
                "interface %s has no IP address set", interface
            )
            raise SystemExit

        if "FAIL: ARP timed-out resolving MAC address for router" in result.stderr.decode("utf-8"):
            logger.error(
                "can't resolve MAC address for router, please specify --router-ip <IP of your router>", interface
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
                logger.fatal("output from masscan is not readable, expected valid json (masscan's bug?):\n%s", e)
                raise SystemExit

        for r in masscan_results:
            for port in r["ports"]:
                resources.add_port(r["ip"], port["port"], port["proto"])

        try:
            os.remove(masscan_input)
            os.remove(masscan_output)
        except:
            pass

