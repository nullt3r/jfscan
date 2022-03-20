#!/usr/bin/env python3
import logging
import inspect
import json
import validators
import os
import time
import requests
import multiprocessing

from jfscan.core.utils import Utils


class Modules:
    @staticmethod
    def _run_single_nmap(_args):
        domains, host, ports, options, output = _args

        if len(ports) == 0:
            return

        ports = ",".join(map(str, ports))

        if output is not None:
            _nmap_output = f"/tmp/_jfscan_{Utils.random_string()}.xml"
            result = Utils.handle_command(
                f"nmap --noninteractive -Pn {host} -p {ports} {options} -oX {_nmap_output}"
            )
        else:
            result = Utils.handle_command(
                f"nmap --noninteractive -Pn {host} -p {ports} {options}"
            )

        _stdout = result.stdout.decode("utf-8")

        if "Nmap done: 1 IP address (0 hosts up)" in _stdout:
            logging.error("%s: host %s seems down, your network connection is not able to handle the scanning, are you on WiFi?", inspect.stack()[0][3], host)
        else:
            _stdout = "\r\n".join(_stdout.splitlines()[3:][:-2]) + "\r\n"

            if len(domains) == 0:
                f_host_domain = f" {host} "
            else:
                f_host_domain = f" {host} ({', '.join([domain for domain in domains])}) "
            
            output_in_colors =  _stdout.replace(" open ", "\033[1m\033[92m open \033[0m")
            output_in_colors =  output_in_colors.replace(" filtered ", "\033[1m\033[93m filtered \033[0m")
            output_in_colors =  output_in_colors.replace(" closed ", "\033[1m\033[91m closed \033[0m")

            print("-------" + f_host_domain +  "".join(["-" for s in range(94 - len(f_host_domain))]) + "\n" + _stdout.replace(" open ", "\033[1m\033[92m open \033[0m"))

        if output is not None:
            if Utils.file_is_empty(_nmap_output):
                return None
            else:
                return _nmap_output


    @classmethod
    def scan_nmap(cls, resources, nmap_options, nmap_output = None, nmap_threads = 8):
        logging.info("%s: scanning started\n", inspect.stack()[0][3])

        nmap_input = resources.get_domains_ips_and_ports()

        if len(nmap_input) == 0:
            logging.error(
                "%s: no resources were given, nothing to scan", inspect.stack()[0][3]
            )
            return

        processPool = multiprocessing.Pool(processes=nmap_threads)
        run = processPool.map(cls._run_single_nmap, [target + (nmap_options, nmap_output) for target in nmap_input])
        processPool.close()

        if nmap_output is not None:
            logging.info("%s: generating report %s", inspect.stack()[0][3], nmap_output)

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


    @staticmethod
    def scan_masscan(resources, ports, max_rate=30000, top_ports = None):
        """
        Description: Native module for identification of open ports, uses Masscan
        Author: nullt3r

        """
        logging.info("%s: port scanning started", inspect.stack()[0][3])

        ips = resources.get_ips()
        cidrs = resources.get_cidrs()

        if len(ips) == 0 and len(cidrs) == 0:
            logging.error(
                "%s: no resources were given, nothing to scan", inspect.stack()[0][3]
            )
            raise SystemExit
        

        masscan_input = f"/tmp/_jfscan_{Utils.random_string()}"
        masscan_output = f"/tmp/_jfscan_{Utils.random_string()}"

        with open(masscan_input, "a") as f:
            if len(ips) != 0:
                for ip, in ips:
                    f.write(f"{ip}\n")

            if len(cidrs) != 0:
                for cidr, in cidrs:
                    f.write(f"{cidr}\n")

        if top_ports is not None:
            result = Utils.handle_command(
                f"masscan --open --top-ports {top_ports} --max-rate {max_rate} -iL {masscan_input} -oJ {masscan_output}"
            )
        else:
            result = Utils.handle_command(
                f"masscan --open -p {ports} --max-rate {max_rate} -iL {masscan_input} -oJ {masscan_output}"
            )

        if Utils.file_is_empty(masscan_output):
            logging.error(
                "%s: no output from masscan, something went wrong or no open ports were discovered",
                inspect.stack()[0][3],
            )
            try:
                os.remove(masscan_input)
                os.remove(masscan_output)
            except:
                pass

            raise SystemExit

        with open(masscan_output, "r") as masscan_results:
            masscan_results = json.load(masscan_results)

        for r in masscan_results:
            for port in r["ports"]:
                resources.add_port(r["ip"], port["port"], port["proto"])

        try:
            os.remove(masscan_input)
            os.remove(masscan_output)
        except:
            pass

    @staticmethod
    def enum_crtsh(resources):
        """
        Description: User module for enumerating subdomains via crt.sh API
        Author: nullt3r

        """

        logging.info(
            "%s: running on:\n %s",
            inspect.stack()[0][3],
            ", ".join(resources.get_root_domains()),
        )
        for domain in resources.get_root_domains():
            results = None
            r = None
            for i in range(5):
                try:
                    r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
                except Exception as e:
                    logging.error(
                        "%s: there was an error while reaching the crt.sh: %s", inspect.stack()[0][3], e
                    )
                    continue

                if r.status_code == 502:
                    logging.error(
                        "%s: there was an error while reaching the crt.sh, the server is down...", inspect.stack()[0][3]
                    )
                    time.sleep(5)
                    continue

                try:
                    results = r.json()
                except Exception as e:
                    logging.error(
                        "%s: can't decode JSON data from crt.sh, reason: %s", inspect.stack()[0][3], e
                    )
                    continue

                if results is not None:
                    break

                time.sleep(1)

            if results is None:
                continue

            for subdomain in results:
                if validators.domain(subdomain["name_value"]):
                    resources.add_domain(subdomain["name_value"])

    @staticmethod
    def enum_amass(resources):
        """
        Description: User module for enumerating subdomains using amass tool
        Author: nullt3r

        """

        Utils.check_dependency("amass")

        logging.info(
            "%s: running on:\n %s",
            inspect.stack()[0][3],
            ", ".join(resources.get_root_domains()),
        )

        for domain in resources.get_root_domains():
            amass_output = f"/tmp/_jfscan_{Utils.random_string()}"

            result = Utils.handle_command(
                f"amass enum -d {domain} -ipv4 -v -json {amass_output}"
            )

            if Utils.file_is_empty(amass_output):
                logging.error(
                    "%s: no output from amass, something went wrong",
                    inspect.stack()[0][3],
                )
                try:
                    os.remove(amass_output)
                except:
                    pass
                return

            with open(amass_output, "r") as amass_results:
                for line in amass_results.readlines():
                    output = json.loads(line)
                    if output["name"] is not None and validators.domain(output["name"]):
                        resources.add_domain(output["name"])

                    if (
                        output["addresses"] is not None
                        and len(output["addresses"]) != 0
                    ):
                        for address in output["addresses"]:
                            resources.add_ip(address["ip"], output["name"])
            try:
                os.remove(amass_output)
            except:
                pass
