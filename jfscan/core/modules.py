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
        domain, host, port, options = _args

        result = Utils.handle_command(
            f"nmap -Pn {host} -p {port} {options}"
        )

        _stdout = "\n".join(result.stdout.decode("utf-8").splitlines()[1:][:-2]) + "\n"

        print(f"------ {host} ({domain}) ------------------------------------------------------------------\n" + _stdout)


    @classmethod
    def scan_nmap(cls, resources, nmap_options, nmap_threads = 8):
        logging.info("%s: scanning started\n", inspect.stack()[0][3])

        if len(resources.get_domains_ips_and_ports()) == 0:
            logging.error(
                "%s: no resources were given, nothing to scan", inspect.stack()[0][3]
            )
            return

        processPool = multiprocessing.Pool(processes=nmap_threads)
        run = processPool.map(cls._run_single_nmap, [t + (nmap_options, ) for t in resources.get_domains_ips_and_ports()])
        processPool.close()

    @staticmethod
    def scan_masscan(resources, ports, max_rate=30000, top_ports = None):
        """
        Description: Native module for identification of open ports, uses Masscan
        Author: nullt3r

        """
        logging.info("%s: port scanning started", inspect.stack()[0][3])

        if len(resources.get_ips()) == 0 and len(resources.get_cidrs()) == 0:
            logging.error(
                "%s: no resources were given, nothing to scan", inspect.stack()[0][3]
            )
            return
        

        masscan_input = f"._{Utils.random_string()}.tmp"
        masscan_output = f"._{Utils.random_string()}.tmp"

        with open(masscan_input, "a") as f:
            if len(resources.get_ips()) != 0:
                for ip in resources.get_ips():
                    f.write(f"{ip}\n")

            if len(resources.get_cidrs()) != 0:
                for cidr in resources.get_cidrs():
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
                resources.add_port(r["ip"], port["port"])

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
            amass_output = f"._{Utils.random_string()}.tmp"

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