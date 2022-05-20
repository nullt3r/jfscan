#!/usr/bin/env python3
import logging
import os
import multiprocessing


class Nmap:
    def __init__(self, utils):
        self.logger = logging.getLogger(__name__)
        self.utils = utils

        self.interface = None
        self.options = None
        self.output = None
        self.threads = 8

    def _run_single_nmap(self, _args):
        utils = self.utils

        from jfscan.core.validator import Validator
        from jfscan.core.logging_formatter import CustomFormatter

        logger = logging.getLogger()
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(CustomFormatter())
        logger.addHandler(stream_handler)

        domains, host, ports, options, interface, output = _args

        if len(ports) == 0:
            return

        if len(ports) > 350:
            logger.warning(
                "host %s has %s of open ports, probably firewall messing with us - not scanning",
                host,
                len(ports),
            )
            return

        ports = ",".join(map(str, ports))
        stdout_buffer = ""

        if output is not None:
            nmap_output = '/tmp/_jfscan_' + utils.random_string() + '.xml'

        result = utils.handle_command(
            f"nmap{' -e ' + interface if interface is not None else ''}{' -6 ' if Validator.is_ipv6(host) is True else ''} --noninteractive -Pn {host} -p {ports}{' '+options if options is not None else ''}{' -oX ' + nmap_output if output is not None else ''}"
        )

        result_stdout = result.stdout.decode("utf-8")
        result_stderr = result.stderr.decode("utf-8")

        if (
            "I cannot figure out what source address to use for device"
            in result_stderr
        ):
            logger.fatal("interface does not exists or can't be used for scanning")
            raise SystemExit(1)

        if "Could not find interface" in result_stderr:
            logger.fatal("interface does not exists or can't be used for scanning")
            raise SystemExit(1)

        if len(domains) == 0:
            f_host_domain = f" {host} "
        else:
            f_host_domain = f" {host} ({', '.join([domain for domain in domains])}) "

        stdout_buffer += "┌──────\033[1m" + f_host_domain + "\033[0m\n"
        stdout_buffer += "│"

        if (
            "Nmap done: 1 IP address (0 hosts up)" in result_stdout
            or result.returncode != 0
        ):
            stdout_buffer += "Host is down.\n\n"

            logger.error("Host %s seems down, but was up while scanning with the masscan, maybe your network connection is not able to handle the scanning, \nare you scanning over a wifi? Try VPS or ethernet instead.\n\n", host)
        else:
            nmap_stdout = "\n│ ".join(result_stdout.splitlines()[3:][:-2]) + "\n"

            output_in_colors = nmap_stdout.replace(
                " open ", "\033[1m\033[92m open \033[0m"
            )
            output_in_colors = output_in_colors.replace(
                " filtered ", "\033[1m\033[93m filtered \033[0m"
            )
            output_in_colors = output_in_colors.replace(
                " closed ", "\033[1m\033[91m closed \033[0m"
            )

            stdout_buffer += output_in_colors

        print(stdout_buffer)

        if output is not None:
            if utils.file_is_empty(nmap_output):
                return None

            return nmap_output

    def run(self, resources):
        logger = self.logger

        threads = self.threads
        options = self.options
        interface = self.interface
        output = self.output

        logger.info("service discovery using nmap started\n")

        nmap_input = resources.get_results_complex()

        if len(nmap_input) == 0:
            logger.error("no resources were given, nothing to scan")
            return

        process_pool = multiprocessing.Pool(processes=threads)
        run = process_pool.map(
            self._run_single_nmap,
            [target + (options, interface, output) for target in nmap_input],
        )
        process_pool.close()

        if output is not None:
            logger.info("generating report %s", output)

            host_report = []
            on_first_run = 0

            for xml_report in run:
                if xml_report is None:
                    continue
                with open(xml_report, "r") as thread_output:
                    _reader = thread_output.readlines()

                    if on_first_run == 0:
                        extract_stylesheet = _reader[2].split('"')[1]
                        on_first_run = 1

                    host_report.append("".join(_reader[8:][:-3]))

                    try:
                        os.remove(xml_report)
                    except:
                        pass

            report_header = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="{extract_stylesheet}" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap --noninteractive -Pn -p port {options} host" start="" startstr="" version="" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="" services=""/>
<verbose level="0"/>
<debugging level="0"/>"""

            report_end = """<runstats><finished time="" timestr="" summary="" elapsed="" exit="success"/><hosts up="" down="" total=""/>
</runstats>
</nmaprun>"""

            with open(output, "w") as output:
                output.write(report_header + "\n".join(host_report) + report_end)
