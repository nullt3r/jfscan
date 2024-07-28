# pylint: disable=import-error
#!/usr/bin/env python3
import logging
import time

from jfscan.core.resources import Resources
from jfscan.core.utils import Utils
from jfscan.core.arg_handler import ArgumentHandler
from jfscan.core.logging_formatter import CustomFormatter

from jfscan.modules.Masscan import Masscan
from jfscan.modules.Nmap import Nmap

from jfscan import __version__

CURRENT_VERSION = __version__.__version__


def main():
    try:
        # Setup logging
        logger = logging.getLogger()
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(CustomFormatter())
        logger.addHandler(stream_handler)

        # Handle arguments
        arguments = ArgumentHandler()

        ports_count = 0

        # Set the debug level
        if arguments.quite is True:
            logger.level = logging.ERROR
        else:
            if arguments.verbose is True:
                logger.level = logging.DEBUG
            else:
                logger.level = logging.INFO

            print(
                f"""\033[38;5;63m
    ___,__, _,  _,_   ,  , 
    ',| '|_,(_, / '|\  |\ | 
    (_|  |   _)'\_ |-\ |'\| 
        '  '     `'  `'  ` \033[0m
    \033[97mversion: {CURRENT_VERSION} / author: @nullt3r\033[0m
"""
            )

        # Set arguments for Utils first
        utils = Utils()

        if arguments.resolvers is not None:
            user_resolvers = arguments.resolvers.split(",")
            logger.info("using custom resolvers: %s", ", ".join(user_resolvers))
            utils.resolvers = user_resolvers

        if arguments.enable_ipv6 is True:
            logger.info("enabling IPv6 support")
            utils.enable_ipv6 = arguments.enable_ipv6

        # Create new instance of the modules with a prepared Utils class.
        # Is there a better way?
        res = Resources(utils)
        masscan = Masscan(utils)
        nmap = Nmap(utils)

        # Set additional parameters for Resources
        if arguments.scope is not None:
            logger.info("targets will be validated against scope defined in file %s", arguments.scope)
            res.scope_file = arguments.scope

        # Set additional parameters for Masscan
        if arguments.interface is not None:
            masscan.interface = arguments.interface

        if arguments.wait is not None:
            masscan.wait = arguments.wait

        if arguments.router_ip is not None:
            masscan.router_ip = arguments.router_ip

        if arguments.router_mac is not None:
            masscan.router_mac = arguments.router_mac

        if arguments.router_mac_ipv6 is not None:
            masscan.router_mac_ipv6 = arguments.router_mac_ipv6

        if arguments.source_ip is not None:
            masscan.source_ip = arguments.source_ip

        if arguments.top_ports is not None:
            ports_count += arguments.top_ports
            masscan.top_ports = arguments.top_ports

        if arguments.ports is not None:
            masscan.ports = arguments.ports
            for _port in arguments.ports.split(","):
                if "-" in _port:
                    high_port = 65535 if _port.split("-")[1].strip() == ""  else int(_port.split("-")[1])
                    low_port = 0 if _port.split("-")[0].strip() == "" else int(_port.split("-")[0])
                    ports_count += high_port - low_port
                else:
                    ports_count += 1

        if arguments.yummy_ports is True:
            yummy_ports = utils.yummy_ports()
            ports_count += len(yummy_ports)
            masscan.ports = ",".join(map(str, yummy_ports))

        # Check dependencies
        utils.check_dependency("nmap", "--version", "Nmap version 7.")
        utils.check_dependency("masscan", "--version", "1.3.2")

        # Load targets specified by user
        utils.load_targets(
            res,
            targets_file=arguments.targets,
            target=arguments.target.split(",")
            if arguments.target is not None
            else None,
        )

        # Count all the possible IPs to be scanned for the auto-rate feature
        ip_count = res.count_ips()

        if ip_count == 0:
            logger.error("nothing to scan, no domains were resolved")
            raise SystemExit(1)
        elif ip_count > 2**32:
            logger.fatal("number of IPs to be scanned is very large (%s to be exact), you probably specified wrong IPv6 network range...", ip_count)
            raise SystemExit(1)

        # Lets continue if number of IPs to be scanned is acceptable
        logger.info("%s unique IP addresses will be scanned", ip_count)

        # Set another parameters to masscan: adjust masscan's rate
        if arguments.disable_auto_rate is False:
            computed_rate = utils.compute_rate(
                ip_count, ports_count, arguments.max_rate
            )
            logger.info(
                "adjusting packet rate to %s kpps (you can disable this by --disable-auto-rate)",
                computed_rate,
            )
            masscan.rate = computed_rate
        else:
            logger.info("rate adjustment disabled, some open ports might not be discovered")
            masscan.rate = arguments.max_rate

        scanning_start = time.perf_counter()

        masscan.run(res)

        # Report results from masscan
        logger.info("showing results")

        results = []
        result_ips, result_domains = res.get_scan_results()

        if arguments.only_domains is True:
            results = result_domains
        elif arguments.only_ips is True:
            results = result_ips
        else:
            results = result_ips + result_domains

        for line in results:
            print(line)

        # Save results to file
        if arguments.output is not None:
            logger.info("saving results to %s", arguments.output)
            utils.save_results(results, arguments.output)

        # Are we going to run nmap also? Set arguments for nmap
        if arguments.nmap is True:
            if arguments.interface is not None:
                nmap.interface = arguments.interface

            if arguments.nmap_output is not None:
                nmap.output = arguments.nmap_output

            if arguments.nmap_threads is not None:
                nmap.threads = arguments.nmap_threads

            if arguments.nmap_options is not None:
                nmap.options = arguments.nmap_options

            nmap.run(res)

        scanning_stop = time.perf_counter()

        logger.info(
            "scan took %0.2f seconds, discovered %s open ports, %s hosts alive out of %s total",
            scanning_stop - scanning_start,
            res.count_ports(),
            res.count_alive_ips(),
            ip_count
        )

    except KeyboardInterrupt:
        logger.fatal("ctrl+c was pressed, cleaning up & exiting...")

        import os, glob

        for jfscan_file in glob.glob("/tmp/_jfscan_*"):
            os.remove(jfscan_file)

        raise SystemExit(1)


if __name__ == "__main__":
    main()
