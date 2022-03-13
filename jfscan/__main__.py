#!/usr/bin/env python3
import logging
import argparse
import sys
import re

from jfscan.core.resources import Resources
from jfscan.core.utils import Utils
from jfscan.core.modules import Modules

def main():
    parser = argparse.ArgumentParser(description="JFScan - Just Fu*king Scan")
    
    group_ports = parser.add_mutually_exclusive_group(required=True)

    modules = [method for method in dir(Modules) if method.startswith("enum_") is True]

    if sys.stdin.isatty():
        is_tty = True
    else:
        is_tty = False
        logging.info(" accepting input from stdin")

    parser.add_argument(
        "-t",
        "--targets",
        action="store",
        help="list of targets, accepted form is: domain name, IPv4, IPv6, URL",
        required=is_tty,
    )
    parser.add_argument(
        "-m",
        "--modules",
        action="store",
        help=f"modules separated by a comma, available modules: {', '.join(modules)}",
        required=False,
    )
    group_ports.add_argument(
        "-p",
        "--ports",
        action="store",
        help="ports, can be a range or port list: 0-65535 or 22,80,100-500,...",
        required=False,
    )
    group_ports.add_argument(
        "-tp",
        "--top-ports",
        action="store",
        type=int,
        help="scan only N of the top ports, e. g., --top-ports 1000",
        required=False,
    )
    parser.add_argument(
        "-r",
        "--max-rate",
        action="store",
        type=int,
        help="max kpps rate",
        required=False,
    )
    parser.add_argument(
        "-oi",
        "--only-ips",
        action="store_true",
        help="output only IP adresses, default: all resources",
        required=False,
    )
    parser.add_argument(
        "-od",
        "--only-domains",
        action="store_true",
        help="output only domains, default: all resources",
        required=False,
    )
    parser.add_argument(
        "-q",
        "--quite",
        action="store_true",
        help="output only results",
        required=False,
    )

    args = parser.parse_args()

    arg_ports = args.ports
    arg_max_rate = args.max_rate
    arg_targets = args.targets
    arg_modules = args.modules
    arg_only_domains = args.only_domains
    arg_only_ips = args.only_ips
    arg_top_ports = args.top_ports
    
    res = Resources()

    if args.quite:
        logging.basicConfig(level=logging.ERROR)
    else:
        Utils.print_banner()
        logging.basicConfig(level=logging.INFO)


    if arg_top_ports is not None:
        scan_masscan_args = (None, arg_max_rate, arg_top_ports)
    else:
        port_chars = re.compile(r"^[0-9,\-]+$")
        if not re.search(port_chars, arg_ports):
            logging.fatal(" ports are in a wrong format")
            raise SystemExit
        scan_masscan_args = (arg_ports, arg_max_rate, None)

    try:
        Utils.load_targets(res, arg_targets, is_tty)
        Utils.load_modules(res, arg_modules)
        Modules.scan_masscan(res, *scan_masscan_args)

    except KeyboardInterrupt:
        logging.fatal(" ctrl+c received, exiting")

        raise SystemExit

    """
    Report results
    """
    if arg_only_domains == True:
        results = res.get_list(ips=False, domains=True)

    elif arg_only_ips == True:
        results = res.get_list(ips=True, domains=False)

    else:
        results = res.get_list(ips=True, domains=True)

    for line in sorted(results):
        print(line)


if __name__ == "__main__":
    main()