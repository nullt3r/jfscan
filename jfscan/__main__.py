#!/usr/bin/env python3
import logging
import argparse
import sys
import re
import subprocess
import os

from jfscan.core.resources import Resources
from jfscan.core.utils import Utils
from jfscan.core.modules import Modules

def main():
    parser = argparse.ArgumentParser(description="JFScan - Just Fu*king Scan")
    
    group_ports = parser.add_mutually_exclusive_group(required=True)
    group_nmap = parser.add_argument_group()

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
        "--resolvers",
        action="store",
        help="custom resolvers separated by a comma, e. g., 8.8.8.8,1.1.1.1",
        required=False,
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
        default=30000,
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

    group_nmap.add_argument(
        "--nmap",
        action="store_true",
        help="run nmap on discovered ports",
    )

    group_nmap.add_argument(
        "--nmap-options",
        action="store",
        help="nmap arguments, e. g., --nmap-options='-sV' or --nmap-options='-sV --script ssh-auth-methods'",
    )

    group_nmap.add_argument(
        "--nmap-threads",
        action="store",
        type=int,
        help="number of nmaps to run concurrently, default 8",
    )

    group_nmap.add_argument(
        "--nmap-output",
        action="store",
        help="path to save output file in XML format (same as nmap option -oX)",
    )

    args = parser.parse_args()

    arg_ports = args.ports
    arg_resolvers = args.resolvers
    arg_max_rate = args.max_rate
    arg_targets = args.targets
    arg_modules = args.modules
    arg_only_domains = args.only_domains
    arg_only_ips = args.only_ips
    arg_top_ports = args.top_ports
    arg_nmap = args.nmap
    arg_nmap_options = args.nmap_options
    arg_nmap_threads = args.nmap_threads
    arg_nmap_output = args.nmap_output

    if args.quite:
        logging.getLogger().setLevel(logging.ERROR)
    else:
        print(
            """\033[38;5;63m
           _____________                
          / / ____/ ___/_________ _____ 
     __  / / /_   \__ \/ ___/ __ `/ __ \\
    / /_/ / __/  ___/ / /__/ /_/ / / / /
    \____/_/    /____/\___/\__,_/_/ /_/ \033[0m
                                        
    \033[97mJust Fu*king Scan / version: 1.0.3 / author: nullt3r\033[0m

    """)
        logging.getLogger().setLevel(logging.INFO)

    if arg_resolvers is not None:
        logging.info(" using custom resolvers: %s", ", ".join(arg_resolvers.split(",")))
        user_resolvers = arg_resolvers.split(",")
        utils = Utils(resolvers = user_resolvers)
    else:
        utils = Utils()

    res = Resources(utils)

    if arg_top_ports is not None:
        scan_masscan_args = (None, arg_max_rate, arg_top_ports)
    else:
        port_chars = re.compile(r"^[0-9,\-]+$")
        if not re.search(port_chars, arg_ports):
            logging.fatal(" ports are in a wrong format")
            raise SystemExit
        scan_masscan_args = (arg_ports, arg_max_rate, None)


    if arg_nmap:
        if arg_nmap_options is not None:
            if any(_opt in arg_nmap_options for _opt in ["-oN", "-oS", "-oX", "-oG"]):
                parser.error("output arguments -oNSXG are not permitted, you can use option --nmap-output to save all results to single xml file (like -oX)")

            result = subprocess.run(
                    f"nmap -p 65532 127.0.0.1 {arg_nmap_options}",
                    capture_output=True,
                    shell=True,
                    check=False,
                )

            if result.returncode != 0:
                logging.fatal(" incorrect nmap options: \n\n%s", result.stderr.decode("UTF-8"))
                raise SystemExit

    try:
        utils.check_dependency("nmap", "--version", "Nmap version 7.")
        utils.check_dependency("masscan", "--version", "1.3.2")

        utils.load_targets(res, arg_targets, is_tty)
        utils.load_modules(res, arg_modules)

        Modules.scan_masscan(res, *scan_masscan_args)

        if arg_nmap:
            if arg_nmap_output is not None:
                Modules.scan_nmap(res, arg_nmap_options, arg_nmap_output, arg_nmap_threads)
            else:
                Modules.scan_nmap(res, arg_nmap_options, None)

    except KeyboardInterrupt:
        logging.fatal(" ctrl+c received, exiting")

        raise SystemExit

    """
    Report results
    """
    if not arg_nmap:
        if arg_only_domains == True:
            results = res.get_list(ips=False, domains=True)

        elif arg_only_ips == True:
            results = res.get_list(ips=True, domains=False)

        else:
            results = res.get_list(ips=True, domains=True)

        for line in results:
            print(line)

if __name__ == "__main__":
    main()