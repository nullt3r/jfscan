#!/usr/bin/env python3
import logging
import argparse
import sys
import re
import subprocess
import validators

from jfscan.core.resources import Resources
from jfscan.core.utils import Utils
from jfscan.core.modules import Modules

from jfscan import __version__

current_version = __version__.__version__

def main():
    logger = logging.getLogger(__name__)
    logging_format = '[%(asctime)s] [%(levelname)s] [%(module)s.%(funcName)s] - %(message)s'


    parser = argparse.ArgumentParser(description="JFScan - Just Fu*king Scan")
    
    group_ports = parser.add_mutually_exclusive_group(required=True)
    group_nmap = parser.add_argument_group()

    available_modules = [method for method in dir(Modules) if method.startswith("enum_") is True]

    if sys.stdin.isatty():
        is_tty = True
    else:
        is_tty = False
        logger.info(" accepting input from stdin")

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
        help=f"modules separated by a comma, available modules: {', '.join(available_modules)}",
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
        "-i",
        "--interface",
        action="store",
        help="interface for masscan and nmap to use",
        required=False,
    )
    parser.add_argument(
        "--router-ip",
        action="store",
        help="IP address of your router for the masscan, e. g., when scanning from Nethunter/Android",
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
    parser.add_argument(
        "--version",
        action="version",
        version=current_version
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
    arg_interface = args.interface
    arg_router_ip = args.router_ip
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
        logging_level = logging.ERROR
    else:
        logging_level = logging.INFO
        print(
            f"""\033[38;5;63m
           _____________                
          / / ____/ ___/_________ _____ 
     __  / / /_   \__ \/ ___/ __ `/ __ \\
    / /_/ / __/  ___/ / /__/ /_/ / / / /
    \____/_/    /____/\___/\__,_/_/ /_/ \033[0m
                                        
    \033[97mJust Fu*king Scan / version: {current_version} / author: @nullt3r\033[0m

    """)
    
    logging.basicConfig(level=logging_level, format=logging_format, datefmt='%Y-%m-%d %H:%M:%S')

    if arg_resolvers is not None:
        logger.info(" using custom resolvers: %s", ", ".join(arg_resolvers.split(",")))
        user_resolvers = arg_resolvers.split(",")
        utils = Utils(resolvers = user_resolvers)
    else:
        utils = Utils()

    res = Resources(utils)
    modules = Modules(utils)

    if arg_router_ip is not None:
        if validators.ipv4(arg_router_ip) != True:
            parser.error("--router-ip has to be an IP addresses")
            raise SystemExit

    if arg_top_ports is not None:
        scan_masscan_args = (None, arg_max_rate, arg_top_ports, arg_interface, arg_router_ip)
    else:
        port_chars = re.compile(r"^[0-9,\-]+$")
        if not re.search(port_chars, arg_ports):
            parser.error("ports are in a wrong format")
            raise SystemExit
        scan_masscan_args = (arg_ports, arg_max_rate, None, arg_interface, arg_router_ip)


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
                parser.error("incorrect nmap options: \n\n{0}".format(result.stderr.decode("UTF-8")))
                raise SystemExit

    try:
        utils.check_dependency("nmap", "--version", "Nmap version 7.")
        utils.check_dependency("masscan", "--version", "1.3.2")

        utils.load_targets(res, arg_targets, is_tty)

        if arg_modules is not None:
            for module in arg_modules.split(","):
                if module in available_modules:
                    getattr(modules, module)(res)

        modules.scan_masscan(res, *scan_masscan_args)

        if arg_nmap:
            if arg_nmap_output is not None:
                modules.scan_nmap(res, arg_nmap_options, arg_interface, arg_nmap_output, arg_nmap_threads)
            else:
                modules.scan_nmap(res, arg_nmap_options, arg_interface, None, arg_nmap_threads)

    except KeyboardInterrupt:
        logger.fatal("ctrl+c received, exiting")

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