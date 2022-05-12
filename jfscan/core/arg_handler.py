import validators
import argparse
import subprocess
import sys
import re

from jfscan import __version__

CURRENT_VERSION = __version__.__version__

class ArgumentHandler:
    def __init__(self):
        is_tty = bool(sys.stdin.isatty())

        parser = argparse.ArgumentParser(description="JFScan - Just Fu*king Scan")

        group_ports = parser.add_mutually_exclusive_group(required=True)
        group_logging = parser.add_mutually_exclusive_group(required=False)
        group_nmap = parser.add_argument_group()
        group_targets = parser.add_argument_group()
        group_output = parser.add_argument_group()
        group_scan_settings = parser.add_argument_group()
        group_version = parser.add_argument_group()

        group_targets.add_argument(
            "target",
            action="store",
            help="a target or targets separated by a comma, accepted form is: domain name, IPv4, IPv6, URL",
            nargs="?",
        )
        group_targets.add_argument(
            "--targets",
            action="store",
            help="file with targets, accepted form is: domain name, IPv4, IPv6, URL",
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
            "--top-ports",
            action="store",
            type=int,
            help="scan only N of the top ports, e. g., --top-ports 1000",
            required=False,
        )
        group_ports.add_argument(
            "--yummy-ports",
            action="store_true",
            help="scan only for the most yummy ports",
            required=False,
        )
        group_scan_settings.add_argument(
            "--resolvers",
            action="store",
            help="custom resolvers separated by a comma, e. g., 8.8.8.8,1.1.1.1",
            required=False,
        )
        group_scan_settings.add_argument(
            "--enable-ipv6",
            action="store_true",
            help="enable IPv6 support, otherwise all IPv6 addresses will be ignored in the scanning process",
            required=False,
        )
        group_scan_settings.add_argument(
            "--scope",
            action="store",
            help="file path with IP adresses and CIDRs to control scope, expected format: IPv6, IPv4, IPv6 CIDR, IPv4 CIDR",
            required=False,
        )
        group_scan_settings.add_argument(
            "-r",
            "--max-rate",
            action="store",
            type=int,
            default=30000,
            help="max kpps rate for the masscan",
            required=False,
        )
        group_scan_settings.add_argument(
            "--wait",
            action="store",
            type=int,
            default=10,
            help="a number of seconds to wait for packets to arrive (when scanning large networks), option for the masscan",
            required=False,
        )
        group_scan_settings.add_argument(
            "--disable-auto-rate",
            action="store_true",
            help="disable rate adjustment mechanism for masscan (more false positives/negatives)",
            required=False,
        )
        group_scan_settings.add_argument(
            "-i",
            "--interface",
            action="store",
            help="interface for masscan and nmap to use",
            required=False,
        )
        group_scan_settings.add_argument(
            "--source-ip",
            action="store",
            help="IP address of your interface for the masscan",
            required=False,
        )
        group_scan_settings.add_argument(
            "--router-ip",
            action="store",
            help="IP address of your router for the masscan",
            required=False,
        )
        group_scan_settings.add_argument(
            "--router-mac",
            action="store",
            help="MAC address of your router for the masscan",
            required=False,
        )
        group_scan_settings.add_argument(
            "--router-mac-ipv6",
            action="store",
            help="MAC address of your IPv6 router for the masscan",
            required=False,
        )
        group_output.add_argument(
            "-oi",
            "--only-ips",
            action="store_true",
            help="output only IP adresses, default: all resources",
            required=False,
        )
        group_output.add_argument(
            "-od",
            "--only-domains",
            action="store_true",
            help="output only domains, default: all resources",
            required=False,
        )
        group_output.add_argument(
            "-o",
            "--output",
            action="store",
            help="output masscan's results to specified file",
            required=False,
        )
        group_logging.add_argument(
            "-q",
            "--quite",
            action="store_true",
            help="output only results",
            required=False,
        )
        group_logging.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help="verbose output",
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
            help="output results from nmap to specified file in standard XML format (same as nmap option -oX)",
        )
        group_version.add_argument(
            "--version", action="version", version=CURRENT_VERSION
        )

        args = parser.parse_args()

        if (args.targets or args.target) is None:
            if is_tty is True:
                parser.error(
                    "the following arguments are required: --targets, positional parameter [target] or stdin, you can also combine all options"
                )

        if args.router_ip is not None:
            if validators.ipv4(args.router_ip) or validators.ipv6(args.router_ip) is not True:
                parser.error("--router-ip has to be an IP addresses")

        if args.source_ip is not None:
            if validators.ipv4(args.source_ip) or validators.ipv6(args.source_ip) is not True:
                parser.error("--source-ip has to be an IP addresses")

        if args.router_mac is not None:
            if validators.mac_address(args.router_mac) is not True:
                parser.error("--router-mac has to be an MAC addresses")

        if args.router_mac_ipv6 is not None:
            if args.enable_ipv6 is False:
                parser.error("you have to enable ipv6 by --enable-ipv6 before using option --router-mac-ipv6")
            if validators.mac_address(args.router_mac_ipv6) is not True:
                parser.error("--router-mac-ipv6 has to be an MAC addresses")

        if args.ports is not None:
            port_chars = re.compile(r"^[0-9,\-]+$")
            if not re.search(port_chars, args.ports):
                parser.error("ports are in a wrong format")

        if args.nmap:
            if args.nmap_options is not None:
                if any(
                    _opt in args.nmap_options for _opt in ["-oN", "-oS", "-oX", "-oG"]
                ):
                    parser.error(
                        "output arguments -oNSXG are not permitted, you can use option --nmap-output to save all results to a single xml file (like -oX)"
                    )

                result = subprocess.run(
                    f"nmap --noninteractive -p 65532 127.0.0.1 {args.nmap_options} {'-e ' + args.interface if args.interface is not None else ''}",
                    capture_output=True,
                    shell=True,
                    check=False,
                )

                if result.returncode != 0:
                    error = result.stderr.decode()
                    parser.error(f"incorrect nmap options: \n{error}")

        if args.resolvers is not None:
            for resolver in args.resolvers.split(","):
                if (validators.ipv4(resolver) or validators.ipv6(resolver)) is not True:
                    parser.error("resolvers must be specified as IP addresses")

        self.quite = args.quite
        self.verbose = args.verbose
        self.scope = args.scope
        self.enable_ipv6 = args.enable_ipv6
        self.ports = args.ports
        self.top_ports = args.top_ports
        self.yummy_ports = args.yummy_ports
        self.resolvers = args.resolvers
        self.max_rate = args.max_rate
        self.wait = args.wait
        self.disable_auto_rate = args.disable_auto_rate
        self.interface = args.interface
        self.source_ip = args.source_ip
        self.router_ip = args.router_ip
        self.router_mac = args.router_mac
        self.router_mac_ipv6 = args.router_mac_ipv6
        self.targets = args.targets
        self.target = args.target
        self.only_domains = args.only_domains
        self.only_ips = args.only_ips
        self.output = args.output
        self.nmap = args.nmap
        self.nmap_options = args.nmap_options
        self.nmap_threads = args.nmap_threads
        self.nmap_output = args.nmap_output


