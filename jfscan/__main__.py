# pylint: disable=import-error
#!/usr/bin/env python3
import logging

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
        logger = logging.getLogger()
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(CustomFormatter())
        logger.addHandler(stream_handler)

        arguments = ArgumentHandler()

        if arguments.quite is True:
            logger.level = logging.ERROR
        else:
            logger.level = logging.INFO
            print(
                f"""\033[38;5;63m
               _____________                
              / / ____/ ___/_________ _____ 
         __  / / /_   \__ \/ ___/ __ `/ __ \\
        / /_/ / __/  ___/ / /__/ /_/ / / / /
        \____/_/    /____/\___/\__,_/_/ /_/ \033[0m
                                            
        \033[97mversion: {CURRENT_VERSION} / author: @nullt3r\033[0m

        """)

        if arguments.resolvers is not None:
            user_resolvers = arguments.resolvers.split(",")
            logger.info("using custom resolvers: %s", ", ".join(user_resolvers))
            utils = Utils(resolvers = user_resolvers)
        else:
            utils = Utils()

        res = Resources(utils)
        masscan = Masscan(utils)
        nmap = Nmap(utils)
        ports_count = 0

        if arguments.router_ip is not None:
            masscan.router_ip = arguments.router_ip

        if arguments.top_ports is not None:
            ports_count += arguments.top_ports
            masscan.top_ports = arguments.top_ports

        if arguments.ports is not None:
            masscan.ports = arguments.ports
            for _port in arguments.ports.split(","):
                if "-" in _port:
                    ports_count += int(_port.split("-")[1]) - int(_port.split("-")[0])
                else:
                    ports_count += 1

        if arguments.yummy_ports is True:
            yummy_ports = utils.yummy_ports()
            ports_count += len(yummy_ports)
            masscan.ports = ",".join(map(str, yummy_ports))

        utils.check_dependency("nmap", "--version", "Nmap version 7.")
        utils.check_dependency("masscan", "--version", "1.3.2")

        utils.load_targets(res,
                           targets_file = arguments.targets,
                           target = arguments.target.split(",") if arguments.target is not None else None
        )
        ip_count = res.count_ips()

        if ip_count == 0:
            logger.error("nothing to scan, no domains were resolved")
            raise SystemExit

        if arguments.disable_auto_rate is False:
            computed_rate = utils.compute_rate(ip_count, ports_count, arguments.max_rate)
            logger.info("adjusting packet rate to %s kpps (you can disable this by --disable-auto-rate)", computed_rate)
            masscan.rate = computed_rate
        else:
            logger.info("rate adjustment disabled, expect unexpected")
            masscan.rate = arguments.max_rate

        masscan.run(res)

        logger.info("dumping results")

        if arguments.only_domains is True:
            results = res.get_list(ips=False, domains=True)
        elif arguments.only_ips is True:
            results = res.get_list(ips=True, domains=False)
        else:
            results = res.get_list(ips=True, domains=True)

        for line in results:
            print(line)

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


    except KeyboardInterrupt:
        logger.fatal("ctrl+c was pressed, cleaning up & exiting...")

        import os, glob
        for jfscan_file in glob.glob("/tmp/_jfscan_*"):
            os.remove(jfscan_file)

        raise SystemExit

if __name__ == "__main__":
    main()

