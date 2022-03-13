#!/usr/bin/env python3
import subprocess
import logging
import inspect
import validators
import os
import sys
import dns.resolver
import socket
import random
import string


class Utils:

    @staticmethod
    def print_banner():
        print(
            """
           _____________                
          / / ____/ ___/_________ _____ 
     __  / / /_   \__ \/ ___/ __ `/ __ \\
    / /_/ / __/  ___/ / /__/ /_/ / / / /
    \____/_/    /____/\___/\__,_/_/ /_/ 
                                        
    Just Fu*king Scan / version: 1.0.0 / author: nullt3r
        
        """
        )

    @classmethod
    def check_dependency(cls, bin, version_flag = None, version_string = None):
        result = subprocess.run(
                f"which {bin}",
                capture_output=True,
                shell=True,
                check=False,
            )

        if result.returncode == 1:
            logging.fatal("%s: %s is not installed", inspect.stack()[0][3], bin)

            raise SystemExit


        if version_flag and version_string is not None:
            result = subprocess.run(
                f"{bin} {version_flag}",
                capture_output=True,
                shell=True,
                check=False,
            )

            if version_string not in str(result.stdout):
                logging.fatal("%s: wrong version of %s is installed - version %s is required", inspect.stack()[0][3], bin, version_string)

                raise SystemExit

    @staticmethod
    def handle_command(cmd):
        result = None
        try:
            logging.debug("%s: running command %s", inspect.stack()[0][3], cmd)

            result = subprocess.run(
                cmd,
                capture_output=True,
                shell=True,
                check=True,
            )

        except subprocess.CalledProcessError as e:
            logging.error(
                "%s: there was an exception while running command %s: %s",
                inspect.stack()[0][3],
                cmd,
                e,
            )

        return result

    @staticmethod
    def resolve_host(host):
        ips = []
        try:
            result = dns.resolver.resolve(host, "A")
        except:
            logging.debug(
                "%s: the host %s could not be resolved", inspect.stack()[0][3], host
            )
            return None
        if result is not None and len(result) != 0:
            for ipval in result:
                ips.append(ipval.to_text())
            return list(set(ips))
        else:
            return None


    """
    Beta feature: Not tested, maybe it's not working as intended.
    """
    @classmethod
    def detect_firewall(cls, host):
        random_ports = random.sample(range(50000, 65535), 90)
        open_ports = []

        for port in random_ports:
            if cls.is_port_open(host, port):
                open_ports.append(port)

        if len(open_ports) > len(random_ports) / 10:
            return True

        return False

    @staticmethod
    def is_port_open(host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((host, port))
        except:
            pass
        if result == 0:
            return True
        else:
            return False

    """
    Not too efficient way.
    """
    @classmethod
    def load_targets(cls, res, targets = None, is_tty = True):
        logging.info("%s: loading targets and resolving domain names (if any)", inspect.stack()[0][3])

        if is_tty:
            if targets is None:
                return
            if cls.file_is_empty(targets):
                logging.error(
                    "%s: file is empty or does not exists: %s",
                    inspect.stack()[0][3],
                    targets,
                )
                raise SystemExit

            _file = open(targets, "r")
            _reader = _file.readlines()
        else:
            _reader = sys.stdin.readlines()

        for target in _reader:
            target = target.strip()

            if validators.domain(target):
                res.add_domain(target)

            elif validators.ipv4(target) or validators.ipv6(target):
                res.add_ip(target)

            elif validators.ipv4_cidr(target) or validators.ipv6_cidr(target):
                res.add_cidr(target)

            elif validators.url(target):
                target = target.split("/")[2]

                if validators.domain(target):
                    res.add_domain(target)

                elif validators.ipv4(target) or validators.ipv6(target):
                    res.add_ip(target)
        
        if is_tty:
            _file.close()
        

    @staticmethod
    def file_is_empty(file):
        try:
            if os.path.exists(file) is not True or os.path.getsize(file) == 0:
                return True
        except:
            return True
        else:
            return False

    @staticmethod
    def load_modules(res, modules):
        if modules is None:
            return

        from core.modules import Modules

        for module in modules.split(","):
            if module in modules:
                logging.info("%s: starting module", module)
                getattr(Modules, module)(res)
                logging.info("%s: module finished", module)

    @staticmethod
    def random_string():
        return "".join(
            random.choice(string.ascii_lowercase + string.digits) for _ in range(9)
        )