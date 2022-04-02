#!/usr/bin/env python3
import subprocess
import logging
import validators
import os
import sys
import dns.resolver
import socket
import random
import string


class Utils:
    def __init__(self, resolvers = None):
        self.logger = logging.getLogger(__name__)
        self.resolvers = resolvers

    def check_dependency(self, bin, version_flag = None, version_string = None):
        logger = self.logger

        result = subprocess.run(
                f"which {bin}",
                capture_output=True,
                shell=True,
                check=False,
            )

        if result.returncode == 1:
            logger.fatal("%s is not installed", bin)

            raise SystemExit


        if version_flag and version_string is not None:
            result = subprocess.run(
                f"{bin} {version_flag}",
                capture_output=True,
                shell=True,
                check=False,
            )

            if version_string not in str(result.stdout):
                logger.fatal("wrong version of %s is installed - version %s is required", bin, version_string)

                raise SystemExit


    def handle_command(self, cmd):
        logger = self.logger

        result = None

        logger.debug("running command %s", cmd)

        result = subprocess.run(
            cmd,
            capture_output=True,
            shell=True,
            check=False,
        )

        if result.returncode != 0:
            logger.error(
                "there was an exception while running command:\n %s",
                cmd
            )
        
        return result

    def resolve_host(self, host):
        logger = self.logger

        resolver = dns.resolver.Resolver()

        if self.resolvers is not None:
            resolver.nameservers = self.resolvers

        ips = []
        try:
            result = resolver.query(host, "A")
        except:
            logger.warning(
                "the host %s could not be resolved by provided resolvers", host
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
    def detect_firewall(self, host):
        random_ports = random.sample(range(50000, 65535), 90)
        open_ports = []

        for port in random_ports:
            if self.is_port_open(host, port):
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
    def load_targets(self, res, targets = None, is_tty = True):
        logger = self.logger

        logger.info("loading targets and resolving domain names (if any)")

        if is_tty:
            if targets is None:
                return
            if self.file_is_empty(targets):
                logger.error(
                    "file is empty or does not exists: %s",
                    targets,
                )
                raise SystemExit

            _file = open(targets, "r")
            _reader = _file.readlines()
        else:
            _reader = sys.stdin.readlines()

        target_before = None

        for target in _reader:

            if validators.url(target):
                target = target.split("/")[2]

            if target == target_before:
                continue

            target = target.strip()

            if validators.domain(target):
                res.add_domain(target)

            elif validators.ipv4(target) or validators.ipv6(target):
                res.add_ip(target)

            elif validators.ipv4_cidr(target) or validators.ipv6_cidr(target):
                res.add_cidr(target)

            target_before = target
        
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
    def random_string():
        return "".join(
            random.choice(string.ascii_lowercase + string.digits) for _ in range(9)
        )
