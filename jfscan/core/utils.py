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
import selectors


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


    def handle_command(self, cmd, stream_output = False):
        logger = self.logger

        logger.debug("running command %s", cmd)

        if stream_output == False:
            process = subprocess.run(
                cmd,
                capture_output=True,
                shell=True,
                check=False,
            )
            if process.returncode != 0:
                logger.error(
                    "there was an exception while running command:\n %s",
                    cmd
                )

            return process

        _stdout = b''
        _stderr = b''

        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        sel = selectors.DefaultSelector()
        sel.register(process.stdout, selectors.EVENT_READ)
        sel.register(process.stderr, selectors.EVENT_READ)

        while True:
            for key, _ in sel.select():
                data = key.fileobj.read1()
                if not data:
                    returncode = process.poll()
                    if returncode != 0:
                        logger.error(
                            "there was an exception while running command:\n %s",
                            cmd
                        )
                    return subprocess.CompletedProcess(process.args, process.returncode, _stdout, _stderr)
                if key.fileobj is process.stdout:
                    print(data.decode(), end="")
                    _stdout += data
                else:
                    print(data.decode(), end="", file=sys.stderr)
                    _stderr += data

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
    def load_targets(self, res, targets_file = None, target = None):
        logger = self.logger
        targets = []

        logger.info("loading targets and resolving domain names (if any)")

        if targets_file is not None:
            if self.file_is_empty(targets_file):
                logger.error(
                    "file is empty or does not exists: %s",
                    targets_file,
                )
                raise SystemExit

            _file = open(targets_file, "r")
            targets += _file.readlines()
            _file.close()

        if target is not None:
            targets += target

        if sys.stdin.isatty() == False:
            logger.info(
                "reading input from stdin"
            )
            targets += sys.stdin.readlines()
        
        if len(targets) == 0:
            logger.error(
                "no valid targets were specified"
            )
            raise SystemExit

        target_before = None

        for _target in targets:

            if validators.url(_target):
                _target = _target.split("/")[2]

            if _target == target_before:
                continue

            _target = _target.strip()

            if validators.domain(_target):
                res.add_domain(_target)

            elif validators.ipv4(_target) or validators.ipv6(_target):
                res.add_ip(_target)

            elif validators.ipv4_cidr(_target) or validators.ipv6_cidr(_target):
                res.add_cidr(_target)

            target_before = _target

        

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
    
    @staticmethod
    def yummy_ports():
        return [22,21,23,80,443,389,636,8443,9443,8088,9088,8081,9081,8090,8983,8161,8009,6066,7077,9998,3306,1433,6379,5984,27017,27018,27019,5000,9010,9999,9998,8855,1099,5044,9600,9700,9200,9300,5601,10080,10443,3000,3322,8086,4712,4560,8834,3343,8080,8081,7990,7999,5701,7992,7993,4848,8080,5900,5901,111,2049,1110,4045,135,139,445]
