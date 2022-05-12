# pylint: disable=import-error
#!/usr/bin/env python3
import subprocess
import logging
import os
import sys
import socket
import random
import string
import selectors
import dns.resolver

from jfscan.core.validator import Validator

class Utils:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.resolvers = None
        self.enable_ipv6 = False

    def check_dependency(self, binary, version_flag=None, version_string=None):
        logger = self.logger

        result = subprocess.run(
            f"which {binary}",
            capture_output=True,
            shell=True,
            check=False,
        )

        if result.returncode == 1:
            logger.fatal("%s is not installed", binary)

            raise SystemExit

        if version_flag and version_string is not None:
            result = subprocess.run(
                f"{binary} {version_flag}",
                capture_output=True,
                shell=True,
                check=False,
            )

            if version_string not in str(result.stdout):
                logger.fatal(
                    "wrong version of %s is installed - version %s is required",
                    binary,
                    version_string,
                )

                raise SystemExit

    def handle_command(self, cmd, stream_output=False):
        logger = self.logger

        logger.debug("running command %s", cmd)

        _stdout = b""
        _stderr = b""

        try:
            with subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            ) as process:
                sel = selectors.DefaultSelector()
                sel.register(process.stdout, selectors.EVENT_READ)
                sel.register(process.stderr, selectors.EVENT_READ)

                while True:
                    for key, _ in sel.select():
                        data = key.fileobj.read1()
                        if not data:
                            process.wait()
                            returncode = process.poll()
                            if returncode != 0:
                                logger.error(
                                    "there was an exception while running command:\n %s",
                                    cmd,
                                )
                            return subprocess.CompletedProcess(
                                process.args, process.returncode, _stdout, _stderr
                            )
                        if key.fileobj is process.stdout:
                            if stream_output is True:
                                print(data.decode(), end="")
                            _stdout += data
                        else:
                            if stream_output is True:
                                print(data.decode(), end="", file=sys.stderr)
                            _stderr += data
        except KeyboardInterrupt:
            logger.error(
                "process was killed, continuing..."
            )
            process.kill()
            return subprocess.CompletedProcess(
                process.args, process.returncode, _stdout, _stderr
            )

    def resolve_host(self, host):
        logger = self.logger

        resolver = dns.resolver.Resolver()

        if self.resolvers is not None:
            resolver.nameservers = self.resolvers

        ips = []

        if self.enable_ipv6 is True:
            queries = ["A", "AAAA"]
        else:
            queries = ["A"]

        for query in queries:
            try:
                result = resolver.query(host, query)
            except Exception as e:
                logger.debug(
                    "%s could not be resolved by provided resolvers (%s):\n %s", host, query, e
                )
                result = None

            if result is not None and len(result) != 0:
                for ipval in result:
                    ips.append(ipval.to_text())
        
        if len(ips) == 0:
            logger.warning("host %s could not be resolved", host)
            return None
        
        ips = list(set(ips))
        
        logger.debug("host %s was resolved to: %s", host, ", ".join(ips))
        
        return ips

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

        return bool(result)   

    def save_results(self, results, target_file):
        logger = self.logger
        try:
            with open(target_file, "w", encoding="UTF-8") as f:
                for result in results:
                    f.write(f"{result}\n")
        except Exception as e:
            logger.error("Could not save results to the specified file %s:\n %s", target_file, e)

    def load_targets(self, res, targets_file=None, target=None):
        logger = self.logger
        targets = []

        logger.info("loading targets and resolving domain names (if any)")

        if targets_file is not None:
            if self.file_is_empty(targets_file):
                logger.fatal(
                    "input file is empty or does not exists: %s",
                    targets_file,
                )
                raise SystemExit

            with open(targets_file, "r", encoding="UTF-8") as _file:
                targets += _file.readlines()

        if target is not None:
            targets += target

        if sys.stdin.isatty() is False:
            logger.info("reading input from stdin")
            targets += sys.stdin.readlines()

        if len(targets) == 0:
            logger.error("no valid targets were specified")
            raise SystemExit

        target_before = None

        for _target in targets:

            # In case the target is URL, we have to extract it first before further checks
            if Validator.is_url(_target):
                _target = _target.split("/")[2]

            # If the next target is same as the one before, we can move onto another one
            if _target == target_before:
                continue

            _target = _target.strip()

            if Validator.is_domain(_target):
                res.add_domain(_target)

            elif Validator.is_ipv4(_target) or Validator.is_ipv6(_target):
                res.add_ip(_target)

            elif Validator.is_ipv4_cidr(_target) or Validator.is_ipv6_cidr(_target):
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
        return [
            22,
            21,
            23,
            80,
            443,
            389,
            636,
            8443,
            9443,
            8088,
            9088,
            8081,
            9081,
            8090,
            8983,
            8161,
            8009,
            6066,
            7077,
            9998,
            3306,
            1433,
            6379,
            5984,
            27017,
            27018,
            27019,
            5000,
            9010,
            9999,
            9998,
            8855,
            1099,
            5044,
            9600,
            9700,
            9200,
            9300,
            5601,
            10080,
            10443,
            3000,
            3322,
            8086,
            4712,
            4560,
            8834,
            3343,
            8080,
            8081,
            7990,
            7999,
            5701,
            7992,
            7993,
            4848,
            8080,
            5900,
            5901,
            111,
            2049,
            1110,
            4045,
            135,
            139,
            445,
        ]

    @staticmethod
    def compute_rate(num_ips, num_ports, max_rate):
        computed_rate = num_ips * num_ports / (num_ports / 100)

        if computed_rate > max_rate:
            return int(max_rate)

        return int(computed_rate)
