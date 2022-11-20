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

            raise SystemExit(1)

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

                raise SystemExit(1)

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
                raise SystemExit(1)

            with open(targets_file, "r", encoding="UTF-8") as _file:
                targets += _file.readlines()

        if target is not None:
            targets += target

        if sys.stdin.isatty() is False:
            logger.info("reading input from stdin")
            targets += sys.stdin.readlines()

        if len(targets) == 0:
            logger.error("no valid targets were specified")
            raise SystemExit(1)


        for _target in list(set(targets)):

            _target = _target.strip()

            # Domain from URL must be extracted first
            if Validator.is_url(_target):
                _target = _target.split("/")[2]

            if Validator.is_domain(_target):
                res.add_domain(_target)

            elif Validator.is_ipv4(_target) or Validator.is_ipv6(_target):
                res.add_ip(_target)

            elif Validator.is_ipv4_cidr(_target) or Validator.is_ipv6_cidr(_target):
                res.add_cidr(_target)

            elif Validator.is_ipv4_range(_target):
                cidrs = self.ipv4_range_to_cidrs(_target)

                logger.debug("IP range %s was divided into the following CIDRs: %s", _target, ", ".join(cidrs))

                for cidr in cidrs:
                    res.add_cidr(cidr)

            elif Validator.is_ipv6_range(_target):
                cidrs = self.ipv6_range_to_cidrs(_target)

                logger.debug("IP range %s was divided into the following CIDRs: %s", _target, ", ".join(cidrs))

                for cidr in cidrs:
                    res.add_cidr(cidr)

            else:
                logger.warning("host %s is in unrecognized format, skipping...", _target)

    @staticmethod
    def ipv4_range_to_cidrs(ip_range):
        """Converts target specified as IP range (inetnum) to CIDR(s)

        Args:
            ip_range (str): IP range - 192.168.0.0-192.168.1.255

        Returns:
            list: list of CIDR(s)
        """
        import ipaddress
        try:
            ip_range = ip_range.split("-")
            startip = ipaddress.IPv4Address(ip_range[0])
            endip = ipaddress.IPv4Address(ip_range[1])
            return [str(ipaddr) for ipaddr in ipaddress.summarize_address_range(startip, endip)]
        except:
            return None

    @staticmethod
    def ipv6_range_to_cidrs(ip_range):
        """Converts target specified as IP range (inetnum) to CIDR(s)

        Args:
            ip_range (str): IP range - 2620:0:2d0:200::7-2620:0:2d0:2df::7

        Returns:
            list: list of CIDR(s)
        """
        import ipaddress
        try:
            ip_range = ip_range.split("-")
            startip = ipaddress.IPv6Address(ip_range[0])
            endip = ipaddress.IPv6Address(ip_range[1])
            return [str(ipaddr) for ipaddr in ipaddress.summarize_address_range(startip, endip)]
        except:
            return None

    # Oh, just remove it already...
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
            10000,
            10006,
            10009,
            10010,
            10026,
            10037,
            10047,
            10048,
            10080,
            10087,
            10089,
            10093,
            10100,
            10136,
            10141,
            10187,
            1022,
            10256,
            1026,
            10283,
            10443,
            10477,
            1050,
            10543,
            10652,
            10691,
            10776,
            1080,
            1099,
            111,
            1110,
            11180,
            11680,
            1194,
            12088,
            12170,
            12200,
            12211,
            12283,
            12318,
            12320,
            12323,
            12325,
            12327,
            12378,
            12383,
            12424,
            12432,
            12437,
            12457,
            12490,
            12516,
            12584,
            12588,
            1343,
            135,
            139,
            1433,
            1444,
            15672,
            15673,
            16004,
            16017,
            16029,
            16036,
            16052,
            16059,
            16063,
            16082,
            161,
            16100,
            16316,
            16443,
            16992,
            18001,
            18042,
            18094,
            18888,
            19015,
            19082,
            19999,
            20000,
            20010,
            2002,
            2030,
            2049,
            20512,
            2052,
            2053,
            2063,
            2078,
            2079,
            2082,
            2083,
            2086,
            2087,
            2096,
            21,
            2100,
            2103,
            2107,
            2108,
            2109,
            2111,
            2121,
            2122,
            2123,
            2126,
            21299,
            2130,
            2133,
            2134,
            2156,
            2195,
            2196,
            22,
            2200,
            22206,
            23,
            2301,
            2323,
            2375,
            2377,
            2381,
            2443,
            2455,
            25000,
            2570,
            2598,
            27017,
            27018,
            27019,
            3000,
            30000,
            3001,
            3002,
            30027,
            3003,
            3004,
            3005,
            3006,
            3007,
            3008,
            3009,
            30113,
            30452,
            3048,
            3081,
            3100,
            3111,
            3120,
            3121,
            3128,
            3175,
            3190,
            31948,
            3199,
            3200,
            32102,
            32444,
            3306,
            3322,
            3343,
            3443,
            3551,
            35531,
            3580,
            3582,
            389,
            40000,
            40005,
            4040,
            4045,
            4101,
            4165,
            42420,
            443,
            4431,
            4432,
            4433,
            444,
            4443,
            4444,
            44443,
            44444,
            445,
            4510,
            4560,
            45886,
            47001,
            4712,
            4848,
            49443,
            49682,
            49694,
            5000,
            50001,
            50002,
            5001,
            5004,
            50080,
            50202,
            5022,
            5044,
            5060,
            5061,
            5080,
            5090,
            520,
            5236,
            5252,
            5272,
            5357,
            5400,
            5432,
            5443,
            5500,
            5555,
            556,
            5601,
            5671,
            5672,
            5673,
            5701,
            5900,
            5901,
            5911,
            5984,
            5985,
            5989,
            60000,
            6066,
            6070,
            632,
            636,
            6379,
            6666,
            6688,
            7000,
            7070,
            7077,
            7080,
            7332,
            7403,
            7424,
            7443,
            7445,
            7446,
            7547,
            7672,
            7776,
            7777,
            7914,
            7946,
            7990,
            7991,
            7992,
            7993,
            7999,
            80,
            8000,
            8001,
            8002,
            8003,
            8007,
            8008,
            8009,
            8012,
            8022,
            8043,
            805,
            8060,
            8080,
            8081,
            8082,
            8083,
            8084,
            8085,
            8086,
            8088,
            8089,
            8090,
            8091,
            8095,
            8098,
            81,
            8100,
            8101,
            8120,
            8123,
            8137,
            8150,
            8152,
            8161,
            8187,
            82,
            8200,
            83,
            8381,
            8403,
            8411,
            8443,
            8454,
            8519,
            8550,
            8573,
            8634,
            8707,
            880,
            8810,
            8831,
            8834,
            8843,
            8844,
            8855,
            8866,
            8880,
            8888,
            8899,
            8983,
            8989,
            9000,
            9001,
            9010,
            9016,
            9024,
            9033,
            9080,
            9081,
            9084,
            9088,
            9090,
            9091,
            9098,
            9100,
            9114,
            9115,
            9116,
            9120,
            9121,
            9153,
            9162,
            9200,
            9207,
            9208,
            9214,
            9256,
            9300,
            9306,
            9443,
            9600,
            9696,
            9700,
            9882,
            9901,
            9928,
            9966,
            9990,
            9998,
            9999
        ]

    @staticmethod
    def compute_rate(num_ips, num_ports, max_rate):
        computed_rate = num_ips * num_ports / (num_ports / 100)

        if computed_rate > max_rate:
            return int(max_rate)

        return int(computed_rate)
