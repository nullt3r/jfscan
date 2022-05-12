import logging


class CustomFormatter(logging.Formatter):

    grey = "\x1b[38;20m"
    bold_cyan = "\x1b[1;36m"
    cyan = "\x1b[0;36m"
    bold_white = "\x1b[1;37m"
    bold_white = "\x1b[1;37m"
    white = "\x1b[0;37m"
    yellow = "\x1b[33;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    # format = "[%(asctime)s] [%(levelname)s] [%(module)s.%(funcName)s] - %(message)s"
    message = "[%(asctime)s] [%(levelname)s] - %(message)s"

    """
    FORMATS = {
        logging.DEBUG: cyan + message + reset,
        logging.INFO: f"[%(asctime)s] {green}[%(levelname)s]{reset} - %(message)s",
        logging.WARNING: yellow + message + reset,
        logging.ERROR: red + message + reset,
        logging.CRITICAL: bold_red + message + reset,
    }
    """

    FORMATS = {
        logging.DEBUG: f"{cyan}[%(asctime)s]{reset} {bold_cyan}[%(levelname)s]{reset} - {cyan}%(message)s{reset}",
        logging.INFO: f"[%(asctime)s] {white}[%(levelname)s]{reset} - %(message)s",
        logging.WARNING: f"[%(asctime)s] {yellow}[%(levelname)s]{reset} - %(message)s",
        logging.ERROR: f"[%(asctime)s] {red}[%(levelname)s]{reset} - %(message)s",
        logging.CRITICAL: f"[%(asctime)s] {bold_red}[%(levelname)s]{reset} - %(message)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, "%Y-%m-%d %H:%M:%S")
        return formatter.format(record)
