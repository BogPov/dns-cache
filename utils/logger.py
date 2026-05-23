import logging
import sys


class ColoredFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: "\033[90m",
        logging.INFO: "\033[96m",
        logging.WARNING: "\033[93m",
        logging.ERROR: "\033[91m",
        logging.CRITICAL: "\033[95m\033[1m",
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelno, self.RESET)

        fmt = (
            f"\033[90m%(asctime)s\033[0m | "
            f"{color}%(levelname)-8s{self.RESET} | "
            f" %(message)s"
        )

        formatter = logging.Formatter(fmt, datefmt="%H:%M:%S")
        return formatter.format(record)


def get_logger():
    logger = logging.getLogger("app")

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(ColoredFormatter())

    logger.addHandler(handler)

    return logger