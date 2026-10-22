import sys
from loguru import logger

LOG_FORMAT = (
    "<green>{time:HH:mm:ss}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{function}</cyan> | "
    "<level>{message}</level>"
)


def setup_logging(logfile=None, level="INFO"):
    """Configure loguru once, at an entry point. Shared modules just import `logger` and use it."""
    logger.remove()
    logger.add(sys.stderr, format=LOG_FORMAT, level=level)
    if logfile:
        logger.add(logfile, rotation="5 MB", level="DEBUG")
    return logger
