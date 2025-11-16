import logging
import sys
from pythonjsonlogger import jsonlogger


def setup_logger(name: str = "threat_detection") -> logging.Logger:
    """
    Setup structured JSON logger
    """
    logger = logging.getLogger(name)
    
    if logger.hasHandlers():
        return logger
    
    logger.setLevel(logging.INFO)
    
    # Console handler
    handler = logging.StreamHandler(sys.stdout)
    
    # JSON formatter
    formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(name)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger


# Create default logger
logger = setup_logger()
