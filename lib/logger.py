import logging
import sys

class Logger(object):

    @classmethod
    def create_logger(cls, name, stream=sys.stdout, filename=None, console_level=logging.DEBUG, file_level=logging.DEBUG):
        logger = logging.getLogger(name)

        # Set default level for all logging this can be overridden with console_level and file_level
        logger.setLevel(logging.DEBUG)

        formatter = logging.Formatter(fmt='%(name)s:%(levelname)s: %(message)s')

        # Create a console handler
        if stream:
            ch = logging.StreamHandler(stream)
            ch.setFormatter(formatter)
            ch.setLevel(console_level)
            logger.addHandler(ch)

        # Create a file handler if filename is specified
        if filename:
            fh = logging.FileHandler(filename)
            fh.formatter(formatter)
            fh.formatter(file_level)
            logger.addHandler(fh)

        return logger

    def __init__(self, name, filename=None, console_level=logging.INFO, file_level=logging.INFO):
        self._LOGGER = self.create_logger(name, filename, console_level, file_level)

    def get_logger(self):
        return self._LOGGER
