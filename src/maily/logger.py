import time
import socket
import logging
import requests
import traceback
from maily.config import SLACK_WEB_HOOK

NOTIFY_LEVEL_NUM = 100


class SlackHandler(logging.Handler):
    def __init__(self, webhook_url):
        super().__init__()
        self.webhook_url = webhook_url

    def emit(self, record):
        if record.levelname == 'NOTIFY' or record.levelname == 'ERROR':
            msg = '```%s```' % self.format(record)
            payload = {"text": msg}
            try:
                requests.post(json=payload, url=self.webhook_url)
            except requests.exceptions.RequestException:
                pass


class Logger:
    @staticmethod
    def __init__(slack_webhook_url):
        # logging.getLogger('pika').propagate = False

        format_string = '%(asctime)s {hostname} %(levelname)s %(message)s'.format(**{'hostname': socket.gethostname()})
        format_log = logging.Formatter(format_string)
        format_log.converter = time.gmtime

        logging.basicConfig(level=logging.INFO)
        logging.disable(logging.DEBUG)
        for handler in logging.getLogger().handlers:
            logging.getLogger().removeHandler(handler)

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(format_log)
        logging.getLogger().addHandler(stream_handler)

        slack_handler = SlackHandler(slack_webhook_url)
        slack_handler.setFormatter(format_log)
        logging.getLogger().addHandler(slack_handler)

        logging.addLevelName(NOTIFY_LEVEL_NUM, "NOTIFY")

    @staticmethod
    def info(msg):
        logging.info(msg)

    @staticmethod
    def warning(msg):
        logging.warning(msg)

    @staticmethod
    def notify(message):
        logging.log(NOTIFY_LEVEL_NUM, message)

    @staticmethod
    def error(trace=None):
        if trace is None:
            tb = traceback.format_exc()
            trace = 'Something was wrong' if tb is None else tb
        logging.error(trace)


logger = Logger(SLACK_WEB_HOOK)
