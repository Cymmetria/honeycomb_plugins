# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import pjl_server
import web_server

from common_strings import ERROR_MSG


class XeroxHoneypot(object):
    def __init__(self, alert_callback, debug_callback, info_callback, logger):
        self.info = info_callback
        self.debug = debug_callback

        self.web = web_server.XeroxWebServer(alert_callback, debug_callback, info_callback)
        self.web.logger = logger
        self.pjl = pjl_server.XeroxPJLServer(alert_callback, debug_callback, info_callback)
        self.pjl.logger = logger

    def start(self):
        self.info("Starting {name}".format(name=self))
        try:
            self.web.start()
            self.pjl.start()
            self.pjl.thread.join()
        except Exception as err:
            self.debug(ERROR_MSG.format(error=err))
            self.stop()

    def stop(self):
        self.pjl.stop()
        self.web.stop()

    def __str__(self):
        return "Xerox Honeypot Server"
