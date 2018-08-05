# -*- coding: utf-8 -*-
"""Struts Honeycomb Service."""
from __future__ import unicode_literals

import json
import os
import re
import shutil
import tempfile
import time

from base_service import DockerService


class StrutsService(DockerService):
    """Struts service."""

    def __init__(self, *args, **kwargs):
        super(StrutsService, self).__init__(*args, **kwargs)
        self.folder_files = None

    def on_server_start(self):
        """Start server."""
        self.folder_files = tempfile.mkdtemp()
        os.chmod(self.folder_files, 0777)
        super(StrutsService, self).on_server_start()

    def on_server_shutdown(self):
        """Shutdown server."""
        super(StrutsService, self).on_server_shutdown()
        if self.folder_files and os.path.exists(self.folder_files):
            shutil.rmtree(self.folder_files)

    @property
    def docker_params(self):
        """Docker parameters for logs and port binds."""
        return dict(
            ports={80: 80},
            volumes={self.folder_files: {"bind": "/var/log/apache2/", "mode": "rw"}})

    @property
    def docker_image_name(self):
        """Docker image name."""
        return "galcymmetria/struts_honeypot"

    def parse_line(self, line):
        """Parse the line from the log files and return alert dict if needed."""
        result = re.match(r".*\[client .*\] (?P<json>.*)", line)
        if not result:
            return None
        json_output = result.groupdict()["json"].decode("string_escape")
        result_dict = json.loads(json_output)
        return {
            "event_type": "struts_exploit",
            "originating_ip": result_dict["src"],
            "originating_port": result_dict["sport"],
            "request": result_dict["uri"],
            "additional_fields": "User agent: {}, ctypes: {}".format(result_dict["ua"], result_dict["ctype"])
        }

    def get_lines(self):
        """Get lines from the apache error log."""
        error_log = os.path.join(self.folder_files, "error.log")
        while True:
            if os.path.exists(error_log):
                break
            time.sleep(1)
        return self.read_lines(error_log)


service_class = StrutsService
