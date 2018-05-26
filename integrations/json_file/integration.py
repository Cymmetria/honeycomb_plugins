# -*- coding: utf-8 -*-
"""Honeycomb JSON integration."""

from __future__ import unicode_literals

import logging

from pythonjsonlogger import jsonlogger

from integrationmanager.exceptions import IntegrationSendEventError
from integrationmanager.integration_utils import BaseIntegration


class JsonIntegration(BaseIntegration):
    """Honeycomb JSON integration."""

    def send_event(self, alert_fields):
        """Write event to JSON file."""
        json_logger = logging.getLogger("honeycomb.json")
        json_logger.setLevel(logging.CRITICAL)
        json_logger.propagate = False

        for handler in json_logger.handlers[:]:
            json_logger.removeHandler(handler)

        json_handler = logging.handlers.WatchedFileHandler(filename=self.integration_data["filepath"])
        json_handler.setFormatter(jsonlogger.JsonFormatter("%(levelname)s %(asctime)s %(name)s %(message)s"))
        json_logger.addHandler(json_handler)

        try:
            json_logger.critical(alert_fields.get("event_description"), extra=alert_fields)
            return {}, None
        except Exception as exc:
            raise IntegrationSendEventError(exc)

    def format_output_data(self, output_data):
        """No special formatting needed."""
        return output_data


IntegrationActionsClass = JsonIntegration
