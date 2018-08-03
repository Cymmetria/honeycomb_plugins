# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import json
import requests

from integrationmanager.exceptions import IntegrationSendEventError
from integrationmanager.integration_utils import BaseIntegration

logger = logging.getLogger(__name__)


class ElasticsearchIntegration(BaseIntegration):

    def send_event(self, alert_fields):
        address = self.integration_data["url_address"]
        port = self.integration_data["port"]
        index = self.integration_data["index"]
        user = self.integration_data.get("username", "").encode('utf-8')
        passwd = self.integration_data.get("password", "").encode('utf-8')
        url = "{}:{}/{}".format(address, port, index)
        skip_cert_validation = self.integration_data.get('skip_cert_validation', False)
        format_alert = json.dumps(alert_fields,
                                  indent=4,
                                  sort_keys=True,
                                  default=str)
        response = requests.post(url=url,
                                 auth=(user, passwd),
                                 data=format_alert,
                                 headers={"Content-type": "application/json"},
                                 verify=not skip_cert_validation)
        logger.info(alert_fields)
        if response.status_code == 201:
            return {}, None

        raise IntegrationSendEventError("status code: {}, content: {}".format(response.status_code, response.content))

    def format_output_data(self, output_data):
        return output_data


IntegrationActionsClass = ElasticsearchIntegration
