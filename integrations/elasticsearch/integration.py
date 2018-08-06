# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import requests

from integrationmanager.exceptions import IntegrationSendEventError
from integrationmanager.integration_utils import BaseIntegration

session = requests.Session()

class ElasticsearchIntegration(BaseIntegration):

    def send_event(self, alert_fields):
        user = self.integration_data.get("username", "").encode('utf-8')
        index = self.integration_data.get("index")
        verify = self.integration_data.get('verify', False)
        password = self.integration_data.get("password", "").encode('utf-8')

        url = "{}/{}".format(self.integration_data.get("url"), index)
        auth = (user, password) if (user or passwd) else None

        response = session.post(url=url, auth=auth, json=alert_fields, verify=verify)
        if response.status_code == 201:
            return {}, None

        raise IntegrationSendEventError("status code: {}, content: {}".format(response.status_code, response.content))

    def format_output_data(self, output_data):
        return output_data


IntegrationActionsClass = ElasticsearchIntegration
