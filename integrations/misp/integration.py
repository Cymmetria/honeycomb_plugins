# -*- coding: utf-8 -*-
"""Honeycomb MISP integration."""
from __future__ import unicode_literals

import six
from pymisp import PyMISP

from integrationmanager.exceptions import IntegrationSendEventError
from integrationmanager.integration_utils import BaseIntegration

URL = "url"
KEY = "key"
VERIFY_SSL = "verify_ssl"
SSL_CA_PATH = "ssl_ca_path"


class MISPIntegration(BaseIntegration):
    """Honeycomb MISP integration."""

    misp = None
    """MISP instance."""

    misp_dict = {
        "originating_ip": [("add_ipsrc", "ipsrc")],
        "originating_hostname": [("add_hostname", "hostname")],

        "domain": ["add_domain"],

        "image_path": [("add_filename", "filename"), ("add_attachment", "attachment")],
        "image_sha256": [("add_hashes", "sha256")],
        "MD5": [("add_hashes", "md5")],

        # Extra fields:
        "additional_fields": "",
    }
    """A list of methods to call on event. Methods are tuples of (method_name, value_kwarg)."""

    def send_event(self, alert_dict):
        """Send MISP event.

        PyMISP parameters are passed directly to requests.
        The `ssl` parameter can be either True/False to control requests.Session.verify,
        but can also be a path to CA cert file

        .. seealso:: http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification
        """
        if not self.misp:
            url = self.integration_data[URL]
            key = self.integration_data[KEY]
            verify_ssl = self.integration_data.get(VERIFY_SSL)
            ssl_ca_path = self.integration_data.get(SSL_CA_PATH)
            ssl = ssl_ca_path if ssl_ca_path else verify_ssl
            try:
                self.misp = PyMISP(url, key, ssl)
            except Exception as exc:
                raise IntegrationSendEventError(str(exc))

        try:
            event = self.misp.new_event(info=alert_dict["event_description"], date=alert_dict["timestamp"])
            self.misp.add_internal_text(event, "Honeycomb alert details", comment=repr(alert_dict))
            for (field, value) in six.iteritems(alert_dict):
                misp_action = self.misp_dict.get(field, [])
                for action in misp_action:
                    method, kwarg = action
                    kwargs = {"event": event, kwarg: value}
                    getattr(self.misp, method)(**kwargs)
            return {}, None

        except Exception as exc:
            raise IntegrationSendEventError(exc)

    def test_connection(self, data):
        """Test connectivity to MISP and fetch details about server.

        Parameters are passed directly to PyMISP which in turn passes them to requests.
        The `ssl` parameter can be either True/False to control verify_ssl but can also be a path to CA cert file
        .. seealso:: http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification
        """
        url = data[URL]
        key = data[KEY]
        verify_ssl = data.get(VERIFY_SSL)
        ssl_ca_path = data.get(SSL_CA_PATH)

        # PyMISP takes (and passes to requests) True/False to validate ssl, or a path to a CA cert file
        # We do this swap here because integration parameters aren"t that flexible
        ssl = ssl_ca_path if ssl_ca_path else verify_ssl

        success = True
        response = {}
        try:
            self.misp = PyMISP(url, key, ssl)
            response = None
        except Exception as exc:
            success = False
            response["non_field_errors"] = str(exc)

        return success, response

    def format_output_data(data):
        """No special formatting needed."""
        return data


IntegrationActionsClass = MISPIntegration
