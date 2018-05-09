# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import socket
import errno
from collections import defaultdict

import gevent
import gevent.server
from telnetsrv.green import TelnetHandler, command

from base_service import ServerCustomService
from custom_pool import CustomPool


DEFAULT_TIMEOUT = 60  # Use to timeout the connection
POOL = 10
PORT = 23
IP_ADDRESS = "0.0.0.0"

MIRAI_DETECTED_EVENT_TYPE = "mirai_detection"
BUSYBOX_TELNET_INTERACTION_EVENT_TYPE = "busybox_telnet_execution"
BUSYBOX_TELNET_AUTHENTICATION = "busybox_telnet_authentication"
BUSYBOX_COMMAND_DESCRIPTION = "Command executed"

# Fields
EVENT_TYPE = "event_type"
CMD = "cmd"
USERNAME = "username"
PASSWORD = "password"
DESCRIPTION = "event_description"
ORIGINATING_IP = "originating_ip"
ORIGINATING_PORT = "originating_port"

DDOS_NAME = "Mirai"
COMMANDS = {
    "ECCHI": "ECCHI: applet not found",
    "ps": "1 pts/21   00:00:00 init",
    "cat /proc/mounts": "tmpfs /run tmpfs rw,nosuid,noexec,relatime,size=1635616k,mode=755 0 0",
    b"echo -e \\x6b\\x61\\x6d\\x69/dev > /dev/.nippon": "",
    "cat /dev/.nippon": "kami/dev",
    "rm /dev/.nippon": "",
    b"echo -e \\x6b\\x61\\x6d\\x69/run > /run/.nippon": "",
    "cat /run/.nippon": "kami/run",
    "rm /run/.nippon": "",
    "cat /bin/echo": b"\\x7fELF\\x01\\x01\\x01\\x03\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x08\\x00\\x00\\x00\\x00\\x00"
}

OVERWRITE_COMMANDS = {}  # Use to overwrite default telnet command behavior crashing the handler (e.g. 'help')
OVERWRITE_COMMANDS_LIST = ["help"]  # Don't forget to update the list when adding new commands

BUSY_BOX = "/bin/busybox"
MIRAI_SCANNER_COMMANDS = ["shell", "sh", "enable"]


class MyTelnetHandler(TelnetHandler, object):
    WELCOME = "welcome"
    PROMPT = ">"
    authNeedUser = True
    authNeedPass = True

    custom_pool = None
    logger = None
    active_users = {}
    ips_command_executed = defaultdict(list)

    def emit(self, alert_dict):
        raise NotImplementedError

    @command(OVERWRITE_COMMANDS_LIST)
    def telnet_commands_respond(self, params):
        self.writeresponse(OVERWRITE_COMMANDS.get(self.input.raw, ""))

    @command(MIRAI_SCANNER_COMMANDS)
    def shell_respond(self, params):
        self.writeresponse("")

    @command([BUSY_BOX])
    def handle_busybox(self, params):
        full_response = self._get_busybox_response(params)
        self.writeresponse(full_response)

    def authCallback(self, username, password):
        self.active_users[self.client_address] = {USERNAME: username, PASSWORD: password}

    def session_start(self):
        self._send_alert(**{DESCRIPTION: "Session started", EVENT_TYPE: BUSYBOX_TELNET_AUTHENTICATION})

    def session_end(self):
        self._send_alert(**{DESCRIPTION: "Session end", EVENT_TYPE: BUSYBOX_TELNET_AUTHENTICATION})
        self._disconnect()

    def _get_busybox_response(self, params):
        response = ""
        full_command = " ".join(params)
        for cmd in full_command.split(";"):
            cmd = cmd.strip()
            # Check for busybox executable
            if cmd.startswith(BUSY_BOX):
                cmd = cmd.replace(BUSY_BOX, "")
                cmd = cmd.strip()
            response += COMMANDS.get(cmd, "") + "\n"
            self._send_alert(**{CMD: cmd.strip(), EVENT_TYPE: BUSYBOX_TELNET_INTERACTION_EVENT_TYPE})
            self._store_command(cmd)
        return response

    def _send_alert(self, **kwargs):
        kwargs.update({
            ORIGINATING_IP: self.client_address[0],
            ORIGINATING_PORT: self.client_address[1],
            })
        kwargs.update(self.active_users.get(self.client_address, {}))
        self.emit(kwargs)

    def _is_fingerprinted(self):
        if all([self.ips_command_executed[self.client_address[0]].count(cmd) > 0 for cmd in COMMANDS]):
            self.logger.info(
                "confirmed IP: [%s:%d]", self.client_address[0], self.client_address[1])
            self._send_alert(**{EVENT_TYPE: MIRAI_DETECTED_EVENT_TYPE})
            self.ips_command_executed.pop(self.client_address[0], None)
        else:
            self.logger.debug("no fingerprinted for ip %s with executed commands %s",
                              self.client_address, self.ips_command_executed[self.client_address[0]])

    def _store_command(self, cmd):
        self.logger.debug(
            "[%s:%d] executed: %s", self.client_address[0], self.client_address[1], cmd.strip())

        self.ips_command_executed[self.client_address[0]].append(cmd)
        self._is_fingerprinted()

    def inputcooker(self):
        try:
            super(MyTelnetHandler, self).inputcooker()
        except socket.timeout:
            self.custom_pool.remove_connection(str(self.client_address[0]) + ':' + str(self.client_address[1]))
            self.logger.debug("[%s:%d] session timed out", self.client_address[0], self.client_address[1])
            self.finish()
            self._disconnect()
        except socket.error as e:
            if e.errno != errno.EBADF: # file descriptor error
                raise
            else:
                pass

    def _disconnect(self):
        self.active_users.pop(self.client_address, None)
        self.ips_command_executed.pop(self.client_address[0], None)


class MiraiWormMonitorService(ServerCustomService):
    def __init__(self, *args, **kwargs):
        super(MiraiWormMonitorService, self).__init__(*args, **kwargs)
        self.server = None

    def __str__(self):
        return "MiraiWormMonitor"

    def on_server_shutdown(self):
        if not self.server:
            return
        self.server.stop()

    def on_server_start(self):
        socket.setdefaulttimeout(DEFAULT_TIMEOUT)
        custom_pool = CustomPool(self.logger, POOL)

        handler = MyTelnetHandler
        handler.custom_pool = custom_pool
        handler.logger = self.logger
        handler.emit = self.add_alert_to_queue

        self.server = gevent.server.StreamServer(
            (IP_ADDRESS, PORT),
            handler.streamserver_handle,
            spawn=custom_pool)

        self.signal_ready()
        self.server.serve_forever()

    def test(self):
        """trigger service alerts and return a list of triggered event types"""

        event_types = [BUSYBOX_TELNET_AUTHENTICATION]
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(2)
        client_socket.connect(("127.0.0.1", PORT))
        client_socket.send("my_username\r\n")
        client_socket.send("mypass\r\n")
        for command in COMMANDS:
            event_types.append(BUSYBOX_TELNET_INTERACTION_EVENT_TYPE)
            client_socket.send("{shell} {command}\r\n".format(shell=BUSY_BOX, command=command))

        event_types.append(MIRAI_DETECTED_EVENT_TYPE)
        client_socket.send("bye\r\n")
        event_types.append(BUSYBOX_TELNET_AUTHENTICATION)

        return event_types


service_class = MiraiWormMonitorService
