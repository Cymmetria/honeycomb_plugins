# -*- coding: utf-8 -*-
#!/usr/bin/env python # noqa: E265
"""libssh Honeycomb Service with CVE-2018-10933 support."""
from __future__ import unicode_literals

import socket
import sys
import os
import threading
import struct
from six.moves.socketserver import ThreadingTCPServer, StreamRequestHandler

import paramiko
from paramiko import util
from paramiko import Message
from paramiko.py3compat import b, long
from paramiko.transport import _active_threads
from paramiko.common import (
    xffffffff,
    MSG_KEXINIT,
    DEBUG,
    ERROR,
    WARNING,
    MSG_IGNORE,
    MSG_DISCONNECT,
    MSG_DEBUG,
    MSG_NAMES,
    MSG_UNIMPLEMENTED,
    MSG_USERAUTH_SUCCESS,
    cMSG_UNIMPLEMENTED,
)
from paramiko.ssh_exception import SSHException
from paramiko.packet import NeedRekeyException

from consts import SERVER_SIG, EVENT_TYPE_FIELD_NAME, SSH_ALERT_TYPE, USERNAME_FIELD_NAME, PASSWORD_FIELD_NAME,\
    ADDITIONAL_FIELDS_FIELD_NAME, KEY_FIELD_NAME, CVE_SSH_PORT

# setup logging
paramiko.util.log_to_file("demo_server.log")
host_key = paramiko.RSAKey(filename=os.path.join(os.path.dirname(__file__), "test_rsa.key"))


class CVETransport(paramiko.Transport):
    """Implementation of the ssh transport server with the detection of the CVE-2018-10933 vulnerability."""

    alert = None

    def __init__(self, *args, **kwargs):
        super(CVETransport, self).__init__(*args, **kwargs)
        self.local_version = SERVER_SIG

    def run(self):
        """
        Run function from paramiko.Transport.

        This function was copied from Paramiko (paramiko.Transport) in order to implement the CVE-2018-10933
        vulnerability. The only change in this function is where we added if ptype == MSG_USERAUTH_SUCCESS.
        """
        # noqa: W503, E722
        # (use the exposed "run" method, because if we specify a thread target
        # of a private method, threading.Thread will keep a reference to it
        # indefinitely, creating a GC cycle and not letting Transport ever be
        # GC'd. it's a bug in Thread.)

        # Hold reference to 'sys' so we can test sys.modules to detect
        # interpreter shutdown.
        self.sys = sys

        # active=True occurs before the thread is launched, to avoid a race
        _active_threads.append(self)
        tid = hex(long(id(self)) & xffffffff)
        if self.server_mode:
            self._log(DEBUG, "starting thread (server mode): {}".format(tid))
        else:
            self._log(DEBUG, "starting thread (client mode): {}".format(tid))
        try:
            try:
                self.packetizer.write_all(b(self.local_version + "\r\n"))
                self._log(
                    DEBUG,
                    "Local version/idstring: {}".format(self.local_version),
                )  # noqa
                self._check_banner()
                # The above is actually very much part of the handshake, but
                # sometimes the banner can be read but the machine is not
                # responding, for example when the remote ssh daemon is loaded
                # in to memory but we can not read from the disk/spawn a new
                # shell.
                # Make sure we can specify a timeout for the initial handshake.
                # Re-use the banner timeout for now.
                self.packetizer.start_handshake(self.handshake_timeout)
                self._send_kex_init()
                self._expect_packet(MSG_KEXINIT)

                while self.active:
                    if self.packetizer.need_rekey() and not self.in_kex:
                        self._send_kex_init()
                    try:
                        ptype, m = self.packetizer.read_message()
                    except NeedRekeyException:
                        continue
                    # START - This is the part the implements the detection of CVE-2018-10933
                    if ptype == MSG_USERAUTH_SUCCESS:
                        self.alert(self.sock)
                        continue
                    # END - This is the part the implements the detection of CVE-2018-10933
                    if ptype == MSG_IGNORE:
                        continue
                    elif ptype == MSG_DISCONNECT:
                        self._parse_disconnect(m)
                        break
                    elif ptype == MSG_DEBUG:
                        self._parse_debug(m)
                        continue
                    if len(self._expected_packet) > 0:
                        if ptype not in self._expected_packet:
                            raise SSHException(
                                "Expecting packet from {!r}, got {:d}".format(
                                    self._expected_packet, ptype
                                )
                            )  # noqa
                        self._expected_packet = tuple()
                        if (ptype >= 30) and (ptype <= 41):
                            self.kex_engine.parse_next(ptype, m)
                            continue

                    if ptype in self._handler_table:
                        error_msg = self._ensure_authed(ptype, m)
                        if error_msg:
                            self._send_message(error_msg)
                        else:
                            self._handler_table[ptype](self, m)
                    elif ptype in self._channel_handler_table:
                        chanid = m.get_int()
                        chan = self._channels.get(chanid)
                        if chan is not None:
                            self._channel_handler_table[ptype](chan, m)
                        elif chanid in self.channels_seen:
                            self._log(
                                DEBUG,
                                "Ignoring message for dead channel {:d}".format(  # noqa
                                    chanid
                                ),
                            )
                        else:
                            self._log(
                                ERROR,
                                "Channel request for unknown channel {:d}".format(  # noqa
                                    chanid
                                ),
                            )
                            break
                    elif (
                        self.auth_handler is not None and
                        ptype in self.auth_handler._handler_table
                    ):
                        handler = self.auth_handler._handler_table[ptype]
                        handler(self.auth_handler, m)
                        if len(self._expected_packet) > 0:
                            continue
                    else:
                        # Respond with "I don't implement this particular
                        # message type" message (unless the message type was
                        # itself literally MSG_UNIMPLEMENTED, in which case, we
                        # just shut up to avoid causing a useless loop).
                        name = MSG_NAMES[ptype]
                        warning = "Oops, unhandled type {} ({!r})".format(
                            ptype, name
                        )
                        self._log(WARNING, warning)
                        if ptype != MSG_UNIMPLEMENTED:
                            msg = Message()
                            msg.add_byte(cMSG_UNIMPLEMENTED)
                            msg.add_int(m.seqno)
                            self._send_message(msg)
                    self.packetizer.complete_handshake()
            except SSHException as e:
                self._log(ERROR, "Exception: " + str(e))
                self._log(ERROR, util.tb_strings())
                self.saved_exception = e
            except EOFError as e:
                self._log(DEBUG, "EOF in transport thread")
                self.saved_exception = e
            except socket.error as e:
                if type(e.args) is tuple:
                    if e.args:
                        emsg = "{} ({:d})".format(e.args[1], e.args[0])
                    else:  # empty tuple, e.g. socket.timeout
                        emsg = str(e) or repr(e)
                else:
                    emsg = e.args
                self._log(ERROR, "Socket exception: " + emsg)
                self.saved_exception = e
            except Exception as e:
                self._log(ERROR, "Unknown exception: " + str(e))
                self._log(ERROR, util.tb_strings())
                self.saved_exception = e
            _active_threads.remove(self)
            for chan in list(self._channels.values()):
                chan._unlink()
            if self.active:
                self.active = False
                self.packetizer.close()
                if self.completion_event is not None:
                    self.completion_event.set()
                if self.auth_handler is not None:
                    self.auth_handler.abort()
                for event in self.channel_events.values():
                    event.set()
                try:
                    self.lock.acquire()
                    self.server_accept_cv.notify()
                finally:
                    self.lock.release()
            self.sock.close()
        except:  # noqa: E722
            # Don't raise spurious 'NoneType has no attribute X' errors when we
            # wake up during interpreter shutdown. Or rather -- raise
            # everything *if* sys.modules (used as a convenient sentinel)
            # appears to still exist.
            if self.sys.modules is not None:
                raise


class ParamikoSSHServer(paramiko.ServerInterface):  # noqa: D101
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):  # noqa: D102
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):  # noqa: D102
        data = {
            EVENT_TYPE_FIELD_NAME: SSH_ALERT_TYPE,
            USERNAME_FIELD_NAME: username,
            PASSWORD_FIELD_NAME: password
        }
        self.alert(self.socket, **data)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):  # noqa: D102
        data = {
            EVENT_TYPE_FIELD_NAME: SSH_ALERT_TYPE,
            USERNAME_FIELD_NAME: username,
            ADDITIONAL_FIELDS_FIELD_NAME: {
                KEY_FIELD_NAME: key.get_base64()
            }
        }
        self.alert(self.socket, **data)
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_with_mic(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):  # noqa: D102
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):  # noqa: D102
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):  # noqa: D102
        return True

    def get_allowed_auths(self, username):  # noqa: D102
        return "gssapi-keyex,gssapi-with-mic,password,publickey"

    def check_channel_shell_request(self, channel):  # noqa: D102
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):  # noqa: D102
        return True


class SSHRequestHandler(StreamRequestHandler):  # noqa: D101

    alert = None
    chan = None
    transport = None
    paramiko_server = None

    def handle(self):  # noqa: D102
        self.transport = CVETransport(self.connection, gss_kex=True)
        self.transport.alert = self.alert
        self.transport.set_gss_host(socket.getfqdn(""))
        self.transport.load_server_moduli()
        self.transport.add_server_key(host_key)
        self.paramiko_server = ParamikoSSHServer()
        self.paramiko_server.socket = self.connection
        self.paramiko_server.alert = self.alert
        try:
            self.transport.start_server(server=self.paramiko_server)
        except SSHException:
            return

        self.chan = self.transport.accept(20)
        if not self.chan:
            return
        self.chan.close()


class SSHServer(object):
    """SSHServer object."""

    def run(self, port):  # noqa: D102
        requestHandler = SSHRequestHandler
        requestHandler.alert = self.alert

        self.server = ThreadingTCPServer(("", port), requestHandler)
        # This prevents the timewait on the socket that prevents us from restarting the honeypot right
        # away after closing
        self.server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))

        self.server.serve_forever()

    def shutdown(self):  # noqa: D102
        if not self.server:
            return
        self.server.shutdown()


def main():
    """Run the server directly."""
    s = SSHServer()
    s.run(CVE_SSH_PORT)


if __name__ == "__main__":
    main()
