#!/usr/bin/env python

import socket
import sys
import threading
import traceback

import paramiko
from paramiko import util
from paramiko import Message
from paramiko.py3compat import b, decodebytes, long
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

# setup logging
paramiko.util.log_to_file("demo_server.log")

host_key = paramiko.RSAKey(filename="test_rsa.key")

SERVER_SIG = "SSH-2.0-libssh_0.7.4"


class CVETransport(paramiko.Transport):
    alert = None
    def __init__(self, *args, **kwargs):
        super(CVETransport, self).__init__(*args, **kwargs)
        self.local_version = SERVER_SIG

    def run(self):
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
                    if ptype == MSG_USERAUTH_SUCCESS:
                        print("MSG_USERAUTH_SUCCESS")
                        continue
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
                        self.auth_handler is not None
                        and ptype in self.auth_handler._handler_table
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
        except:
            # Don't raise spurious 'NoneType has no attribute X' errors when we
            # wake up during interpreter shutdown. Or rather -- raise
            # everything *if* sys.modules (used as a convenient sentinel)
            # appears to still exist.
            if self.sys.modules is not None:
                raise


class SSHServer(paramiko.ServerInterface):
    data = (
        b"AAAAB3NzaC1yc2EAAAABIwAAAIEAyO4it3fHlmGZWJaGrfeHOVY7RWO3P9M7hp"
        b"fAu7jJ2d7eothvfeuoRFtJwhUmZDluRdFyhFY/hFAh76PJKGAusIqIQKlkJxMC"
        b"KDqIexkgHAfID/6mqvmnSJf0b5W8v5h2pI/stOSwTQ+pxVhwJ9ctYDhRSlF0iT"
        b"UWT10hcuO4Ks8="
    )
    good_pub_key = paramiko.RSAKey(data=decodebytes(data))

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_with_mic(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(
        self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None
    ):
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        return True

    def get_allowed_auths(self, username):
        return "gssapi-keyex,gssapi-with-mic,password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


def run_server():
    DoGSSAPIKeyExchange = True

    # now connect
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 2200))
    except Exception as e:
        print("*** Bind failed: " + str(e))
        traceback.print_exc()
        sys.exit(1)

    try:
        sock.listen(100)
        print("Listening for connection ...")
        client, addr = sock.accept()
    except Exception as e:
        print("*** Listen/accept failed: " + str(e))
        traceback.print_exc()
        sys.exit(1)

    print("Got a connection!")

    try:
        t = CVETransport(client, gss_kex=DoGSSAPIKeyExchange)
        t.set_gss_host(socket.getfqdn(""))
        try:
            t.load_server_moduli()
        except:
            print("(Failed to load moduli -- gex will be unsupported.)")
            raise
        t.add_server_key(host_key)
        server = SSHServer()
        try:
            t.start_server(server=server)
        except SSHException:
            print("*** SSH negotiation failed.")
            sys.exit(1)


        # wait for auth
        chan = t.accept(20)
        if chan is None:
            print("*** No channel.")
            sys.exit(1)
        print("Authenticated!")

        server.event.wait(10)
        if not server.event.is_set():
            print("*** Client never asked for a shell.")
            sys.exit(1)

        chan.close()

    except Exception as e:
        print("*** Caught exception: " + str(e.__class__) + ": " + str(e))
        traceback.print_exc()
        try:
            t.close()
        except:
            pass
        sys.exit(1)


def main():
    run_server()


if __name__ == "__main__":
    main()
