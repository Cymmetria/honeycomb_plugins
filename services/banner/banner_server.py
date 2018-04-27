# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import sys
import time
import socket
import select
import collections

LISTEN_BACKLOG = 10
SELECT_TIMEOUT = 1
RECV_BUFFSIZE = 1000

MAX_SOCK_DURATION = 20 # in seconds

RESOURCE_UNAVAILABLE_ERROR = 35

def _create_listen_socket(port_number):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port_number))
        s.listen(LISTEN_BACKLOG)
    except socket.error, e:
        print e, port_number
        raise
    return s

def _recv_all(sock, max_time):
    result = []
    while time.time() < max_time:
        new_data = None
        try:
            new_data = sock.recv(RECV_BUFFSIZE)
        except socket.error, e:
            if e.args[0] == RESOURCE_UNAVAILABLE_ERROR:
                #no data to read
                break
        if new_data:
            result.append(new_data)
        else:
            break
    return ''.join(result)


class MultiSocketServer(object):
    def __init__(self, listen_ports, banner, alert_function):
        self.listen_sockets = set()
        self.recv_sockets = set()
        self.recv_socket_max_time = {}
        self.recv_socket_data = collections.defaultdict(list)
        self.recv_socket_peers = {}
        self.banner = banner
        self.alert_function = alert_function
        #the reason this is done in a loop and not in a set comprehension is that if there's
        #an exception, we want the already created sockets to be recorded
        for port in listen_ports:
            try:
                self.listen_sockets.add(_create_listen_socket(port))
            except socket.error as e:
                print port
                raise

    def close_all(self):
        if hasattr(self, 'recv_sockets'):
            for sock in self.recv_sockets:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except socket.error:
                    pass
                sock.close()
            self.recv_sockets = set()
        if hasattr(self, 'listen_sockets'):
            for sock in self.listen_sockets:
                sock.close()
            self.listen_sockets = set()

    def __del__(self):
        if hasattr(self, 'close_all'):
            self.close_all()

    def _close_timeout_sockets(self):
        for sock in set(self.recv_sockets):
            if time.time() > self.recv_socket_max_time[sock]:
                peer_name = self.recv_socket_peers[sock]
                if self.recv_socket_data[sock]:
                    self.alert_function(
                        data = ''.join(self.recv_socket_data[sock]),
                        originating_ip = peer_name[0],
                        originating_port = peer_name[1],
                        dest_port = sock.getsockname()[1])
                self.recv_sockets.remove(sock)
                del self.recv_socket_max_time[sock]
                #this will not raise exception because we checked if sock is in the dict earlier
                del self.recv_socket_data[sock]
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except socket.error:
                    pass
                sock.close()

    def serve_forever(self):
        while True:
            self._close_timeout_sockets()

            select_result = select.select(self.listen_sockets | self.recv_sockets, [], [], SELECT_TIMEOUT)
            ready_sockets = select_result[0]
            for sock in ready_sockets:
                if sock in self.listen_sockets:
                    new_socket, remote_addr = sock.accept()
                    new_socket.settimeout(0)
                    self.recv_socket_peers[new_socket] = remote_addr
                    self.recv_socket_max_time[new_socket] = time.time() + MAX_SOCK_DURATION
                    self.recv_sockets.add(new_socket)
                    new_socket.send(self.banner)
                    continue
                recv_data = _recv_all(sock, self.recv_socket_max_time[sock])
                if recv_data:
                    self.recv_socket_data[sock].append(recv_data)


def main():
    def print_function(*args, **kwargs):
        print args, kwargs
    server = MultiSocketServer([int(sys.argv[1])], "hello world!\n", print_function)
    server.serve_forever()

if __name__ == '__main__':
    main()
