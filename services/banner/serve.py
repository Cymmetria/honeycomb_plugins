import sys
import socket

s = socket.socket()
s.bind(('0.0.0.0', int(sys.argv[1])))
s.listen(10)
recv_sock, address = s.accept()
recv_sock.shutdown(socket.SHUT_RDWR)
recv_sock.close()
s.close()
