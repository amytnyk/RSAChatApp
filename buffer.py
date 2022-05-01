from socket import socket
from sha256 import SHA


class PacketLossError(Exception):
    pass


class Reader:
    def __init__(self, sock: socket):
        self.sock = sock

    def read(self) -> bytes:
        size = int.from_bytes(self.sock.recv(4), "big")
        checksum = self.sock.recv(32)
        data = self.sock.recv(size)
        if checksum != SHA.checksum(data):
            raise PacketLossError
        return data


class Writer:
    def __init__(self, sock: socket):
        self.sock = sock

    def send(self, data: bytes):
        self.sock.send(len(data).to_bytes(4, "big") + SHA.checksum(data) + data)
