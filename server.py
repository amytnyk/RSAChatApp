import socket
import threading
from typing import List
from buffer import Reader, Writer
from rsa import RSA


class Client:
    def __init__(self, conn: socket, server):
        self.conn = conn
        self.server = server
        self.reader = Reader(conn)
        self.writer = Writer(conn)

        self.name = self.reader.read().decode('utf-8')
        self.server.broadcast(f'New person has joined: {self.name}')

        self.writer.send(self.server.public_key.to_bytes())
        self.client_key = RSA.PublicKey.from_bytes(self.reader.read())

        threading.Thread(target=self.listen, args=()).start()

    def listen(self):
        while True:
            msg = self.server.private_key.decrypt(self.reader.read())
            self.server.broadcast(msg.decode('utf-8'), self)

    def send(self, text: str):
        self.writer.send(self.client_key.encrypt(text.encode('utf-8')))

    def __eq__(self, other):
        return self.conn == other.conn


class Server:
    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients: List[Client] = []
        self.public_key, self.private_key = RSA(1024).generate_keys()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.host, self.port))
            sock.listen(100)

            while True:
                self.clients.append(Client(sock.accept()[0], self))

    def broadcast(self, msg: str, user: Client = None):
        if user:
            msg = f"[{user.name}] - {msg}"
        for client in self.clients:
            if not user or client != user:
                client.send(msg)
        print(msg)


if __name__ == "__main__":
    Server(8080).start()
