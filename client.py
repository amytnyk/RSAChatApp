import socket
import threading
from buffer import Reader, Writer
from rsa import RSA


class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.public_key, self.private_key = RSA(1024).generate_keys()
        self.reader, self.writer, self.server_key = None, None, None

    def connect(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
            try:
                self.sock.connect((self.server_ip, self.port))
            except Exception as e:
                print("[client]: could not connect to server: ", e)
                return

            self.reader = Reader(self.sock)
            self.writer = Writer(self.sock)

            self.writer.send(self.username.encode('utf-8'))
            self.server_key = RSA.PublicKey.from_bytes(self.reader.read())
            self.writer.send(self.public_key.to_bytes())

            message_handler = threading.Thread(target=self.listen, args=())
            message_handler.start()
            input_handler = threading.Thread(target=self.write_handler, args=())
            input_handler.start()

            message_handler.join()
            input_handler.join()

    def listen(self):
        while True:
            print(self.private_key.decrypt(self.reader.read()).decode('utf-8'))

    def write_handler(self):
        while True:
            self.writer.send(self.server_key.encrypt(input().encode('utf-8')))


if __name__ == "__main__":
    Client("127.0.0.1", 8080, input("Enter username: ")).connect()
