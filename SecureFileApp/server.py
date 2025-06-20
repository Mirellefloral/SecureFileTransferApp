import socket
import ssl
import os

SERVER_CERT = 'server.crt'
SERVER_KEY = 'server.key'
UPLOAD_DIR = 'uploads'

if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 4443))
server_socket.listen(5)

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)

print("Server listening on 0.0.0.0:4443")

while True:
    conn, addr = server_socket.accept()
    with context.wrap_socket(conn, server_side=True) as ssock:
        print(f"Connection established with {addr}")
        command = ssock.recv(4096).decode().strip()

        if command == "UPLOAD":
            filename = ssock.recv(4096).decode().strip()
            safe_filename = os.path.basename(filename)
            filepath = os.path.join(UPLOAD_DIR, safe_filename)
            print(f"Saving to: {filepath}")

            filesize = int(ssock.recv(4096).decode().strip())

            with open(filepath, 'wb') as f:
                bytes_read = 0
                while bytes_read < filesize:
                    data = ssock.recv(4096)
                    if not data:
                        break
                    f.write(data)
                    bytes_read += len(data)

            print(f"File '{safe_filename}' uploaded successfully.")

        elif command == "DOWNLOAD":
            filename = ssock.recv(4096).decode().strip()
            safe_filename = os.path.basename(filename)
            filepath = os.path.join(UPLOAD_DIR, safe_filename)

            if not os.path.exists(filepath):
                ssock.sendall(b"ERROR: File does not exist\n")
                print(f"Requested file '{safe_filename}' does not exist.")
            else:
                filesize = os.path.getsize(filepath)
                ssock.sendall(f"{filesize}\n".encode())  # Send file size first

                with open(filepath, 'rb') as f:
                    while True:
                        data = f.read(4096)
                        if not data:
                            break
                        ssock.sendall(data)
                print(f"File '{safe_filename}' sent successfully.")

        elif command == "LIST":
            # List all files in the uploads directory
            files = os.listdir(UPLOAD_DIR)
            if not files:
                ssock.sendall(b"No files available.\n")
            else:
                file_list = "\n".join(files) + "\n"
                ssock.sendall(file_list.encode())
            print("Sent list of files to client.")
