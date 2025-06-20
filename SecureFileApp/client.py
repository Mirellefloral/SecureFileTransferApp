import socket
import ssl
import os

# Server Configuration
SERVER_HOST = '192.168.1.75'  # replace with actual IP
SERVER_PORT = 4443
SERVER_CERT = 'server.crt'

def upload_file(filename):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=SERVER_CERT)
    if not os.path.exists(filename):
        print("File does not exist.")
        return

    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
            ssock.sendall(b"UPLOAD")
            try:
                # Normalize and send the file name
                normalized_filename = os.path.normpath(filename).replace(os.sep, '/')
                ssock.sendall(normalized_filename.encode() + b'\n')

                # Send the file size
                file_size = os.path.getsize(filename)
                ssock.sendall(f"{file_size}\n".encode())

                # Send the file content
                with open(filename, 'rb') as f:
                    while True:
                        data = f.read(4096)
                        if not data:
                            break
                        ssock.sendall(data)

                # ✅ ADD this after sending all data
                ssock.shutdown(socket.SHUT_WR)

                print("File uploaded successfully.")

            except Exception as e:
                print(f"An error occurred: {e}")

def download_file(filename):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=SERVER_CERT)
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
            ssock.sendall(b"DOWNLOAD")
            ssock.sendall(filename.encode() + b'\n')

            response = ssock.recv(4096)
            if response.startswith(b"ERROR"):
                print(response.decode())
                return

            filesize = int(response.decode().strip())
            with open('downloaded_' + os.path.basename(filename), 'wb') as f:
                bytes_read = 0
                while bytes_read < filesize:
                    data = ssock.recv(4096)
                    if not data:
                        break
                    f.write(data)
                    bytes_read += len(data)

            print("File downloaded successfully.")

def list_files():
    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=SERVER_CERT)
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
            ssock.sendall(b"LIST")
            data = ssock.recv(4096).decode()
            print("\nAvailable files on server:")
            print(data)


if __name__ == "__main__":
    choice = input("Do you want to (U)pload, (D)ownload, or (L)ist files? ").strip().upper()

    if choice == 'U':
        filename = input("Enter the path to the file to upload: ").strip()
        upload_file(filename)
    elif choice == 'D':
        filename = input("Enter the filename to download: ").strip()
        download_file(filename)
    elif choice == 'L':
        list_files()
    else:
        print("Invalid choice.")

