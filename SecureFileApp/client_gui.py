import socket
import ssl
import os
import tkinter as tk
from tkinter import filedialog, scrolledtext

# Config
SERVER_PORT = 4443
SERVER_CERT = 'server.crt'

# GUI setup
root = tk.Tk()
root.title("Client")

def log(message):
    log_area.insert(tk.END, message + '\n')
    log_area.see(tk.END)

def upload_file():
    server_ip = server_ip_entry.get().strip()
    if not server_ip:
        log("Please enter the server IP address.")
        return

    filename = filedialog.askopenfilename()
    if not filename:
        return

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=SERVER_CERT)
    try:
        with socket.create_connection((server_ip, SERVER_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=server_ip) as ssock:
                ssock.sendall(b"UPLOAD\n")

                # Send file name
                normalized_filename = os.path.basename(filename)
                ssock.sendall((normalized_filename + '\n').encode())

                # Send file size
                file_size = os.path.getsize(filename)
                ssock.sendall(f"{file_size}\n".encode())

                # Send file data
                with open(filename, 'rb') as f:
                    while True:
                        data = f.read(4096)
                        if not data:
                            break
                        ssock.sendall(data)

                # ✅ Important: tell server "I'm done sending"
                ssock.shutdown(socket.SHUT_WR)

                log(f"✅ File '{normalized_filename}' uploaded successfully.")

    except Exception as e:
        log(f"Upload error: {e}")

def download_file():
    server_ip = server_ip_entry.get().strip()
    if not server_ip:
        log("Please enter the server IP address.")
        return

    filename = filedialog.asksaveasfilename()
    if not filename:
        return

    basename = os.path.basename(filename)

    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=SERVER_CERT)
        with socket.create_connection((server_ip, SERVER_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=server_ip) as ssock:
                ssock.sendall(b"DOWNLOAD\n")
                ssock.sendall((basename + "\n").encode())

                # Receive file size
                filesize_data = b""
                while not filesize_data.endswith(b'\n'):
                    part = ssock.recv(1)
                    if not part:
                        raise Exception("Connection closed before receiving file size.")
                    filesize_data += part

                if b"ERROR" in filesize_data:
                    log(filesize_data.decode().strip())
                    return

                filesize = int(filesize_data.decode().strip())

                with open(filename, 'wb') as f:
                    bytes_read = 0
                    while bytes_read < filesize:
                        data = ssock.recv(4096)
                        if not data:
                            break
                        f.write(data)
                        bytes_read += len(data)

                log(f"✅ File '{basename}' downloaded successfully.")

    except Exception as e:
        log(f"Download error: {e}")

def list_files():
    server_ip = server_ip_entry.get().strip()
    if not server_ip:
        log("Please enter the server IP address.")
        return

    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=SERVER_CERT)
        with socket.create_connection((server_ip, SERVER_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=server_ip) as ssock:
                ssock.sendall(b"LIST\n")
                data = ssock.recv(4096).decode()
                log("\nAvailable files on server:")
                log(data)

    except Exception as e:
        log(f"List error: {e}")

# GUI Elements
server_ip_label = tk.Label(root, text="Server IP:")
server_ip_label.pack(padx=10, pady=5)

server_ip_entry = tk.Entry(root, width=40)
server_ip_entry.pack(padx=10, pady=5)
server_ip_entry.insert(0, "192.168.1.75")  # default IP

upload_btn = tk.Button(root, text="Upload File", command=upload_file)
upload_btn.pack(padx=10, pady=5)

download_btn = tk.Button(root, text="Download File", command=download_file)
download_btn.pack(padx=10, pady=5)

list_btn = tk.Button(root, text="List Files", command=list_files)
list_btn.pack(padx=10, pady=5)

log_area = scrolledtext.ScrolledText(root, width=80, height=30)
log_area.pack(padx=10, pady=10)

root.mainloop()
