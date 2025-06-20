import socket
import ssl
import json
import os
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Constants
HOST = '127.0.0.1'
PORT = 12345
SERVER_KEY = "server.key"
SERVER_CERT = "server.cert"
UPLOAD_DIR = "uploads"

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Transfer Server")
        self.root.geometry("700x500")
        self.server_running = False
        self.server_thread = None
        
        # Create uploads directory if it doesn't exist
        if not os.path.exists(UPLOAD_DIR):
            os.makedirs(UPLOAD_DIR)
        
        # Generate certificates if they don't exist
        if not os.path.exists(SERVER_KEY) or not os.path.exists(SERVER_CERT):
            self.log_message("Certificates not found. Generating new certificates...")
            self.generate_certificates()
        
        # Create GUI elements
        self.create_widgets()
        
    def create_widgets(self):
        # Control frame
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X)
        
        # Start/Stop button
        self.server_button = ttk.Button(control_frame, text="Start Server", command=self.toggle_server)
        self.server_button.pack(side=tk.LEFT, padx=5)
        
        # Status label
        self.status_label = ttk.Label(control_frame, text="Server: Stopped")
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Log frame
        log_frame = ttk.LabelFrame(self.root, text="Server Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Log text area
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, width=80, height=20)
        self.log_area.pack(fill=tk.BOTH, expand=True)
        self.log_area.config(state=tk.DISABLED)
        
        # Files frame
        files_frame = ttk.LabelFrame(self.root, text="Uploaded Files", padding="10")
        files_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Files listbox with scrollbar
        self.files_list = tk.Listbox(files_frame)
        scrollbar = ttk.Scrollbar(files_frame, orient="vertical", command=self.files_list.yview)
        self.files_list.config(yscrollcommand=scrollbar.set)
        self.files_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Refresh files button
        refresh_button = ttk.Button(files_frame, text="Refresh", command=self.refresh_files_list)
        refresh_button.pack(side=tk.BOTTOM, pady=5)
        
        # Initialize files list
        self.refresh_files_list()
    
    def generate_certificates(self):
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Save private key to file
            with open(SERVER_KEY, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Generate a self-signed certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Valid for 365 days
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Save certificate to file
            with open(SERVER_CERT, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            self.log_message("Certificate and private key generated successfully.")
        except Exception as e:
            self.log_message(f"Error generating certificates: {e}")
    
    def log_message(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, log_message)
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)
    
    def refresh_files_list(self):
        self.files_list.delete(0, tk.END)
        
        if os.path.exists(UPLOAD_DIR):
            files = sorted(os.listdir(UPLOAD_DIR))
            for file in files:
                file_path = os.path.join(UPLOAD_DIR, file)
                if os.path.isfile(file_path):
                    file_size = os.path.getsize(file_path)
                    self.files_list.insert(tk.END, f"{file} ({self.format_size(file_size)})")
    
    def format_size(self, size_bytes):
        # Convert file size to human-readable format
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024 or unit == 'GB':
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
    
    def toggle_server(self):
        if self.server_running:
            self.stop_server()
        else:
            self.start_server()
    
    def start_server(self):
        if not self.server_running:
            self.server_running = True
            self.server_button.config(text="Stop Server")
            self.status_label.config(text="Server: Running")
            
            # Start server in a separate thread
            self.server_thread = threading.Thread(target=self.run_server)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            self.log_message(f"Server started on {HOST}:{PORT}")
    
    def stop_server(self):
        if self.server_running:
            self.server_running = False
            self.server_button.config(text="Start Server")
            self.status_label.config(text="Server: Stopped")
            self.log_message("Server stopped")
    
    def run_server(self):
        try:
            # Create server socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((HOST, PORT))
            server_socket.listen(5)
            
            # Configure SSL/TLS
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
            
            # Set timeout to allow checking server_running flag
            server_socket.settimeout(1.0)
            
            while self.server_running:
                try:
                    # Accept connections with timeout
                    client_socket, addr = server_socket.accept()
                    self.log_message(f"Connection from {addr}")
                    
                    # Start client handler in a new thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, addr, context)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.server_running:
                        self.log_message(f"Error accepting connection: {e}")
            
            server_socket.close()
        
        except Exception as e:
            self.log_message(f"Server error: {e}")
            self.server_running = False
            self.root.after(0, lambda: self.server_button.config(text="Start Server"))
            self.root.after(0, lambda: self.status_label.config(text="Server: Error"))
    
    def handle_client(self, client_socket, addr, context):
        secure_socket = None
        
        try:
            # Wrap socket with SSL/TLS
            secure_socket = context.wrap_socket(client_socket, server_side=True)
            
            # Log TLS connection details
            tls_version = secure_socket.version()
            cipher = secure_socket.cipher()
            
            self.log_message(f"Secure connection established with {addr}")
            self.log_message(f"TLS Version: {tls_version}")
            self.log_message(f"Cipher: {cipher[0]}")
            
            # Receive command
            command_data = secure_socket.recv(1024).decode('utf-8')
            command = json.loads(command_data)
            cmd_type = command.get('type', '')
            
            if cmd_type == 'SEND':
                filename = command.get('filename', '')
                filesize = command.get('filesize', 0)
                
                # Create safe filename (basic security)
                safe_filename = os.path.basename(filename)
                filepath = os.path.join(UPLOAD_DIR, safe_filename)
                
                self.log_message(f"Receiving file: {safe_filename} ({self.format_size(filesize)})")
                
                # Acknowledge command
                secure_socket.send(json.dumps({'status': 'READY'}).encode('utf-8'))
                
                # Receive file
                self.receive_file(secure_socket, filepath, filesize)
                
                # Confirm receipt
                secure_socket.send(json.dumps({'status': 'SUCCESS'}).encode('utf-8'))
                
                # Update files list
                self.root.after(0, self.refresh_files_list)
                
            elif cmd_type == 'LIST':
                self.log_message(f"Client requested file listing")
                
                # List files in upload directory
                files = os.listdir(UPLOAD_DIR)
                file_info = []
                for file in files:
                    file_path = os.path.join(UPLOAD_DIR, file)
                    if os.path.isfile(file_path):
                        file_info.append({
                            'name': file,
                            'size': os.path.getsize(file_path)
                        })
                
                response = {
                    'status': 'SUCCESS',
                    'files': file_info
                }
                secure_socket.send(json.dumps(response).encode('utf-8'))
            
            elif cmd_type == 'DELETE':
                filename = command.get('filename', '')
                safe_filename = os.path.basename(filename)
                filepath = os.path.join(UPLOAD_DIR, safe_filename)
                
                self.log_message(f"Delete request for file: {safe_filename}")
                
                if os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                        secure_socket.send(json.dumps({'status': 'SUCCESS', 'message': 'File deleted'}).encode('utf-8'))
                        self.log_message(f"File deleted: {safe_filename}")
                        
                        # Update files list
                        self.root.after(0, self.refresh_files_list)
                    except Exception as e:
                        secure_socket.send(json.dumps({'status': 'ERROR', 'message': str(e)}).encode('utf-8'))
                        self.log_message(f"Error deleting file: {e}")
                else:
                    secure_socket.send(json.dumps({'status': 'ERROR', 'message': 'File not found'}).encode('utf-8'))
                    self.log_message(f"File not found: {safe_filename}")
        
        except Exception as e:
            self.log_message(f"Error handling client {addr}: {e}")
        
        finally:
            # Close connection
            if secure_socket:
                try:
                    secure_socket.close()
                except:
                    pass
            else:
                try:
                    client_socket.close()
                except:
                    pass
    
    def receive_file(self, secure_socket, filepath, filesize):
        try:
            # Receive the file
            with open(filepath, 'wb') as f:
                bytes_received = 0
                start_time = datetime.datetime.now()
                
                while bytes_received < filesize:
                    # Receive chunks of data
                    chunk = secure_socket.recv(min(8192, filesize - bytes_received))
                    if not chunk:
                        break  # Connection closed
                    
                    # Write to file and update counter
                    f.write(chunk)
                    bytes_received += len(chunk)
                    
                    # Calculate progress and speed
                    progress = (bytes_received / filesize) * 100
                    elapsed = (datetime.datetime.now() - start_time).total_seconds()
                    speed = bytes_received / elapsed if elapsed > 0 else 0
                    
                    # Log progress periodically (not too often to avoid GUI freezing)
                    if bytes_received == filesize or bytes_received % 1048576 == 0:  # Every 1MB
                        self.log_message(f"Receiving: {progress:.1f}% complete ({self.format_size(speed)}/s)")
            
            self.log_message(f"File received: {os.path.basename(filepath)}")
            return True
        
        except Exception as e:
            self.log_message(f"Error receiving file: {e}")
            return False

# Main application
if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.protocol("WM_DELETE_WINDOW", root.quit)
    root.mainloop()