import socket
import ssl
import os
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox
import time
import socks  # For proxy support
from socks import PROXY_TYPES
import ipaddress

# Configuration
BUFFER_SIZE = 4096
CERT_FILE = 'server.crt'
PROXY_TIMEOUT = 30  # Increased from 10 to 30 seconds to allow more time for proxy response

class SecureFileClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Client")
        self.root.geometry("700x600")
        ctk.set_appearance_mode("dark")

        self.conn = None
        self.raw_sock = None
        self.cancel_transfer = False
        self.is_connected = False
        self.transfer_in_progress = False
        
        # Proxy settings
        self.use_proxy = False
        self.proxy_type = socks.PROXY_TYPE_SOCKS5
        self.proxy_host = ""
        self.proxy_port = 1080
        self.proxy_username = ""
        self.proxy_password = ""
        self.proxy_rdns = True
        
        # TLS settings
        self.verify_cert = False
        
        self.create_widgets()
        
    def create_widgets(self):
        self.frame = ctk.CTkFrame(self.root)
        self.frame.pack(pady=20, padx=20, fill="both", expand=True)

        # Connection frame
        self.connection_frame = ctk.CTkFrame(self.frame)
        self.connection_frame.pack(pady=10, fill="x")
        
        ctk.CTkLabel(self.connection_frame, text="Server IP:").grid(row=0, column=0, padx=10, pady=10)
        self.server_ip = ctk.CTkEntry(self.connection_frame, width=200)
        self.server_ip.insert(0, "localhost")
        self.server_ip.grid(row=0, column=1, padx=10, pady=10)
        
        ctk.CTkLabel(self.connection_frame, text="Port:").grid(row=0, column=2, padx=10, pady=10)
        self.server_port = ctk.CTkEntry(self.connection_frame, width=80)
        self.server_port.insert(0, "4443")
        self.server_port.grid(row=0, column=3, padx=10, pady=10)
        
        self.connect_button = ctk.CTkButton(self.connection_frame, text="Connect", command=self.connect_to_server)
        self.connect_button.grid(row=0, column=4, padx=10, pady=10)

        # TLS Settings frame
        self.tls_frame = ctk.CTkFrame(self.frame)
        self.tls_frame.pack(pady=10, fill="x")
        
        self.verify_cert_var = ctk.BooleanVar(value=self.verify_cert)
        self.verify_cert_checkbox = ctk.CTkCheckBox(self.tls_frame, text="Verify Server Certificate", 
                                                   variable=self.verify_cert_var)
        self.verify_cert_checkbox.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.cert_path_button = ctk.CTkButton(self.tls_frame, text="Import Certificate", 
                                             command=self.import_certificate)
        self.cert_path_button.grid(row=0, column=1, padx=10, pady=10)
        
        self.cert_path_label = ctk.CTkLabel(self.tls_frame, text="Using: Default Certificate")
        self.cert_path_label.grid(row=0, column=2, padx=10, pady=10, sticky="w")

        # Proxy settings frame
        self.proxy_frame = ctk.CTkFrame(self.frame)
        self.proxy_frame.pack(pady=10, fill="x")
        
        # Proxy enable checkbox
        self.proxy_var = ctk.BooleanVar(value=False)
        self.proxy_checkbox = ctk.CTkCheckBox(self.proxy_frame, text="Use Proxy", 
                                             variable=self.proxy_var, command=self.toggle_proxy_settings)
        self.proxy_checkbox.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        # Proxy type dropdown
        ctk.CTkLabel(self.proxy_frame, text="Proxy Type:").grid(row=0, column=1, padx=10, pady=10)
        proxy_types = ["SOCKS5", "SOCKS4", "HTTP"]
        self.proxy_type_var = ctk.StringVar(value=proxy_types[0])
        self.proxy_type_menu = ctk.CTkOptionMenu(self.proxy_frame, values=proxy_types, 
                                               variable=self.proxy_type_var, state="disabled")
        self.proxy_type_menu.grid(row=0, column=2, padx=10, pady=10)
        
        # Proxy host and port
        ctk.CTkLabel(self.proxy_frame, text="Proxy Host:").grid(row=1, column=0, padx=10, pady=5)
        self.proxy_host_entry = ctk.CTkEntry(self.proxy_frame, width=200, state="disabled")
        self.proxy_host_entry.grid(row=1, column=1, padx=10, pady=5)
        
        ctk.CTkLabel(self.proxy_frame, text="Proxy Port:").grid(row=1, column=2, padx=10, pady=5)
        self.proxy_port_entry = ctk.CTkEntry(self.proxy_frame, width=80, state="disabled")
        self.proxy_port_entry.insert(0, "1080")
        self.proxy_port_entry.grid(row=1, column=3, padx=10, pady=5)
        
        # Proxy authentication
        ctk.CTkLabel(self.proxy_frame, text="Username:").grid(row=2, column=0, padx=10, pady=5)
        self.proxy_username_entry = ctk.CTkEntry(self.proxy_frame, width=200, state="disabled")
        self.proxy_username_entry.grid(row=2, column=1, padx=10, pady=5)
        
        ctk.CTkLabel(self.proxy_frame, text="Password:").grid(row=2, column=2, padx=10, pady=5)
        self.proxy_password_entry = ctk.CTkEntry(self.proxy_frame, width=200, show="*", state="disabled")
        self.proxy_password_entry.grid(row=2, column=3, padx=10, pady=5)
        
        # DNS resolution through proxy
        self.proxy_rdns_var = ctk.BooleanVar(value=self.proxy_rdns)
        self.proxy_rdns_checkbox = ctk.CTkCheckBox(self.proxy_frame, text="Resolve DNS through proxy", 
                                                  variable=self.proxy_rdns_var, state="disabled")
        self.proxy_rdns_checkbox.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="w")

        # File list
        self.file_listbox = ctk.CTkTextbox(self.frame, height=150)
        self.file_listbox.pack(pady=10, fill="x")

        # Progress frame
        self.progress_frame = ctk.CTkFrame(self.frame)
        self.progress_frame.pack(pady=10, fill="x")
        
        self.status_label = ctk.CTkLabel(self.progress_frame, text="Not connected")
        self.status_label.pack(pady=5)
        
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, width=600)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=5)
        
        self.cancel_button = ctk.CTkButton(self.progress_frame, text="Cancel", 
                                         command=self.cancel_transfer_operation, 
                                         state="disabled", fg_color="red", hover_color="darkred")
        self.cancel_button.pack(pady=5)

        # Button frame
        self.button_frame = ctk.CTkFrame(self.frame)
        self.button_frame.pack(pady=10, fill="x")

        self.upload_button = ctk.CTkButton(self.button_frame, text="Upload File", 
                                         command=self.upload_file, state="disabled")
        self.download_button = ctk.CTkButton(self.button_frame, text="Download File", 
                                           command=self.download_file_prompt, state="disabled")
        self.delete_button = ctk.CTkButton(self.button_frame, text="Delete File", 
                                         command=self.delete_file_prompt, 
                                         state="disabled", fg_color="red", hover_color="darkred")

        self.upload_button.grid(row=0, column=0, padx=10, pady=10)
        self.download_button.grid(row=0, column=1, padx=10, pady=10)
        self.delete_button.grid(row=0, column=2, padx=10, pady=10)

    def import_certificate(self):
        """Allow user to import a custom certificate"""
        filepath = filedialog.askopenfilename(filetypes=[("Certificate files", "*.crt *.pem"), ("All files", "*.*")])
        if filepath:
            global CERT_FILE
            CERT_FILE = filepath
            self.cert_path_label.configure(text=f"Using: {os.path.basename(filepath)}")
            
    def toggle_proxy_settings(self):
        """Enable or disable proxy settings based on checkbox"""
        state = "normal" if self.proxy_var.get() else "disabled"
        self.proxy_type_menu.configure(state=state)
        self.proxy_host_entry.configure(state=state)
        self.proxy_port_entry.configure(state=state)
        self.proxy_username_entry.configure(state=state)
        self.proxy_password_entry.configure(state=state)
        self.proxy_rdns_checkbox.configure(state=state)

    def update_status(self, text):
        self.status_label.configure(text=text)
        print(f"Status Update: {text}")  # Added for debugging
        self.root.update_idletasks()

    def update_progress(self, progress_value):
        self.progress_bar.set(progress_value)
        self.root.update_idletasks()

    def reset_progress(self):
        self.update_progress(0)
        self.cancel_button.configure(state="disabled")
        self.transfer_in_progress = False
        self.cancel_transfer = False
        self.update_status("Ready" if self.is_connected else "Not connected")
        
    def enable_transfer_controls(self, enable=True):
        state = "normal" if enable else "disabled"
        self.upload_button.configure(state=state)
        self.download_button.configure(state=state)
        self.delete_button.configure(state=state)
        
    def enable_connection_controls(self, connected=False):
        if connected:
            self.connect_button.configure(text="Disconnect", command=self.disconnect_from_server)
            self.server_ip.configure(state="disabled")
            self.server_port.configure(state="disabled")
            self.proxy_checkbox.configure(state="disabled")
            self.toggle_proxy_settings()  # Disable all proxy controls
            self.verify_cert_checkbox.configure(state="disabled")
            self.cert_path_button.configure(state="disabled")
            self.enable_transfer_controls(True)
            self.is_connected = True
        else:
            self.connect_button.configure(text="Connect", command=self.connect_to_server)
            self.server_ip.configure(state="normal")
            self.server_port.configure(state="normal")
            self.proxy_checkbox.configure(state="normal")
            self.toggle_proxy_settings()  # Re-enable based on checkbox
            self.verify_cert_checkbox.configure(state="normal")
            self.cert_path_button.configure(state="normal")
            self.enable_transfer_controls(False)
            self.is_connected = False

    def threaded(func):
        def wrapper(self, *args, **kwargs):
            threading.Thread(target=func, args=(self, *args), kwargs=kwargs, daemon=True).start()
        return wrapper

    def configure_proxy(self):
        """Configure and return proxy settings dictionary if enabled"""
        if not self.proxy_var.get():
            return None
            
        # Get proxy settings from GUI
        proxy_type_str = self.proxy_type_var.get()
        proxy_host = self.proxy_host_entry.get().strip()
        
        try:
            proxy_port = int(self.proxy_port_entry.get().strip())
        except ValueError:
            raise ValueError("Proxy port must be a number")
            
        proxy_username = self.proxy_username_entry.get().strip() or None
        proxy_password = self.proxy_password_entry.get() or None
        proxy_rdns = self.proxy_rdns_var.get()
        
        # Map proxy type string to socks type
        proxy_types = {
            "SOCKS5": socks.PROXY_TYPE_SOCKS5,
            "SOCKS4": socks.PROXY_TYPE_SOCKS4,
            "HTTP": socks.PROXY_TYPE_HTTP
        }
        
        proxy_type = proxy_types.get(proxy_type_str, socks.PROXY_TYPE_SOCKS5)
        
        # Validate proxy host
        if not proxy_host:
            raise ValueError("Proxy host cannot be empty")
            
        # Test proxy hostname resolution
        try:
            socket.getaddrinfo(proxy_host, proxy_port)
        except socket.gaierror as e:
            raise ConnectionError(f"Could not resolve proxy host '{proxy_host}': {str(e)}")
            
        # Return proxy configuration
        return {
            'proxy_type': proxy_type,
            'addr': proxy_host,
            'port': proxy_port,
            'rdns': proxy_rdns,
            'username': proxy_username,
            'password': proxy_password
        }

    def create_socket_with_proxy(self):
        """Create a socket with proxy configuration if enabled"""
        proxy_config = self.configure_proxy()
        
        if proxy_config:
            try:
                self.update_status(f"Connecting to proxy {proxy_config['addr']}:{proxy_config['port']}...")
                proxied_socket = socks.socksocket()
                proxied_socket.set_proxy(**proxy_config)
                proxied_socket.settimeout(PROXY_TIMEOUT)
                # Test proxy connection by attempting to connect to the proxy
                proxied_socket.connect((proxy_config['addr'], proxy_config['port']))
                self.update_status(f"Successfully connected to proxy {proxy_config['addr']}:{proxy_config['port']}")
                return proxied_socket
            except socks.Socks5Error as e:
                raise ConnectionError(f"Proxy authentication or connection failed: {str(e)}")
            except socket.timeout:
                raise ConnectionError(f"Proxy connection timed out after {PROXY_TIMEOUT} seconds")
            except Exception as e:
                raise ConnectionError(f"Proxy connection failed: {str(e)}")
        else:
            self.update_status("No proxy configured, using direct connection...")
            return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def is_ip_address(self, host):
        """Check if the host is an IP address."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @threaded
    def connect_to_server(self):
        try:
            # Get server information
            ip = self.server_ip.get().strip()
            try:
                port = int(self.server_port.get().strip())
            except ValueError:
                raise ValueError("Port must be a number")
            
            self.update_status(f"Connecting to {ip}:{port}...")
            
            # Store if certificate verification is needed
            self.verify_cert = self.verify_cert_var.get()
            
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            
            if self.verify_cert:
                if os.path.exists(CERT_FILE):
                    self.update_status(f"Loading certificate from {CERT_FILE}...")
                    context.load_verify_locations(CERT_FILE)
                else:
                    raise FileNotFoundError(f"Certificate file {CERT_FILE} not found")
                # Check if the host is an IP address
                if self.is_ip_address(ip):
                    # If connecting via IP, disable hostname verification
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_REQUIRED
                    self.update_status("IP address detected, disabling hostname verification...")
                else:
                    # If connecting via hostname, enable hostname verification
                    context.check_hostname = True
                    context.verify_mode = ssl.CERT_REQUIRED
                    self.update_status("Hostname detected, enabling hostname verification...")
            else:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self.update_status("Certificate verification disabled...")
            
            # Create socket with proxy if configured
            self.raw_sock = self.create_socket_with_proxy()
            self.raw_sock.settimeout(PROXY_TIMEOUT)
            
            # Connect using the raw socket
            self.update_status(f"Establishing connection to {ip}:{port}...")
            self.raw_sock.connect((ip, port))
            self.update_status(f"Raw socket connected to {ip}:{port}")
            
            # Wrap with SSL after establishing connection
            # Pass server_hostname only if verifying and not an IP address
            server_hostname = ip if self.verify_cert and not self.is_ip_address(ip) else None
            self.update_status(f"Wrapping socket with SSL (server_hostname={server_hostname})...")
            try:
                self.conn = context.wrap_socket(self.raw_sock, server_hostname=server_hostname, do_handshake_on_connect=True)
            except ssl.SSLError as e:
                raise ConnectionError(f"SSL handshake failed: {str(e)}")
            
            # Verify the connection object is valid
            if not hasattr(self.conn, 'recv'):
                raise ValueError("Invalid SSL connection object created")
            self.update_status("SSL connection established successfully")
            
            self.enable_connection_controls(True)
            self.update_status("Connected")
            
            # Show certificate info if verified
            if self.verify_cert:
                try:
                    cert = self.conn.getpeercert()
                    if cert is None:
                        self.update_status("No certificate received from server")
                        messagebox.showwarning("Certificate Warning", "Server did not provide a certificate.")
                    else:
                        self.update_status("Certificate received, extracting details...")
                        subject = dict(x[0] for x in cert['subject'])
                        cn = subject.get('commonName', 'Unknown')
                        issuer = dict(x[0] for x in cert['issuer'])
                        issuer_name = issuer.get('organizationName', 'Unknown')
                        messagebox.showinfo("Secure Connection", 
                                          f"Connected to:\nCommon Name: {cn}\nIssuer: {issuer_name}")
                except Exception as e:
                    self.update_status(f"Failed to retrieve certificate: {str(e)}")
                    messagebox.showwarning("Certificate Error", f"Could not retrieve server certificate: {str(e)}")
            
            self.list_files()
            
        except Exception as e:
            self.update_status(f"Connection failed: {str(e)}")
            messagebox.showerror("Connection Error", f"Could not connect to server: {str(e)}")
            self.reset_progress()
            if self.raw_sock:
                try:
                    self.raw_sock.close()
                except:
                    pass
                self.raw_sock = None
            self.conn = None

    def disconnect_from_server(self):
        try:
            if self.conn:
                self.conn.close()
            if self.raw_sock:
                self.raw_sock.close()
                
            self.conn = None
            self.raw_sock = None
            self.enable_connection_controls(False)
            self.file_listbox.delete("1.0", ctk.END)
            self.file_listbox.insert(ctk.END, "Disconnected from server.")
            self.reset_progress()
            
        except Exception as e:
            messagebox.showerror("Disconnect Error", str(e))

    def cancel_transfer_operation(self):
        if self.transfer_in_progress:
            self.cancel_transfer = True
            self.update_status("Cancelling transfer...")

    @threaded
    def upload_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        try:
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            
            # Prepare for transfer
            self.transfer_in_progress = True
            self.cancel_transfer = False
            self.cancel_button.configure(state="normal")
            
            # Send UPLOAD command
            self.conn.send("UPLOAD".encode())
            time.sleep(0.1)
            
            # Send filename and filesize
            self.conn.send(filename.encode())
            time.sleep(0.1)
            self.conn.send(str(filesize).encode())
            
            # Check if file exists on server
            response = self.conn.recv(BUFFER_SIZE).decode()
            if response == "EXISTS":
                if messagebox.askyesno("File exists", "File already exists on server. Overwrite?"):
                    self.conn.send("OVERWRITE".encode())
                else:
                    self.conn.send("CANCEL".encode())
                    self.reset_progress()
                    return
            
            # Update progress
            self.update_status(f"Uploading {filename}...")
            self.update_progress(0)
            
            # Send file data
            sent = 0
            with open(filepath, 'rb') as f:
                start_time = time.time()
                last_update_time = start_time
                
                while sent < filesize and not self.cancel_transfer:
                    chunk = f.read(min(BUFFER_SIZE, filesize - sent))
                    if not chunk:
                        break
                    
                    self.conn.sendall(chunk)
                    sent += len(chunk)
                    progress = sent / filesize
                    
                    current_time = time.time()
                    if current_time - last_update_time > 0.05:
                        self.update_progress(progress)
                        elapsed = current_time - start_time
                        speed = sent / elapsed if elapsed > 0 else 0
                        speed_text = f"{speed/1024:.1f} KB/s" if speed < 1024*1024 else f"{speed/(1024*1024):.1f} MB/s"
                        self.update_status(f"Uploading {filename}: {int(progress * 100)}% ({speed_text})")
                        last_update_time = current_time

            if not self.cancel_transfer:
                self.update_progress(1.0)
                self.update_status("Upload complete")
                messagebox.showinfo("Success", f"Uploaded {filename} successfully.")
                self.list_files()
            else:
                self.update_status("Upload cancelled")
                messagebox.showinfo("Cancelled", "File upload cancelled.")
                
        except Exception as e:
            self.update_status(f"Upload failed: {str(e)}")
            messagebox.showerror("Upload Failed", str(e))
        finally:
            self.reset_progress()

    @threaded
    def download_file_prompt(self):
        filename = ctk.CTkInputDialog(text="Enter filename to download:").get_input()
        if filename:
            self.download_file(filename)

    def download_file(self, filename):
        try:
            self.transfer_in_progress = True
            self.cancel_transfer = False
            self.cancel_button.configure(state="normal")
            
            # Send DOWNLOAD command
            self.conn.send("DOWNLOAD".encode())
            time.sleep(0.1)
            
            # Send filename
            self.conn.send(filename.encode())
            
            # Get response
            response = self.conn.recv(BUFFER_SIZE).decode()
            
            if response == "NOTFOUND":
                messagebox.showwarning("Not Found", "File not found on server.")
                self.reset_progress()
                return
            
            # Response should be filesize
            filesize = int(response)
            
            # Ask for save location
            save_path = filedialog.asksaveasfilename(initialfile=filename)
            if not save_path:
                self.conn.send("CANCEL".encode())
                self.reset_progress()
                return
            
            # Send ready signal
            self.conn.send("READY".encode())
            
            # Receive file
            self.update_status(f"Downloading {filename}...")
            self.update_progress(0)
            
            received = 0
            with open(save_path, "wb") as f:
                start_time = time.time()
                last_update_time = start_time
                
                while received < filesize and not self.cancel_transfer:
                    chunk_size = min(BUFFER_SIZE, filesize - received)
                    chunk = self.conn.recv(chunk_size)
                    
                    if not chunk:
                        if received < filesize:
                            raise Exception("Connection closed before file download completed")
                        break
                        
                    f.write(chunk)
                    received += len(chunk)
                    progress = received / filesize
                    
                    current_time = time.time()
                    if current_time - last_update_time > 0.05:
                        self.update_progress(progress)
                        elapsed = current_time - start_time
                        speed = received / elapsed if elapsed > 0 else 0
                        speed_text = f"{speed/1024:.1f} KB/s" if speed < 1024*1024 else f"{speed/(1024*1024):.1f} MB/s"
                        self.update_status(f"Downloading {filename}: {int(progress * 100)}% ({speed_text})")
                        last_update_time = current_time
            
            if self.cancel_transfer:
                f.close()
                os.remove(save_path)
                self.update_status("Download cancelled")
                messagebox.showinfo("Cancelled", "File download cancelled.")
            else:
                self.update_progress(1.0)
                self.update_status("Download complete")
                messagebox.showinfo("Downloaded", f"{filename} downloaded successfully.")
                
        except Exception as e:
            self.update_status(f"Download failed: {str(e)}")
            messagebox.showerror("Download Failed", str(e))
        finally:
            self.reset_progress()

    @threaded
    def delete_file_prompt(self):
        filename = ctk.CTkInputDialog(text="Enter filename to delete:").get_input()
        if filename:
            self.delete_file(filename)

    def delete_file(self, filename):
        try:
            # Send DELETE command
            self.conn.send("DELETE".encode())
            time.sleep(0.1)
            
            # Send filename
            self.conn.send(filename.encode())
            
            # Get response
            response = self.conn.recv(BUFFER_SIZE).decode()
            
            if response == "DELETED":
                messagebox.showinfo("Deleted", f"{filename} deleted from server.")
                self.list_files()
            else:
                messagebox.showwarning("Not Found", "File not found on server.")
        except Exception as e:
            messagebox.showerror("Delete Failed", str(e))

    @threaded
    def list_files(self):
        try:
            # Send LIST command
            self.conn.send("LIST".encode())
            
            # Receive file list
            response = self.conn.recv(BUFFER_SIZE).decode()
            
            # Update list display
            self.file_listbox.delete("1.0", ctk.END)
            self.file_listbox.insert(ctk.END, response if response else "[No files on server]")
        except Exception as e:
            if self.is_connected:
                messagebox.showerror("List Error", str(e))
                self.disconnect_from_server()

if __name__ == '__main__':
    ctk.set_default_color_theme("dark-blue")
    app = ctk.CTk()
    gui = SecureFileClientGUI(app)
    app.mainloop()