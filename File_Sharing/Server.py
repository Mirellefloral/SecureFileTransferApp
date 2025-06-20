import socket
import ssl
import os
import threading
import time
import customtkinter as ctk
from tkinter import messagebox, filedialog
from datetime import datetime, timedelta, timezone
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import socks

# ===== CONFIGURATION =====
SERVER_CERT = 'server.crt'
SERVER_KEY = 'server.key'
CLIENT_CERT_DIR = 'client_certs'
UPLOAD_DIR = 'uploads'
SERVER_PORT = 4443
BUFFER_SIZE = 4096
SOCKET_TIMEOUT = 300
# ========================

# Create required directories
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(CLIENT_CERT_DIR, exist_ok=True)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class SecureFileServer:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Server")
        self.root.geometry("800x600")
        
        # Initialize all attributes
        self.server_socket = None
        self.ssl_context = None
        self.is_running = False
        self.clients = []
        
        # Proxy settings
        self.use_proxy = False
        self.proxy_type = socks.PROXY_TYPE_SOCKS5
        self.proxy_host = ""
        self.proxy_port = 1080
        self.proxy_username = ""
        self.proxy_password = ""
        self.proxy_rdns = True
        
        # Security settings
        self.require_client_cert = False
        self.accept_all_connections = True
        self.allowed_ips = set()
        
        # Network info
        self.hostname = socket.gethostname()
        self.server_ip = self.get_local_ip()
        
        # UI components
        self.status_var = ctk.StringVar(value="[Server stopped]")
        
        # Create widgets
        self.create_widgets()
        
        # Generate certificates if needed
        if not os.path.exists(SERVER_CERT) or not os.path.exists(SERVER_KEY):
            self.generate_certificates()
            
        # Update UI
        self.ip_display.configure(text=self.server_ip)
        self.ip_var.set(self.server_ip)

    def get_local_ip(self):
        """Get server's local IP address"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"

    def create_widgets(self):
        """Initialize all UI components"""
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(padx=10, pady=10, fill='both', expand=True)
        
        # Tab view
        self.tabview = ctk.CTkTabview(main_frame)
        self.tabview.pack(padx=10, pady=10, fill='both', expand=True)
        
        # Create tabs
        self.tab_general = self.tabview.add("General")
        self.tab_security = self.tabview.add("Security")
        self.tab_proxy = self.tabview.add("Proxy")
        self.tab_logs = self.tabview.add("Logs")
        
        # Setup tabs
        self.setup_general_tab()
        self.setup_security_tab()
        self.setup_proxy_tab()
        self.setup_logs_tab()
        
        # Status bar
        status_frame = ctk.CTkFrame(self.root)
        status_frame.pack(side='bottom', fill='x')
        ctk.CTkLabel(status_frame, textvariable=self.status_var).pack(side='left', padx=10)

    def setup_general_tab(self):
        """Configure General tab"""
        # Server info frame
        info_frame = ctk.CTkFrame(self.tab_general)
        info_frame.pack(padx=10, pady=10, fill='x')
        
        ctk.CTkLabel(info_frame, text="Server Information", font=("Arial", 14, "bold")).pack(pady=5)
        
        # IP display
        ip_frame = ctk.CTkFrame(info_frame)
        ip_frame.pack(fill='x', pady=5)
        ctk.CTkLabel(ip_frame, text="Server IP:").pack(side='left', padx=5)
        self.ip_display = ctk.CTkLabel(ip_frame, text="Detecting...", font=("Arial", 12))
        self.ip_display.pack(side='left')
        
        # IP selection
        self.ip_var = ctk.StringVar()
        ip_dropdown = ctk.CTkOptionMenu(ip_frame, variable=self.ip_var, values=["Detecting..."])
        ip_dropdown.pack(side='left', padx=5)
        
        # Port setting
        port_frame = ctk.CTkFrame(info_frame)
        port_frame.pack(fill='x', pady=5)
        ctk.CTkLabel(port_frame, text="Port:").pack(side='left', padx=5)
        self.port_var = ctk.StringVar(value=str(SERVER_PORT))
        port_entry = ctk.CTkEntry(port_frame, textvariable=self.port_var, width=80)
        port_entry.pack(side='left')
        
        # Certificate paths
        self.cert_path_var = ctk.StringVar(value=os.path.abspath(SERVER_CERT))
        self.key_path_var = ctk.StringVar(value=os.path.abspath(SERVER_KEY))
        
        # Connection instructions
        instr_frame = ctk.CTkFrame(info_frame)
        instr_frame.pack(fill='x', pady=10)
        ctk.CTkLabel(instr_frame, 
                    text=f"Tell clients to connect to: {self.server_ip}:{SERVER_PORT}",
                    font=("Arial", 12)).pack()
        
        # Upload directory
        upload_frame = ctk.CTkFrame(self.tab_general)
        upload_frame.pack(padx=10, pady=10, fill='x')
        ctk.CTkLabel(upload_frame, text="Upload Directory:").pack(side='left', padx=5)
        self.upload_dir_var = ctk.StringVar(value=os.path.abspath(UPLOAD_DIR))
        upload_dir_entry = ctk.CTkEntry(upload_frame, textvariable=self.upload_dir_var, width=300)
        upload_dir_entry.pack(side='left', padx=5)
        upload_dir_btn = ctk.CTkButton(upload_frame, text="Browse", command=self.browse_upload_dir)
        upload_dir_btn.pack(side='left', padx=5)
        
        # Server controls
        control_frame = ctk.CTkFrame(self.tab_general)
        control_frame.pack(pady=20, fill='x')
        self.start_button = ctk.CTkButton(control_frame, text="Start Server", 
                                        command=self.start_server,
                                        fg_color="green", hover_color="dark green")
        self.start_button.pack(side='left', padx=10)
        self.stop_button = ctk.CTkButton(control_frame, text="Stop Server", 
                                       command=self.stop_server,
                                       fg_color="red", hover_color="dark red", 
                                       state='disabled')
        self.stop_button.pack(side='left', padx=10)
        
        # Connected clients
        ctk.CTkLabel(self.tab_general, text="Connected Clients:").pack(anchor='w', padx=10, pady=(20, 5))
        self.clients_listbox = ctk.CTkTextbox(self.tab_general, height=150)
        self.clients_listbox.pack(padx=10, pady=5, fill='both')
    
    def setup_security_tab(self):
        """Setup the Security tab with certificate and access control options"""
        # Certificate management
        cert_frame = ctk.CTkFrame(self.tab_security)
        cert_frame.pack(padx=10, pady=10, fill='x')
        
        ctk.CTkLabel(cert_frame, text="Server Certificate:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.cert_path_var = ctk.StringVar(value=os.path.abspath(SERVER_CERT))
        cert_entry = ctk.CTkEntry(cert_frame, textvariable=self.cert_path_var, width=300)
        cert_entry.grid(row=0, column=1, padx=5, pady=5)
        
        cert_btn = ctk.CTkButton(cert_frame, text="Browse", command=lambda: self.browse_file(self.cert_path_var))
        cert_btn.grid(row=0, column=2, padx=5, pady=5)
        
        ctk.CTkLabel(cert_frame, text="Server Key:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.key_path_var = ctk.StringVar(value=os.path.abspath(SERVER_KEY))
        key_entry = ctk.CTkEntry(cert_frame, textvariable=self.key_path_var, width=300)
        key_entry.grid(row=1, column=1, padx=5, pady=5)
        
        key_btn = ctk.CTkButton(cert_frame, text="Browse", command=lambda: self.browse_file(self.key_path_var))
        key_btn.grid(row=1, column=2, padx=5, pady=5)
        
        # Generate certificates button
        gen_cert_btn = ctk.CTkButton(cert_frame, text="Generate Certificates", 
                                   command=self.generate_certificates)
        gen_cert_btn.grid(row=2, column=0, columnspan=3, padx=5, pady=15)
        
        # Client Certificate Authentication
        client_cert_frame = ctk.CTkFrame(self.tab_security)
        client_cert_frame.pack(padx=10, pady=(20, 10), fill='x')
        
        self.require_client_cert_var = ctk.BooleanVar(value=False)
        client_cert_checkbox = ctk.CTkCheckBox(client_cert_frame, 
                                             text="Require Client Certificate", 
                                             variable=self.require_client_cert_var)
        client_cert_checkbox.pack(anchor='w', padx=10, pady=10)
        
        # IP Restrictions
        ip_restrict_frame = ctk.CTkFrame(self.tab_security)
        ip_restrict_frame.pack(padx=10, pady=10, fill='x')
        
        self.accept_all_var = ctk.BooleanVar(value=True)
        accept_all_checkbox = ctk.CTkCheckBox(ip_restrict_frame, 
                                            text="Accept connections from all IPs", 
                                            variable=self.accept_all_var,
                                            command=self.toggle_ip_restriction)
        accept_all_checkbox.pack(anchor='w', padx=10, pady=10)
        
        # IP whitelist
        ip_list_frame = ctk.CTkFrame(ip_restrict_frame)
        ip_list_frame.pack(padx=10, pady=10, fill='x')
        
        ctk.CTkLabel(ip_list_frame, text="Allowed IP:").grid(row=0, column=0, padx=5, pady=5)
        self.allowed_ip_var = ctk.StringVar()
        ip_entry = ctk.CTkEntry(ip_list_frame, textvariable=self.allowed_ip_var, width=200)
        ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        add_ip_btn = ctk.CTkButton(ip_list_frame, text="Add IP", command=self.add_ip_to_whitelist)
        add_ip_btn.grid(row=0, column=2, padx=5, pady=5)
        
        remove_ip_btn = ctk.CTkButton(ip_list_frame, text="Remove Selected", 
                                    command=self.remove_ip_from_whitelist)
        remove_ip_btn.grid(row=0, column=3, padx=5, pady=5)
        
        # IP list display
        ctk.CTkLabel(ip_list_frame, text="Allowed IPs:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.ip_listbox = ctk.CTkTextbox(ip_list_frame, height=100, width=500)
        self.ip_listbox.grid(row=2, column=0, columnspan=4, padx=5, pady=5)
        
        # Initial state
        self.toggle_ip_restriction()

    def setup_proxy_tab(self):
        """Setup the Proxy tab for outbound connections"""
        proxy_frame = ctk.CTkFrame(self.tab_proxy)
        proxy_frame.pack(padx=10, pady=10, fill='x')
        
        # Proxy enable checkbox
        self.use_proxy_var = ctk.BooleanVar(value=False)
        proxy_checkbox = ctk.CTkCheckBox(proxy_frame, text="Use Proxy for Outbound Connections", 
                                       variable=self.use_proxy_var,
                                       command=self.toggle_proxy_settings)
        proxy_checkbox.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky='w')
        
        # Proxy type
        ctk.CTkLabel(proxy_frame, text="Proxy Type:").grid(row=1, column=0, padx=10, pady=5, sticky='w')
        proxy_types = ["SOCKS5", "SOCKS4", "HTTP"]
        self.proxy_type_var = ctk.StringVar(value=proxy_types[0])
        proxy_type_menu = ctk.CTkOptionMenu(proxy_frame, values=proxy_types, 
                                          variable=self.proxy_type_var, 
                                          state="disabled")
        proxy_type_menu.grid(row=1, column=1, padx=10, pady=5, sticky='w')
        
        # Proxy host
        ctk.CTkLabel(proxy_frame, text="Proxy Host:").grid(row=2, column=0, padx=10, pady=5, sticky='w')
        self.proxy_host_entry = ctk.CTkEntry(proxy_frame, width=200, state="disabled")
        self.proxy_host_entry.grid(row=2, column=1, padx=10, pady=5, sticky='w')
        
        # Proxy port
        ctk.CTkLabel(proxy_frame, text="Proxy Port:").grid(row=3, column=0, padx=10, pady=5, sticky='w')
        self.proxy_port_entry = ctk.CTkEntry(proxy_frame, width=100, state="disabled")
        self.proxy_port_entry.insert(0, str(self.proxy_port))
        self.proxy_port_entry.grid(row=3, column=1, padx=10, pady=5, sticky='w')
        
        # Proxy username
        ctk.CTkLabel(proxy_frame, text="Username (optional):").grid(row=4, column=0, padx=10, pady=5, sticky='w')
        self.proxy_username_entry = ctk.CTkEntry(proxy_frame, width=200, state="disabled")
        self.proxy_username_entry.grid(row=4, column=1, padx=10, pady=5, sticky='w')
        
        # Proxy password
        ctk.CTkLabel(proxy_frame, text="Password (optional):").grid(row=5, column=0, padx=10, pady=5, sticky='w')
        self.proxy_password_entry = ctk.CTkEntry(proxy_frame, width=200, show="*", state="disabled")
        self.proxy_password_entry.grid(row=5, column=1, padx=10, pady=5, sticky='w')
        
        # DNS resolution through proxy
        self.proxy_rdns_var = ctk.BooleanVar(value=self.proxy_rdns)
        self.proxy_rdns_checkbox = ctk.CTkCheckBox(proxy_frame, text="Resolve DNS through proxy", 
                                                 variable=self.proxy_rdns_var, state="disabled")
        self.proxy_rdns_checkbox.grid(row=6, column=0, columnspan=2, padx=10, pady=5, sticky='w')
        
        # Note about proxy usage
        info_label = ctk.CTkLabel(proxy_frame, 
                               text="Note: Proxy settings affect outbound connections initiated by the server only.", 
                               text_color="yellow")
        info_label.grid(row=7, column=0, columnspan=2, padx=10, pady=20, sticky='w')

    def setup_logs_tab(self):
        """Setup the Logs tab for server activity logs"""
        log_frame = ctk.CTkFrame(self.tab_logs)
        log_frame.pack(padx=10, pady=10, fill='both', expand=True)
        
        # Log display area
        self.log_textbox = ctk.CTkTextbox(log_frame, height=450)
        self.log_textbox.pack(padx=10, pady=10, fill='both', expand=True)
        
        # Control buttons
        btn_frame = ctk.CTkFrame(log_frame)
        btn_frame.pack(padx=10, pady=10, fill='x')
        
        clear_btn = ctk.CTkButton(btn_frame, text="Clear Logs", command=self.clear_logs)
        clear_btn.pack(side='left', padx=10)
        
        save_btn = ctk.CTkButton(btn_frame, text="Save Logs", command=self.save_logs)
        save_btn.pack(side='left', padx=10)
    
    def browse_upload_dir(self):
        """Browse for upload directory"""
        directory = filedialog.askdirectory()
        if directory:
            self.upload_dir_var.set(directory)
    
    def browse_file(self, string_var):
        """Browse for a file and store path in the provided StringVar"""
        filepath = filedialog.askopenfilename()
        if filepath:
            string_var.set(filepath)
    
    def toggle_ip_restriction(self):
        """Toggle IP restriction controls based on accept all checkbox"""
        state = "disabled" if self.accept_all_var.get() else "normal"
        for widget in self.tab_security.winfo_children()[2].winfo_children()[1].winfo_children():
            try:
                widget.configure(state=state)
            except:
                pass
    
    def toggle_proxy_settings(self):
        """Toggle proxy settings based on use proxy checkbox"""
        state = "normal" if self.use_proxy_var.get() else "disabled"
        self.proxy_type_var.set("SOCKS5")
        
        widgets = [
            self.tab_proxy.winfo_children()[0].winfo_children()[i] 
            for i in range(2, 14)
        ]
        
        for widget in widgets:
            try:
                widget.configure(state=state)
            except:
                pass
    
    def add_ip_to_whitelist(self):
        """Add IP to whitelist"""
        ip = self.allowed_ip_var.get().strip()
        if not ip:
            return
            
        try:
            ipaddress.ip_address(ip)
            self.allowed_ips.add(ip)
            self.update_ip_listbox()
            self.allowed_ip_var.set("")
        except ValueError:
            messagebox.showerror("Invalid IP", f"'{ip}' is not a valid IP address")
    
    def remove_ip_from_whitelist(self):
        """Remove selected IP from whitelist"""
        try:
            selected = self.ip_listbox.selection_get()
            lines = selected.strip().split('\n')
            
            for line in lines:
                if line.strip() in self.allowed_ips:
                    self.allowed_ips.remove(line.strip())
                    
            self.update_ip_listbox()
        except:
            pass
    
    def update_ip_listbox(self):
        """Update the IP listbox with current IPs"""
        self.ip_listbox.delete("1.0", ctk.END)
        for ip in sorted(self.allowed_ips):
            self.ip_listbox.insert(ctk.END, f"{ip}\n")
    
    def log(self, message):
        """Add a log message with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_textbox.insert(ctk.END, log_entry)
        self.log_textbox.see(ctk.END)
        
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def clear_logs(self):
        """Clear the log display"""
        self.log_textbox.delete("1.0", ctk.END)
    
    def save_logs(self):
        """Save logs to a file"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filepath:
            with open(filepath, "w") as f:
                f.write(self.log_textbox.get("1.0", ctk.END))
            self.log(f"Logs saved to {filepath}")
    
    def update_client_list(self):
        """Update the connected clients list"""
        self.clients_listbox.delete("1.0", ctk.END)
        if not self.clients:
            self.clients_listbox.insert(ctk.END, "No clients connected")
            return
            
        for i, client in enumerate(self.clients):
            addr = client.get('address', ('Unknown', 0))
            conn_time = client.get('connected_time', datetime.now()).strftime("%H:%M:%S")
            self.clients_listbox.insert(ctk.END, f"{i+1}. {addr[0]}:{addr[1]} (connected at {conn_time})\n")

    def generate_certificates(self):
        """Generate self-signed SSL certificate and key"""
        try:
            cert_dir = os.path.dirname(os.path.abspath(self.cert_path_var.get()))
            os.makedirs(cert_dir, exist_ok=True)
            
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure File Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname()),
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
                datetime.utcnow()
            ).not_valid_after(
                # Fixed: Use timedelta directly instead of datetime.timedelta
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(socket.gethostname())]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            with open(self.key_path_var.get(), "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open(self.cert_path_var.get(), "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            self.log(f"Generated new certificate and key: {self.cert_path_var.get()}")
            messagebox.showinfo("Success", "Certificate and key generated successfully!")
            
        except Exception as e:
            self.log(f"Certificate generation failed: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate certificates: {str(e)}")
    
    def start_server(self):
        """Start the secure file server"""
        try:
            try:
                port = int(self.port_var.get())
                if port < 1 or port > 65535:
                    raise ValueError("Port must be between 1 and 65535")
            except ValueError as e:
                messagebox.showerror("Invalid Port", str(e))
                return
                
            cert_path = self.cert_path_var.get()
            key_path = self.key_path_var.get()
            
            if not os.path.exists(cert_path) or not os.path.exists(key_path):
                response = messagebox.askyesno("Certificate Missing", 
                                          "Server certificate or key not found. Generate them now?")
                if response:
                    self.generate_certificates()
                else:
                    return
                    
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            
            if self.require_client_cert_var.get():
                self.ssl_context.verify_mode = ssl.CERT_REQUIRED
                self.ssl_context.load_verify_locations(capath=CLIENT_CERT_DIR)
                self.log("Requiring client certificates for connections")
            else:
                self.ssl_context.verify_mode = ssl.CERT_NONE
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            ip = self.ip_var.get()
            self.server_socket.bind((ip, port))
            self.server_socket.listen(5)
            
            self.is_running = True
            threading.Thread(target=self.accept_connections, daemon=True).start()
            
            self.log(f"Server started on {ip}:{port}")
            
            self.start_button.configure(state='disabled')
            self.stop_button.configure(state='normal')
            
        except Exception as e:
            self.log(f"Failed to start server: {str(e)}")
            messagebox.showerror("Error", f"Failed to start server: {str(e)}")
            
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
                
            self.is_running = False
    
    def stop_server(self):
        """Stop the file server"""
        self.is_running = False
        
        for client in self.clients:
            try:
                if 'connection' in client:
                    client['connection'].close()
            except:
                pass
                
        self.clients.clear()
        self.update_client_list()
        
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        
        self.log("Server stopped")
        
        self.start_button.configure(state='normal')
        self.stop_button.configure(state='disabled')
    
    def accept_connections(self):
        """Accept client connections in a separate thread"""
        self.server_socket.settimeout(1)
        
        while self.is_running:
            try:
                client_socket, addr = self.server_socket.accept()
                
                if not self.accept_all_var.get() and addr[0] not in self.allowed_ips:
                    self.log(f"Rejected connection from unauthorized IP: {addr[0]}")
                    client_socket.close()
                    continue
                
                client_socket.settimeout(SOCKET_TIMEOUT)
                
                try:
                    secure_client = self.ssl_context.wrap_socket(client_socket, server_side=True)
                    
                    client_info = {
                        'connection': secure_client,
                        'address': addr,
                        'connected_time': datetime.now()
                    }
                    
                    self.clients.append(client_info)
                    self.log(f"New connection from {addr[0]}:{addr[1]}")
                    self.update_client_list()
                    
                    threading.Thread(target=self.handle_client, 
                                   args=(client_info,), 
                                   daemon=True).start()
                    
                except ssl.SSLError as e:
                    self.log(f"SSL error from {addr[0]}: {str(e)}")
                    client_socket.close()
                    
                except Exception as e:
                    self.log(f"Error establishing secure connection with {addr[0]}: {str(e)}")
                    client_socket.close()
                    
            except socket.timeout:
                continue
                
            except Exception as e:
                if self.is_running:
                    self.log(f"Error accepting connection: {str(e)}")
                    time.sleep(1)

    def handle_client(self, client_info):
        """Handle client commands and file transfers"""
        conn = client_info['connection']
        addr = client_info['address']
        
        try:
            self.log(f"Handling connection from {addr[0]}:{addr[1]}")
            
            while self.is_running:
                try:
                    command = conn.recv(BUFFER_SIZE).decode().strip().upper()
                    if not command:
                        break
                        
                    self.log(f"Received command from {addr[0]}: {command}")
                    
                    if command == "LIST":
                        self.handle_list_command(conn)
                        
                    elif command == "UPLOAD":
                        self.handle_upload_command(conn, addr)
                        
                    elif command == "DOWNLOAD":
                        self.handle_download_command(conn, addr)
                        
                    elif command == "DELETE":
                        self.handle_delete_command(conn, addr)
                        
                    else:
                        conn.send("INVALID COMMAND".encode())
                        self.log(f"Invalid command from {addr[0]}: {command}")
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    self.log(f"Error handling client {addr[0]}: {str(e)}")
                    break
                    
        except Exception as e:
            self.log(f"Client {addr[0]} error: {str(e)}")
        finally:
            try:
                conn.close()
                if client_info in self.clients:
                    self.clients.remove(client_info)
                self.update_client_list()
                self.log(f"Connection closed with {addr[0]}:{addr[1]}")
            except:
                pass

    def handle_list_command(self, conn):
        """Handle LIST command - send list of files in upload directory"""
        try:
            upload_dir = self.upload_dir_var.get()
            files = os.listdir(upload_dir)
            
            if not files:
                conn.send("[No files on server]".encode())
                return
                
            file_list = []
            for filename in files:
                filepath = os.path.join(upload_dir, filename)
                if os.path.isfile(filepath):
                    size = os.path.getsize(filepath)
                    size_str = f"{size/1024:.1f} KB" if size < 1024*1024 else f"{size/(1024*1024):.1f} MB"
                    file_list.append(f"{filename} ({size_str})")
                    
            response = "\n".join(file_list) if file_list else "[No files on server]"
            conn.send(response.encode())
            
        except Exception as e:
            conn.send(f"Error listing files: {str(e)}".encode())
            raise

    def handle_upload_command(self, conn, addr):
        """Handle UPLOAD command - receive file from client"""
        try:
            filename = conn.recv(BUFFER_SIZE).decode()
            filesize = int(conn.recv(BUFFER_SIZE).decode())
            
            filepath = os.path.join(self.upload_dir_var.get(), filename)
            
            if os.path.exists(filepath):
                conn.send("EXISTS".encode())
                response = conn.recv(BUFFER_SIZE).decode().upper()
                if response != "OVERWRITE":
                    return
            else:
                conn.send("OK".encode())
                
            self.log(f"Receiving file {filename} ({filesize} bytes) from {addr[0]}")
            
            received = 0
            with open(filepath, 'wb') as f:
                while received < filesize:
                    chunk = conn.recv(min(BUFFER_SIZE, filesize - received))
                    if not chunk:
                        raise Exception("Connection closed prematurely")
                        
                    f.write(chunk)
                    received += len(chunk)
                    
            self.log(f"Received file {filename} from {addr[0]}")
            
        except Exception as e:
            self.log(f"Error receiving file from {addr[0]}: {str(e)}")
            try:
                conn.send(f"UPLOAD ERROR: {str(e)}".encode())
            except:
                pass
            raise

    def handle_download_command(self, conn, addr):
        """Handle DOWNLOAD command - send file to client"""
        try:
            filename = conn.recv(BUFFER_SIZE).decode()
            filepath = os.path.join(self.upload_dir_var.get(), filename)
            
            if not os.path.exists(filepath):
                conn.send("NOTFOUND".encode())
                return
                
            filesize = os.path.getsize(filepath)
            conn.send(str(filesize).encode())
            
            response = conn.recv(BUFFER_SIZE).decode().upper()
            if response != "READY":
                return
                
            self.log(f"Sending file {filename} ({filesize} bytes) to {addr[0]}")
            
            sent = 0
            with open(filepath, 'rb') as f:
                while sent < filesize:
                    chunk = f.read(min(BUFFER_SIZE, filesize - sent))
                    conn.sendall(chunk)
                    sent += len(chunk)
                    
            self.log(f"Sent file {filename} to {addr[0]}")
            
        except Exception as e:
            self.log(f"Error sending file to {addr[0]}: {str(e)}")
            raise

    def handle_delete_command(self, conn, addr):
        """Handle DELETE command - delete file on server"""
        try:
            filename = conn.recv(BUFFER_SIZE).decode()
            filepath = os.path.join(self.upload_dir_var.get(), filename)
            
            if not os.path.exists(filepath):
                conn.send("NOTFOUND".encode())
                return
                
            os.remove(filepath)
            conn.send("DELETED".encode())
            self.log(f"Deleted file {filename} requested by {addr[0]}")
            
        except Exception as e:
            self.log(f"Error deleting file for {addr[0]}: {str(e)}")
            try:
                conn.send(f"DELETE ERROR: {str(e)}".encode())
            except:
                pass
            raise

if __name__ == "__main__":
    root = ctk.CTk()
    server = SecureFileServer(root)
    root.mainloop()