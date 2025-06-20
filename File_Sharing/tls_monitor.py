import socket
import ssl
import threading
import logging
from socketserver import ThreadingMixIn
from http.server import HTTPServer, BaseHTTPRequestHandler

# Configuration
PROXY_HOST = '0.0.0.0'
PROXY_PORT = 4445  # Different from server (4443) and monitor (4444)
TARGET_SERVER = ('localhost', 4443)  # Your SecureFileServer

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads"""

class ProxyHandler(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        """Handle HTTPS CONNECT (TLS tunneling)"""
        self.log_request()
        target_host, target_port = self.path.split(':')
        
        try:
            # Connect to target server
            target_sock = socket.create_connection(
                (target_host, int(target_port)),
                timeout=10
            )
            self.send_response(200, 'Connection Established')
            self.end_headers()
            
            # Tunnel SSL between client and server
            self.tunnel_ssl(target_sock)
            
        except Exception as e:
            logging.error(f"Proxy error: {e}")
            self.send_error(500, str(e))
        finally:
            if 'target_sock' in locals():
                target_sock.close()

    def tunnel_ssl(self, target_sock):
        """Monitor TLS traffic without decryption"""
        client_sock = self.connection
        
        # Get client's first data (TLS ClientHello)
        client_hello = client_sock.recv(4096, socket.MSG_PEEK)
        logging.info(f"TLS ClientHello from {self.client_address}: {client_hello[:16]}...")
        
        # Full duplex forwarding
        sockets = [client_sock, target_sock]
        while True:
            try:
                r, _, _ = select.select(sockets, [], [])
                for sock in r:
                    data = sock.recv(4096)
                    if not data:
                        return
                    if sock is client_sock:
                        target_sock.sendall(data)
                        if b"UPLOAD" in data or b"DOWNLOAD" in data:
                            logging.info(f"Command detected: {data[:100]}")
                    else:
                        client_sock.sendall(data)
            except (socket.error, ssl.SSLError) as e:
                logging.warning(f"Tunnel closed: {e}")
                return

def start_proxy():
    """Start the transparent proxy"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename='tls_proxy.log'
    )
    
    server = ThreadedHTTPServer((PROXY_HOST, PROXY_PORT), ProxyHandler)
    logging.info(f"TLS Proxy running on {PROXY_HOST}:{PROXY_PORT}")
    server.serve_forever()

if __name__ == "__main__":
    start_proxy()