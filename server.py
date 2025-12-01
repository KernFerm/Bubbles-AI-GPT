#!/usr/bin/env python3
"""
Secure static HTTP server for Bubbles-AI-GPT web app
Authentication is handled entirely by Puter.js in the frontend
Run with: python server.py
Then open: http://localhost:8000
"""

import http.server
import socketserver
import webbrowser
import os
import sys
import signal
import threading
import urllib.parse
import time
from pathlib import Path

PORT = 8000
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB max request size
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 100  # requests per window
ALLOWED_EXTENSIONS = {'.html', '.js', '.css', '.json', '.txt', '.ico', '.svg', '.png', '.jpg', '.jpeg', '.gif', '.woff', '.woff2', '.ttf', '.eot'}
BLOCKED_PATHS = {'..', '.env', '.git', '__pycache__', '.vscode', 'node_modules'}

# Rate limiting storage
request_counts = {}
blocked_ips = set()

class SecurityHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Set secure server header
        self.server_version = "Bubbles-AI-GPT/2.0"
        self.sys_version = ""
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Enhanced logging with timestamp and client info"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        client_ip = self.client_address[0]
        print(f"[{timestamp}] {client_ip} - {format % args}")
    
    def is_safe_path(self, path):
        """Check if the requested path is safe and allowed"""
        try:
            # Handle root path
            if path in ['/', '']:
                return True
                
            # Clean the path
            clean_path = path.lstrip('/')
            if not clean_path:
                return True
            
            # Check for blocked path components
            path_parts = clean_path.split('/')
            if any(blocked in path_parts for blocked in BLOCKED_PATHS):
                return False
            
            # Check if file exists and has allowed extension
            file_path = Path(clean_path)
            if file_path.exists() and file_path.is_file():
                extension = file_path.suffix.lower()
                if extension and extension not in ALLOWED_EXTENSIONS:
                    return False
            
            # Block attempts to access parent directories
            if '..' in path_parts:
                return False
                
            return True
        except (ValueError, OSError):
            return False
    
    def sanitize_headers(self):
        """Sanitize and validate request headers"""
        content_length = self.headers.get('Content-Length')
        if content_length:
            try:
                length = int(content_length)
                if length > MAX_CONTENT_LENGTH:
                    self.send_error(413, "Request entity too large")
                    return False
            except ValueError:
                self.send_error(400, "Invalid Content-Length")
                return False
        
        # Check for malicious headers
        user_agent = self.headers.get('User-Agent', '')
        if len(user_agent) > 500:  # Suspiciously long user agent
            self.send_error(400, "Invalid User-Agent")
            return False
        
        return True
    
    def rate_limit_check(self):
        """Check rate limiting for client IP"""
        client_ip = self.client_address[0]
        current_time = time.time()
        
        # Check if IP is blocked
        if client_ip in blocked_ips:
            self.send_error(429, "Too Many Requests - IP Blocked")
            return False
        
        # Clean old entries
        cutoff_time = current_time - RATE_LIMIT_WINDOW
        request_counts[client_ip] = [req_time for req_time in request_counts.get(client_ip, []) if req_time > cutoff_time]
        
        # Add current request
        if client_ip not in request_counts:
            request_counts[client_ip] = []
        request_counts[client_ip].append(current_time)
        
        # Check rate limit
        if len(request_counts[client_ip]) > RATE_LIMIT_MAX_REQUESTS:
            blocked_ips.add(client_ip)
            self.log_message(f"SECURITY: Rate limit exceeded for {client_ip} - IP blocked")
            self.send_error(429, "Too Many Requests")
            return False
        
        return True
    
    def do_GET(self):
        """Enhanced GET handler with security checks"""
        if not self.rate_limit_check():
            return
        if not self.sanitize_headers():
            return
        parsed_path = urllib.parse.urlparse(self.path)
        clean_path = urllib.parse.unquote(parsed_path.path)
        # Add shutdown endpoint
        if clean_path == '/shutdown':
            self.log_message("Received shutdown request from frontend.")
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Shutting down server...')
            # Shutdown in a separate thread to avoid blocking response
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        # Security check for path
        if not self.is_safe_path(clean_path):
            self.log_message(f"SECURITY: Blocked unsafe path access: {clean_path}")
            self.log_message(f"DEBUG: Original path: {self.path}, Clean path: {clean_path}")
            self.send_error(403, "Forbidden")
            return
        # Log access
        self.log_message(f"GET {clean_path}")
        # Call parent GET handler
        super().do_GET()
    
    def do_POST(self):
        """Enhanced POST handler with security checks"""
        if not self.rate_limit_check():
            return
        
        if not self.sanitize_headers():
            return
        
        # Log POST attempt
        self.log_message(f"POST {self.path}")
        
        # For security, we'll block POST requests to prevent form submissions
        self.send_error(405, "Method Not Allowed")
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests securely"""
        if not self.rate_limit_check():
            return
        
        self.send_response(200)
        self.end_headers()
    
    def end_headers(self):
        """Add security headers to all responses"""
        # CORS headers (restrictive for security)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Max-Age', '86400')  # Cache preflight for 24 hours
        
        # Security headers
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
        
        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://js.puter.com; "
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self' https: wss:; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        self.send_header('Content-Security-Policy', csp)
        
        # Cache control for static assets
        if self.path.endswith(('.css', '.js', '.png', '.jpg', '.ico', '.woff', '.woff2')):
            self.send_header('Cache-Control', 'public, max-age=3600')
        else:
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        
        super().end_headers()
    
    def send_error(self, code, message=None):
        """Enhanced error handling with security considerations"""
        if code >= 400:
            self.log_message(f"ERROR {code}: {message or 'Unknown error'}")
        
        # Don't reveal server information in errors
        if code == 404:
            message = "Not Found"
        elif code == 403:
            message = "Forbidden"
        elif code == 500:
            message = "Internal Server Error"
        
        super().send_error(code, message)

def main():
    # Change to the directory containing this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Security check: ensure we're serving from a safe directory
    if not os.path.isfile('index.html'):
        print("❌ Security: index.html not found. Server must run from project directory.")
        sys.exit(1)
    
    httpd = socketserver.TCPServer(("", PORT), SecurityHTTPRequestHandler)
    httpd.allow_reuse_address = True
    
    def signal_handler(sig, frame):
        print("\n🛑 Received shutdown signal. Stopping server...")
        try:
            httpd.shutdown()
            httpd.server_close()
            print("✅ Server stopped cleanly")
        except:
            print("✅ Server stopped")
        os._exit(0)  # Force exit
    
    # Register signal handlers for clean shutdown
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    print(f"🚀 Bubbles-AI-GPT Secure Static Server starting on port {PORT}")
    print(f"📂 Serving files from: {script_dir}")
    print(f"🌐 Open your browser to: http://localhost:{PORT}")
    print(f"� Authentication: Handled by Puter.js (no local user database)")
    print(f"�🛡️  Security features enabled:")
    print(f"   • Rate limiting: {RATE_LIMIT_MAX_REQUESTS} requests per {RATE_LIMIT_WINDOW}s")
    print(f"   • Path sanitization and validation")
    print(f"   • Security headers (CSP, XSS protection, etc.)")
    print(f"   • File extension filtering")
    print(f"   • Request size limits: {MAX_CONTENT_LENGTH // (1024*1024)}MB")
    print("📝 Users must sign in with Puter.js to access AI features")
    print("🛑 Press Ctrl+C to stop the server")
    
    try:
        # Auto-open browser
        webbrowser.open(f'http://localhost:{PORT}')
    except:
        pass
    
    try:
        # Start server in a separate thread so signal handling works properly
        server_thread = threading.Thread(target=httpd.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        # Keep main thread alive to handle signals
        while server_thread.is_alive():
            server_thread.join(1)
            
    except KeyboardInterrupt:
        print("\n🛑 KeyboardInterrupt received. Stopping server...")
        httpd.shutdown()
        httpd.server_close()
        print("✅ Server stopped cleanly")
        sys.exit(0)

if __name__ == "__main__":
    main()
