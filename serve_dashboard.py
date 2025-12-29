import http.server
import socketserver
import os
import json
from pathlib import Path

PORT = 8000

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Send cache-control headers FIRST
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()
    
    def log_message(self, format, *args):
        """Custom logging"""
        print(f"[{self.log_date_time_string()}] {format % args}")

if __name__ == "__main__":
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    print("=" * 60)
    print("🛡️  XSS Detection Dashboard Server")
    print("=" * 60)
    print(f"📁 Serving files from: {script_dir}")
    print(f"🌐 Dashboard URL: http://localhost:{PORT}/index.html")
    print(f"📊 Test Results: http://localhost:{PORT}/test_results.json")
    print("=" * 60)
    print("\nPress Ctrl+C to stop the server")
    print("=" * 60)
    
    with socketserver.TCPServer(("", PORT), DashboardHandler) as httpd:
        print(f"✅ Server running on http://localhost:{PORT}/")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n✋ Server stopped by user")
            httpd.shutdown()
