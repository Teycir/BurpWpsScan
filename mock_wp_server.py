#!/usr/bin/env python3
"""Local WordPress-like fixture for testing BurpWpsScan URL handling (not part of the extension).

Serves two virtual hosts on 127.0.0.1:8899:
  xxx.yyy.localhost : a WordPress install, both at / and under /blog/
  yyy.localhost  : a plain site with no WordPress markers

Run:  python3 mock_wp_server.py     (Ctrl+C to stop)
Then browse http://xxx.yyy.localhost:8899/blog/ through Burp.
"""
import http.server
import socketserver

PORT = 8899


def wp_page(base):
    return (
        "<html><head>"
        '<meta name="generator" content="WordPress 6.4.3" />'
        '<link rel="stylesheet" href="{b}/wp-content/themes/fixture/style.css" />'
        '<script src="{b}/wp-includes/js/wp-emoji-release.min.js"></script>'
        "</head><body>WordPress fixture (base={b})</body></html>"
    ).format(b=base)


PLAIN = "<html><head><title>plain</title></head><body>nothing here</body></html>"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("{} {}".format(self.headers.get("Host", "-"), self.path), flush=True)

    def _send(self, code, body, ctype="text/html"):
        raw = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        path = self.path.split("?")[0]

        if host == "xxx.yyy.localhost":
            if path in ("/", "/index.php"):
                self._send(200, wp_page(""))
            elif path in ("/blog", "/blog/", "/blog/index.php"):
                self._send(200, wp_page("/blog"))
            elif path.endswith("wp-login.php"):
                self._send(200, wp_page("/blog" if path.startswith("/blog") else ""))
            elif "/wp-content/" in path or "/wp-includes/" in path:
                self._send(200, "/* fixture asset */", "text/css")
            else:
                self._send(404, PLAIN)
        else:
            self._send(200, PLAIN)

    def do_HEAD(self):
        self.do_GET()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    print("fixture on http://127.0.0.1:{} (xxx.yyy.localhost, yyy.localhost)".format(PORT), flush=True)
    with Server(("127.0.0.1", PORT), Handler) as httpd:
        httpd.serve_forever()
