#!/usr/bin/env python3
"""Reproduction test for the "subdomain collapses to the root domain" bug.

Runs the extension's own URL logic, extracted verbatim from WpsScan.py, against a
local HTTP server. No Burp, no WPScan API, no DNS: every request goes to
127.0.0.1 with a Host header carrying the virtual host name.

    python3 test_url_handling.py          # exit 0 = all checks pass
"""
import ast
import io
import re
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SOURCE = 'WpsScan.py'
METHODS = ['_get_root_domain', '_normalize_url', '_extract_wp_base',
           '_extract_wp_base_from_content', '_add_wp_site', '_extract_url_from_key',
           '_manual_scan_url']


# --------------------------------------------------------------------------
# extract the real implementation from the extension
# --------------------------------------------------------------------------
def load_extension_logic():
    src = io.open(SOURCE, encoding='utf-8', newline='').read()
    version_match = re.search(r'^__version__ = "([^"]+)"', src, re.M)
    version = version_match.group(1) if version_match else '0.0.0'
    tree = ast.parse(src)
    ext = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'BurpExtender')
    segments = {n.name: ast.get_source_segment(src, n).replace('\r\n', '\n')
                for n in ext.body
                if isinstance(n, ast.FunctionDef) and n.name in METHODS}
    missing = [m for m in METHODS if m not in segments]
    assert not missing, missing

    patterns = next(n for n in tree.body
                    if isinstance(n, ast.ClassDef) and n.name == 'PatternCache')
    init = next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == '_init_patterns')

    def indented(text):
        return '\n'.join('    ' + line if line.strip() else line
                         for line in text.split('\n'))

    code = ['class Ext(object):', '    def __init__(self):',
            '        self._callbacks = _Callbacks()', '        self.wp_sites = {}',
            '        self.all_sites_data = []', '        self.list_model = _ListModel()',
            '        self.http_history_indices = set()', '        self.imported_indices = set()',
            '        self._panel = None', '        self.logs = []',
            '    def _log(self, message):', '        self.logs.append(message)']
    for name in METHODS:
        code.append(indented(segments[name]))
    code.append(ast.get_source_segment(src, patterns).replace('\r\n', '\n'))
    code.append(ast.get_source_segment(src, init).replace('\r\n', '\n'))

    ns = {'re': re, '__version__': version, 'SimpleDateFormat': _DateFormat, 'Date': object,
          'JOptionPane': _Pane, '_Callbacks': _Callbacks, '_ListModel': _ListModel,
          'Exception': Exception, 'AttributeError': AttributeError,
          'TypeError': TypeError, 'ValueError': ValueError, 'RuntimeError': RuntimeError}
    exec('\n'.join(code), ns)
    ns['_init_patterns']()
    return ns['Ext'], ns['PatternCache'].WP_PATTERNS


class _Callbacks(object):
    def __init__(self):
        self.errors = []

    def printError(self, message):
        self.errors.append(message)

    def printOutput(self, message):
        pass

    def setExtensionName(self, name):
        pass


class _ListModel(object):
    def __init__(self):
        self.items = []

    def addElement(self, value):
        self.items.append(value)


class _DateFormat(object):
    def __init__(self, pattern=''):
        self.pattern = pattern

    def format(self, date):
        return 'TEST-TS'


class _Pane(object):
    INFORMATION_MESSAGE = 1
    dialogs = []
    @staticmethod
    def showMessageDialog(parent, message, title, kind):
        _Pane.dialogs.append((title, message))


# --------------------------------------------------------------------------
# local reproduction server
# --------------------------------------------------------------------------
def wp_page(base):
    return ('<html><head><meta name="generator" content="WordPress 6.9.1" />'
            '<link rel="stylesheet" href="{b}/wp-content/themes/fixture/style.css" />'
            '<script src="{b}/wp-includes/js/fixture.js"></script>'
            '</head><body>fixture</body></html>').format(b=base)


PLAIN = '<html><head><title>plain</title></head><body>nothing here</body></html>'

# site at /, assets served from /_static/ (the pattern behind the /_static row)
ASSET_PREFIX_PAGE = ('<html><head><meta name="generator" content="WordPress 6.9.1" />'
                     '<link rel="stylesheet" href="/_static/wp-content/themes/x/style.css" />'
                     '<script src="/_static/wp-includes/js/y.js"></script>'
                     '</head><body>asset prefix fixture</body></html>')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        host = (self.headers.get('Host') or '').split(':')[0].lower()
        path = self.path.split('?')[0]

        if host == 'xxx.yyy.localhost':
            if path in ('/', '/index.php'):
                body = wp_page('')
            elif '/wp-content/' in path or '/wp-includes/' in path:
                body = '/* asset */'
            elif path in ('/blog', '/blog/', '/blog/index.php') or path.startswith('/blog/'):
                body = wp_page('/blog')
            else:
                body = PLAIN
        elif host == 'assetprefix.localhost':
            body = ASSET_PREFIX_PAGE if path in ('/', '/index.php') else '/* asset */'
        else:
            body = PLAIN   # apex-like host: reachable, not WordPress

        raw = body.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def start_server():
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def fetch(port, host, path):
    req = urllib.request.Request('http://127.0.0.1:{}{}'.format(port, path),
                                 headers={'Host': '{}:{}'.format(host, port)})
    with OPENER.open(req, timeout=5) as response:
        return response.read().decode('utf-8', 'replace')


# --------------------------------------------------------------------------
# mirrors the branch in processHttpMessage (detect -> derive base -> add)
# --------------------------------------------------------------------------
def live_scan(ext, patterns, port, host, path):
    url = 'http://{}:{}{}'.format(host, port, path)
    body = fetch(port, host, path)
    if not any(p.search(body) for p in patterns):
        return []
    base = ext._extract_wp_base(url)
    if not base:
        base = ext._extract_wp_base_from_content(body, 'http', host, port, url)
    before = len(ext.list_model.items)
    ext._add_wp_site(base or url, host, keep_subdomain=True)
    return ext.list_model.items[before:]


def row_url(ext, key):
    return ext._extract_url_from_key(key)


def main():
    Ext, patterns = load_extension_logic()
    server, port = start_server()
    failures = []

    def check(label, expected, actual):
        status = 'PASS' if expected == actual else 'FAIL'
        if status == 'FAIL':
            failures.append((label, expected, actual))
        print('  [{}] {:38s} expected {!s:<42s} got {!s}'.format(
            status, label, expected, actual))

    print('reproduction server on 127.0.0.1:{} (virtual hosts via Host header)'.format(port))

    print('\n1. HTTP URL scoping (rows the scan list would receive)')
    cases = [
        ('apex not WordPress', 'plain.localhost', '/', []),
        ('WP at subdomain root', 'xxx.yyy.localhost', '/',
         ['http://xxx.yyy.localhost:{}/'.format(port).rstrip('/')]),
        ('WP under /blog', 'xxx.yyy.localhost', '/blog/',
         ['http://xxx.yyy.localhost:{}/blog'.format(port)]),
        ('WP deep page under /blog', 'xxx.yyy.localhost', '/blog/2026/11/story/',
         ['http://xxx.yyy.localhost:{}/blog'.format(port)]),
        ('assets under /_static only', 'assetprefix.localhost', '/',
         ['http://assetprefix.localhost:{}'.format(port)]),
    ]
    for label, host, path, expected in cases:
        ext = Ext()
        rows = [row_url(ext, key) for key in live_scan(ext, patterns, port, host, path)]
        check(label, expected, rows)

    print('\n2. what the old normalization did for the same host')
    ext = Ext()
    check('root-domain collapse (old behaviour)',
          'yyy.localhost', ext._get_root_domain('http://xxx.yyy.localhost:{}'.format(port)))

    print('\n3. context menu (real _manual_scan_url)')
    ext = Ext()
    ext._manual_scan_url('http://xxx.yyy.localhost:{}/blog/wp-login.php'.format(port))
    check('deep URL trimmed to install base',
          ['http://xxx.yyy.localhost:{}/blog'.format(port)], list(ext.wp_sites))
    _Pane.dialogs = []
    ext._manual_scan_url('http://xxx.yyy.localhost:{}/blog/'.format(port))
    check('duplicate -> Already Exists',
          ('Already Exists', True),
          (_Pane.dialogs[-1][0], len(ext.wp_sites) == 1))
    ext._manual_scan_url('http://xxx.yyy.localhost:{}/wp-login.php'.format(port))
    check('login page at host root',
          'http://xxx.yyy.localhost:{}'.format(port),
          list(ext.wp_sites)[-1])

    print('\n4. normalization unit checks')
    ext = Ext()
    for label, url, keep, expected in [
        ('custom port + path + query', 'http://xxx.yyy.localhost:8899/blog?x=1#y', True,
         'http://xxx.yyy.localhost:8899/blog'),
        ('default https port stripped', 'https://xxx.yyy.localhost:443/blog', True,
         'https://xxx.yyy.localhost/blog'),
        ('port-like text in path kept', 'http://xxx.yyy.localhost/a:443/b', True,
         'http://xxx.yyy.localhost/a:443/b'),
        ('legacy root collapse', 'http://xxx.yyy.localhost:8899/blog', False,
         'http://yyy.localhost'),
    ]:
        check(label, expected, ext._normalize_url(url, keep))

    print('\n5. pre-existing behaviour on literal asset-prefix URLs (not touched here)')
    ext = Ext()
    print('  _extract_wp_base(".../_static/wp-content/x.css") -> {}'.format(
        ext._extract_wp_base('http://assetprefix.localhost:{}/_static/wp-content/x.css'.format(port))))

    server.shutdown()
    print()
    if failures:
        print('{} check(s) FAILED'.format(len(failures)))
        return 1
    print('all checks passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
