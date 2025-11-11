# pylint: disable=import-error,consider-using-f-string,too-many-nested-blocks
# type: ignore
from burp import IBurpExtender, ITab, IHttpListener  # type: ignore
from javax.swing import JPanel, JButton, JList, JScrollPane, DefaultListModel, JOptionPane, BorderFactory, ListCellRenderer, JLabel, JCheckBox, BoxLayout, Box, JTextField, JComboBox, JTextArea, JSplitPane, SwingUtilities  # type: ignore
from java.awt import BorderLayout, GridLayout, Color, Font, FlowLayout  # type: ignore
from javax.swing.event import DocumentListener  # type: ignore
from java.awt.event import MouseAdapter  # type: ignore
from java.io import File, FileWriter, BufferedReader, FileReader  # type: ignore
from java.text import SimpleDateFormat  # type: ignore
from java.util import Date  # type: ignore
import json
import re

import urllib2
import time
from threading import Thread, Lock

class PatternCache:
    """Lazy-loaded compiled patterns for Jython compatibility"""
    WP_PATTERNS = None
    VERSION_PATTERNS = None
    PLUGIN_PATTERN = None
    THEME_PATTERN = None

def _init_patterns():
    """Initialize compiled regex patterns (lazy load for Jython)"""
    if PatternCache.WP_PATTERNS is None:
        PatternCache.WP_PATTERNS = [
            re.compile(r'/wp-content/themes/[^"\s]+\.css', re.IGNORECASE),
            re.compile(r'/wp-content/plugins/[^"\s]+\.js', re.IGNORECASE),
            re.compile(r'/wp-includes/js/[^"\s]+\.js', re.IGNORECASE),
            re.compile(r'<meta name="generator" content="WordPress', re.IGNORECASE),
            re.compile(r'wp-emoji-release\.min\.js', re.IGNORECASE),
            re.compile(r'/wp-json/wp/v2/', re.IGNORECASE),
            re.compile(r'<link[^>]+wp-content/themes/', re.IGNORECASE),
            re.compile(r'<script[^>]+wp-includes/js/', re.IGNORECASE),
            re.compile(r'<link[^>]+wp-includes/css/', re.IGNORECASE)
        ]
        PatternCache.VERSION_PATTERNS = [
            re.compile(r'<meta name="generator" content="WordPress\s+(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE),
            re.compile(r'"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"'),
            re.compile(r'<generator>.*WordPress/(\d+\.\d+(?:\.\d+)?)</generator>', re.IGNORECASE)
        ]
        PatternCache.PLUGIN_PATTERN = re.compile(r'/wp-content/plugins/([^/"\s\?]+)', re.IGNORECASE)
        PatternCache.THEME_PATTERN = re.compile(r'/wp-content/themes/([^/"\s\?]+)', re.IGNORECASE)

class WPScanAPI:
    """WPScan API integration for WordPress vulnerability scanning."""
    _api_cache = {}  # {"plugin:slug": {"data": {...}, "timestamp": 123456}, ...}
    _cache_lock = Lock()  # Thread safety for cache operations
    _cache_ttl = 86400  # 24 hours in seconds
    
    # High-risk plugins known to have frequent vulnerabilities
    _HIGH_RISK_PLUGINS = {
        # Form & Contact plugins
        'contact-form-7', 'wpforms-lite', 'wpforms', 'ninja-forms', 'formidable',
        'gravityforms', 'caldera-forms', 'contact-form-7-to-database-extension',
        # E-commerce
        'woocommerce', 'woocommerce-payments', 'woo-gutenberg-products-block',
        'easy-digital-downloads', 'wp-ecommerce',
        # Page Builders
        'elementor', 'elementor-pro', 'beaver-builder', 'divi-builder', 'visual-composer',
        'siteorigin-panels', 'wp-bakery', 'fusion-builder',
        # SEO plugins
        'yoast', 'wordpress-seo', 'all-in-one-seo-pack', 'rank-math', 'seo-by-rank-math',
        # Security plugins
        'wordfence', 'ithemes-security', 'sucuri-scanner', 'all-in-one-wp-security-and-firewall',
        'better-wp-security', 'loginizer', 'limit-login-attempts-reloaded',
        # Backup & Migration
        'updraftplus', 'all-in-one-wp-migration', 'duplicator', 'backupbuddy',
        'backup-guard', 'wp-db-backup',
        # Performance & Cache
        'wp-super-cache', 'w3-total-cache', 'wp-fastest-cache', 'autoptimize',
        'wp-optimize', 'litespeed-cache',
        # Popular utilities
        'jetpack', 'akismet', 'classic-editor', 'duplicate-post', 'really-simple-ssl',
        'google-analytics-for-wordpress', 'wp-mail-smtp', 'redirection', 'broken-link-checker',
        'wp-smushit', 'regenerate-thumbnails', 'enable-media-replace',
        # Membership & LMS
        'memberpress', 'paid-memberships-pro', 'ultimate-member', 'learndash',
        'lifterlms', 'tutor', 'sensei',
        # Sliders & Media
        'revslider', 'slider-revolution', 'metaslider', 'smart-slider-3', 'nextgen-gallery',
        'envira-gallery', 'photo-gallery',
        # Social & Sharing
        'social-warfare', 'monarch', 'shareaholic', 'addtoany', 'jetpack-social',
        # File Management
        'wp-file-manager', 'download-manager', 'simple-file-list',
        # Translation
        'wpml', 'polylang', 'translatepress', 'weglot',
        # Other high-risk
        'advanced-custom-fields', 'custom-post-type-ui', 'wp-statistics',
        'insert-headers-and-footers', 'code-snippets', 'post-smtp'
    }
    
    @staticmethod
    def _get_cache_key(item_type, slug):
        return "{}:{}".format(item_type, slug)
    
    @staticmethod
    def _is_cache_valid(cache_entry):
        if not cache_entry:
            return False
        return (time.time() - cache_entry.get("timestamp", 0)) < WPScanAPI._cache_ttl
    
    @staticmethod
    def _prioritize_plugins(plugins):
        """Sort plugins by vulnerability likelihood - high-risk first"""
        def normalize_plugin(p):
            return p.lower().replace('_', '-').replace(' ', '-')
        
        high_risk = [p for p in plugins if normalize_plugin(p) in WPScanAPI._HIGH_RISK_PLUGINS]
        other = [p for p in plugins if normalize_plugin(p) not in WPScanAPI._HIGH_RISK_PLUGINS]
        return high_risk + other
    
    @staticmethod
    def extract_plugins_themes(response_str):
        """Extract plugin and theme slugs from response"""
        _init_patterns()
        plugins = set(PatternCache.PLUGIN_PATTERN.findall(response_str))
        themes = set(PatternCache.THEME_PATTERN.findall(response_str))
        return list(plugins), list(themes)
    

    @staticmethod
    def test_xmlrpc(url, logger=None):
        """Test XML-RPC endpoint for security issues"""
        result = {"enabled": False, "pingback": False, "multicall": False}
        base_url = url.rstrip('/')
        xmlrpc_url = base_url + '/xmlrpc.php'
        
        response = None
        try:
            req = urllib2.Request(xmlrpc_url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            req.add_header('Content-Type', 'text/xml')
            body = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
            response = urllib2.urlopen(req, body, timeout=10)
            raw_data = response.read()
            if raw_data:
                result["enabled"] = True
                content = str(raw_data)
                if 'pingback.ping' in content:
                    result["pingback"] = True
                if 'system.multicall' in content:
                    result["multicall"] = True
                if logger:
                    logger("[+] XML-RPC enabled")
                    if result["pingback"]:
                        logger("    [!] Pingback available (DDoS risk)")
                    if result["multicall"]:
                        logger("    [!] Multicall available (brute force amplification)")
        except urllib2.HTTPError as e:
            if e.code == 405:
                result["enabled"] = True
                if logger:
                    logger("[+] XML-RPC enabled (405 response)")
        except urllib2.URLError:
            if logger:
                logger("[*] XML-RPC endpoint unreachable")
        except IOError:
            if logger:
                logger("[*] XML-RPC test IO error")
        finally:
            if response:
                response.close()
        return result
    
    @staticmethod
    def discover_rest_endpoints(url, logger=None):
        """Discover and test REST API endpoints"""
        result = {"endpoints": [], "users_exposed": False, "posts_exposed": False}
        base_url = url.rstrip('/')
        
        endpoints = [
            ('/wp-json/', 'API root'),
            ('/wp-json/wp/v2/users', 'Users'),
            ('/wp-json/wp/v2/posts', 'Posts'),
            ('/wp-json/wp/v2/pages', 'Pages'),
            ('/wp-json/wp/v2/media', 'Media')
        ]
        
        for path, name in endpoints:
            response = None
            try:
                req = urllib2.Request(base_url + path)
                req.add_header('User-Agent', 'Mozilla/5.0')
                response = urllib2.urlopen(req, timeout=5)
                if response.getcode() == 200:
                    result["endpoints"].append({"path": path, "name": name, "accessible": True})
                    if 'users' in path:
                        result["users_exposed"] = True
                    if 'posts' in path:
                        result["posts_exposed"] = True
                    if logger:
                        logger("[+] REST endpoint accessible: {}".format(name))
            except urllib2.HTTPError as e:
                if logger:
                    logger("[*] REST endpoint {} returned HTTP {}".format(name, e.code))
                continue
            except urllib2.URLError as e:
                if logger:
                    logger("[*] REST endpoint {} unreachable: {}".format(name, str(e.reason)))
                continue
            except IOError as e:
                if logger:
                    logger("[*] REST endpoint {} IO error: {}".format(name, str(e)))
                continue
            finally:
                if response:
                    response.close()
        
        return result
    
    @staticmethod
    def check_plugin_updates(plugins, logger=None):
        """Check if plugins are outdated using WordPress.org API"""
        if not plugins:
            if logger:
                logger("[*] No plugins detected to check for updates")
            return []
        
        outdated = []
        for plugin_slug in plugins[:10]:
            response = None
            try:
                api_url = "https://api.wordpress.org/plugins/info/1.0/{}.json".format(plugin_slug)
                req = urllib2.Request(api_url)
                response = urllib2.urlopen(req, timeout=5)
                data = json.loads(response.read())
                latest = data.get('version')
                if latest:
                    outdated.append({"slug": plugin_slug, "latest_version": latest})
                    if logger:
                        logger("[*] Plugin '{}': latest version {}".format(plugin_slug, latest))
            except urllib2.HTTPError as e:
                if logger:
                    logger("[*] Plugin '{}' update check failed: HTTP {}".format(plugin_slug, e.code))
                continue
            except urllib2.URLError as e:
                if logger:
                    logger("[*] Plugin '{}' update check network error".format(plugin_slug))
                continue
            except ValueError as e:
                if logger:
                    logger("[*] Plugin '{}' update check JSON error".format(plugin_slug))
                continue
            except IOError as e:
                if logger:
                    logger("[*] Plugin '{}' update check IO error".format(plugin_slug))
                continue
            finally:
                if response:
                    response.close()
        return outdated
    
    @staticmethod
    def enumerate_users(url, logger=None):
        """Enumerate WordPress users via wp-json API and author redirect"""
        users = []
        base_url = url.rstrip('/')
        
        # Try REST API first
        api_url = base_url + '/wp-json/wp/v2/users'
        response = None
        try:
            req = urllib2.Request(api_url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            response = urllib2.urlopen(req, timeout=10)
            raw_data = response.read()
            if raw_data:
                data = json.loads(raw_data)
                if isinstance(data, list):
                    for user in data:
                        user_info = {
                            'id': user.get('id'),
                            'name': user.get('name'),
                            'slug': user.get('slug'),
                            'url': user.get('url', '')
                        }
                        users.append(user_info)
                        if logger:
                            logger("[+] User found: {} (ID: {})".format(user_info['name'], user_info['id']))
        except urllib2.HTTPError as e:
            if e.code == 401:
                if logger:
                    logger("[*] User enumeration via REST API blocked (401)")
            elif e.code == 403:
                if logger:
                    logger("[*] User enumeration via REST API blocked (403)")
        except urllib2.URLError:
            if logger:
                logger("[*] User enumeration network error")
        except ValueError:
            if logger:
                logger("[*] User enumeration JSON parse error")
        finally:
            if response:
                response.close()
        
        # If REST API failed, try author redirect method
        if not users:
            if logger:
                logger("[*] Trying author redirect enumeration...")
            for user_id in range(1, 6):  # Try first 5 users
                response = None
                try:
                    author_url = "{}/?author={}".format(base_url, user_id)
                    req = urllib2.Request(author_url)
                    req.add_header('User-Agent', 'Mozilla/5.0')
                    response = urllib2.urlopen(req, timeout=5)
                    final_url = response.geturl()
                    # Extract username from redirect URL (e.g., /author/admin/)
                    match = re.search(r'/author/([^/]+)', final_url)
                    if match:
                        username = match.group(1)
                        users.append({'id': user_id, 'name': username, 'slug': username, 'url': ''})
                        if logger:
                            logger("[+] User found via redirect: {} (ID: {})".format(username, user_id))
                except urllib2.HTTPError as e:
                    if logger:
                        logger("[*] Author redirect for ID {} returned HTTP {}".format(user_id, e.code))
                    continue
                except urllib2.URLError as e:
                    if logger:
                        logger("[*] Author redirect for ID {} network error".format(user_id))
                    continue
                except IOError as e:
                    if logger:
                        logger("[*] Author redirect for ID {} IO error".format(user_id))
                    continue
                finally:
                    if response:
                        response.close()
        
        if not users and logger:
            logger("[*] No users enumerated (site may be hardened)")
        
        return users
    
    @staticmethod
    def detect_version_enhanced(url, cached_content=None, logger=None):
        """Enhanced version detection from cached content or minimal requests"""
        _init_patterns()
        base_url = url.rstrip('/')
        
        # Try cached content first (from homepage)
        if cached_content:
            for idx, pattern in enumerate(PatternCache.VERSION_PATTERNS):
                match = pattern.search(cached_content)
                if match:
                    version = match.group(1)
                    if logger:
                        sources = ['meta tag', 'inline JSON', 'generator tag']
                        logger("[+] Version {} detected from {}".format(version, sources[idx]))
                    return version
        
        # Only try lightweight endpoints if cached content failed
        opml_pattern = re.compile(r'generator="WordPress/(\d+\.\d+(?:\.\d+)?)"')
        methods = [
            (base_url + '/wp-links-opml.php', opml_pattern, 'OPML'),
            (base_url + '/wp-json/', PatternCache.VERSION_PATTERNS[1], 'wp-json API'),
            (base_url + '/feed/', PatternCache.VERSION_PATTERNS[2], 'RSS feed'),
            (base_url + '/?feed=rss2', PatternCache.VERSION_PATTERNS[2], 'RSS2 feed'),
            (base_url + '/?feed=atom', PatternCache.VERSION_PATTERNS[2], 'Atom feed'),
            (base_url, PatternCache.VERSION_PATTERNS[0], 'homepage meta'),
        ]
        
        for test_url, pattern, source in methods:
            response = None
            try:
                req = urllib2.Request(test_url)
                req.add_header('User-Agent', 'Mozilla/5.0')
                response = urllib2.urlopen(req, timeout=5)
                raw_content = response.read(524288)  # 512KB max
                content = str(raw_content) if raw_content else ''
                match = pattern.search(content)
                if match:
                    version = match.group(1)
                    if logger:
                        logger("[+] Version {} detected from {}".format(version, source))
                    return version
            except urllib2.HTTPError as e:
                if logger:
                    logger("[*] Version check {} returned HTTP {}".format(source, e.code))
                continue
            except urllib2.URLError as e:
                if logger:
                    logger("[*] Version check {} network error".format(source))
                continue
            finally:
                if response:
                    response.close()
        
        return None
    
    @staticmethod
    def detect_version(url):
        """Detect WordPress version from site (legacy method)"""
        return WPScanAPI.detect_version_enhanced(url, None)
    
    @staticmethod
    def detect_security_hardening(url, cached_content, logger=None):
        """Detect security measures hiding WordPress version"""
        findings = []
        base_url = url.rstrip('/')
        
        # Check homepage for security plugin indicators
        if cached_content:
            security_plugins = {
                'wordfence': 'Wordfence Security',
                'ithemes-security': 'iThemes Security',
                'all-in-one-wp-security': 'All In One WP Security',
                'sucuri': 'Sucuri Security',
                'wp-hide': 'WP Hide & Security Enhancer',
                'hide-my-wp': 'Hide My WP'
            }
            for slug, name in security_plugins.items():
                if slug in cached_content.lower():
                    findings.append("Security Plugin: {}".format(name))
                    if logger:
                        logger("[+] Security Plugin: {}".format(name))
            
            if '<meta name="generator"' not in cached_content.lower():
                findings.append("Generator meta tag removed")
                if logger:
                    logger("[+] Generator meta tag removed")
        
        # Check OPML
        response = None
        try:
            req = urllib2.Request(base_url + '/wp-links-opml.php')
            req.add_header('User-Agent', 'Mozilla/5.0')
            response = urllib2.urlopen(req, timeout=5)
            opml = str(response.read(524288))
            if 'generator=' not in opml.lower():
                findings.append("OPML generator attribute removed")
                if logger:
                    logger("[+] OPML generator attribute removed")
        except urllib2.HTTPError as e:
            if logger:
                logger("[*] OPML check HTTP error: {}".format(e.code))
        except urllib2.URLError as e:
            if logger:
                logger("[*] OPML check network error")
        except IOError as e:
            if logger:
                logger("[*] OPML check IO error")
        finally:
            if response:
                response.close()
        
        # Check readme.html
        response = None
        try:
            req = urllib2.Request(base_url + '/readme.html')
            req.add_header('User-Agent', 'Mozilla/5.0')
            response = urllib2.urlopen(req, timeout=5)
            response.close()
        except urllib2.HTTPError as e:
            if e.code == 403 or e.code == 404:
                findings.append("readme.html blocked/removed")
                if logger:
                    logger("[+] readme.html blocked/removed")
        except urllib2.URLError as e:
            if logger:
                logger("[*] readme.html check network error")
        except IOError as e:
            if logger:
                logger("[*] readme.html check IO error")
        finally:
            if response:
                response.close()
        
        # Check RSS feed
        response = None
        try:
            req = urllib2.Request(base_url + '/feed/')
            req.add_header('User-Agent', 'Mozilla/5.0')
            response = urllib2.urlopen(req, timeout=5)
            rss = str(response.read(524288))
            if '<generator>' not in rss.lower() or 'wordpress' not in rss.lower():
                findings.append("RSS generator tag removed/modified")
                if logger:
                    logger("[+] RSS generator tag removed/modified")
        except urllib2.HTTPError as e:
            if logger:
                logger("[*] RSS feed check HTTP error: {}".format(e.code))
        except urllib2.URLError as e:
            if logger:
                logger("[*] RSS feed check network error")
        except IOError as e:
            if logger:
                logger("[*] RSS feed check IO error")
        finally:
            if response:
                response.close()
        
        # Check XML-RPC
        response = None
        try:
            req = urllib2.Request(base_url + '/xmlrpc.php')
            req.add_header('User-Agent', 'Mozilla/5.0')
            response = urllib2.urlopen(req, timeout=5)
            response.close()
        except urllib2.HTTPError as e:
            if e.code == 403:
                findings.append("XML-RPC access blocked")
                if logger:
                    logger("[+] XML-RPC access blocked")
        except urllib2.URLError as e:
            if logger:
                logger("[*] XML-RPC hardening check network error")
        except IOError as e:
            if logger:
                logger("[*] XML-RPC hardening check IO error")
        finally:
            if response:
                response.close()
        
        # Check wp-config.php
        response = None
        try:
            req = urllib2.Request(base_url + '/wp-config.php')
            req.add_header('User-Agent', 'Mozilla/5.0')
            response = urllib2.urlopen(req, timeout=5)
            response.close()
        except urllib2.HTTPError as e:
            if e.code == 403:
                findings.append("wp-config.php access blocked")
                if logger:
                    logger("[+] wp-config.php access blocked")
        except urllib2.URLError as e:
            if logger:
                logger("[*] wp-config.php check network error")
        except IOError as e:
            if logger:
                logger("[*] wp-config.php check IO error")
        finally:
            if response:
                response.close()
        
        if findings and logger:
            logger("[*] Site has {} security measures active".format(len(findings)))
        
        return findings
    
    @staticmethod
    def scan_plugin_theme(slug, item_type, api_key, logger=None, credit_callback=None, api_calls_list=None):
        """Scan plugin or theme using WPScan API with 24h cache"""
        result = {"success": False, "slug": slug, "type": item_type, "vulnerabilities": [], "error": None}
        
        # Check cache first (thread-safe)
        cache_key = WPScanAPI._get_cache_key(item_type, slug)
        with WPScanAPI._cache_lock:
            cached = WPScanAPI._api_cache.get(cache_key)
            if WPScanAPI._is_cache_valid(cached):
                if logger:
                    logger("[CACHE] {} '{}': {} vulnerabilities".format(item_type.title(), slug, len(cached["data"]["vulnerabilities"])))
                return cached["data"]
        
        try:
            endpoint = "plugins" if item_type == "plugin" else "themes"
            api_url = "https://wpscan.com/api/v3/{}/{}".format(endpoint, slug)
            req = urllib2.Request(api_url)
            req.add_header("Authorization", "Token token={}".format(api_key))
            req.add_header("User-Agent", "BurpWpsScan/1.0")
            
            response = None
            try:
                response = urllib2.urlopen(req, timeout=15)
                data = json.loads(response.read())
            finally:
                if response:
                    response.close()
            
            if api_calls_list is not None:
                api_calls_list.append({"type": item_type, "slug": slug})
            if credit_callback:
                credit_callback()
            
            if slug in data and data[slug]:
                result["vulnerabilities"] = data[slug].get("vulnerabilities", [])
                result["success"] = True
            else:
                result["success"] = True
                result["vulnerabilities"] = []
            
            # Always log scan result
            if logger:
                if result["vulnerabilities"]:
                    logger("[+] {} '{}': {} vulnerabilities".format(item_type.title(), slug, len(result["vulnerabilities"])))
                    for vuln in result["vulnerabilities"]:
                        logger("    - {} ({})".format(vuln.get("title", "Unknown"), vuln.get("vuln_type", "N/A")))
                else:
                    logger("[+] {} '{}': 0 vulnerabilities (clean)".format(item_type.title(), slug))
            
            # Cache successful result (thread-safe)
            if result["success"]:
                with WPScanAPI._cache_lock:
                    WPScanAPI._api_cache[cache_key] = {"data": result, "timestamp": time.time()}
        except urllib2.HTTPError as e:
            if e.code == 404:
                result["success"] = True
                result["vulnerabilities"] = []
                if api_calls_list is not None:
                    api_calls_list.append({"type": item_type, "slug": slug})
                if credit_callback:
                    credit_callback()
            else:
                result["error"] = "HTTP {}".format(e.code)
                if logger:
                    logger("[!] HTTP Error {}: {}".format(e.code, str(e)))
        except urllib2.URLError as e:
            result["error"] = "Network error: {}".format(str(e.reason))
            if logger:
                logger("[!] Network error: {}".format(str(e)))
        except ValueError as e:
            result["error"] = "Invalid API response"
            if logger:
                logger("[!] JSON parse error: {}".format(str(e)))
        except KeyError as e:
            result["error"] = "Invalid API response"
            if logger:
                logger("[!] Missing key in response: {}".format(str(e)))
        
        return result
    
    @staticmethod
    def extract_plugins_from_history(url, callbacks, helpers, logger=None):
        """Scan Burp HTTP history for target domain to find all plugins/themes"""
        plugins = set()
        themes = set()
        
        try:
            from urlparse import urlparse
        except ImportError:
            from urllib.parse import urlparse
        
        parsed = urlparse(url)
        target_domain = parsed.hostname if hasattr(parsed, 'hostname') else parsed.netloc.split(':')[0]
        
        proxy_history = callbacks.getProxyHistory()
        if not proxy_history:
            return list(plugins), list(themes)
        
        count = 0
        for item in proxy_history:
            try:
                service = item.getHttpService()
                if service.getHost() != target_domain:
                    continue
                
                response = item.getResponse()
                if not response:
                    continue
                
                response_str = helpers.bytesToString(response)
                p, t = WPScanAPI.extract_plugins_themes(response_str)
                plugins.update(p)
                themes.update(t)
                count += 1
            except AttributeError:
                continue
            except TypeError:
                continue
            except RuntimeError:
                continue
        
        if logger and (len(plugins) > 0 or len(themes) > 0):
            logger("[+] Found {} plugins, {} themes from {} history items".format(len(plugins), len(themes), count))
        
        return list(plugins), list(themes)
    
    @staticmethod
    def scan_site(url, api_key, logger=None, cached_version=None, callbacks=None, helpers=None, credit_callback=None):  # pylint: disable=too-many-branches,too-many-statements
        """Scan WordPress site using WPScan API"""
        result = {
            "success": False,
            "url": url,
            "wordpress_version": None,
            "vulnerabilities": [],
            "plugins": [],
            "themes": [],
            "error": None,
            "api_calls": []
        }
        
        try:
            if logger:
                logger("[*] Fetching homepage...")
            
            # Fetch homepage once for all detections
            response = None
            content = None
            try:
                req = urllib2.Request(url)
                req.add_header('User-Agent', 'Mozilla/5.0')
                response = urllib2.urlopen(req, timeout=10)
                raw_content = response.read(1048576)
                content = str(raw_content) if raw_content else ''
                if logger:
                    logger("[+] Homepage fetched")
            except urllib2.HTTPError as e:
                if logger:
                    logger("[!] HTTP Error fetching homepage: {}".format(e.code))
            except urllib2.URLError as e:
                if logger:
                    logger("[!] Network error fetching homepage: {}".format(str(e.reason)))
            except ValueError as e:
                if logger:
                    logger("[!] Value error fetching homepage: {}".format(str(e)))
            except IOError as e:
                if logger:
                    logger("[!] IO error fetching homepage: {}".format(str(e)))
            finally:
                if response:
                    response.close()
            
            # Security tests (run BEFORE version check - these are free)
            if logger:
                logger("[*] Testing XML-RPC...")
            result["xmlrpc"] = WPScanAPI.test_xmlrpc(url, logger)
            
            if logger:
                logger("[*] Discovering REST API endpoints...")
            result["rest_api"] = WPScanAPI.discover_rest_endpoints(url, logger)
            
            if logger:
                logger("[*] Enumerating users...")
            result["users"] = WPScanAPI.enumerate_users(url, logger)
            
            # Try version from cached content first
            version = None
            if cached_version:
                version = cached_version
                if logger:
                    logger("[+] Version: {} (from Burp traffic)".format(cached_version))
            else:
                if logger:
                    logger("[*] Detecting version...")
                version = WPScanAPI.detect_version_enhanced(url, content, logger)
            
            result["security_plugins"] = []
            if not version:
                if logger:
                    logger("[!] Version detection failed")
                    logger("[*] Analyzing security hardening...")
                hardening = WPScanAPI.detect_security_hardening(url, content, logger)
                result["security_hardening"] = hardening
                
                if len(hardening) >= 3:
                    result["error"] = "Version hidden by security hardening ({} measures)".format(len(hardening))
                    result["success"] = True
                    if logger:
                        logger("[*] Site has strong security hardening - likely well-maintained")
                        logger("[*] Skipping vulnerability scan to save API credits")
                else:
                    result["error"] = "Could not detect WordPress version"
                return result
            
            result["wordpress_version"] = version
            
            if logger:
                logger("[*] Detecting plugins/themes...")
            
            # Extract from homepage first
            plugins, themes = set(), set()
            if content:
                p, t = WPScanAPI.extract_plugins_themes(content)
                plugins.update(p)
                themes.update(t)
            
            # Scan Burp history for more plugins/themes
            if callbacks and helpers:
                p, t = WPScanAPI.extract_plugins_from_history(url, callbacks, helpers, logger)
                plugins.update(p)
                themes.update(t)
            
            plugins, themes = list(plugins), list(themes)
            if logger:
                logger("[+] Found {} plugins, {} themes".format(len(plugins), len(themes)))
                if plugins:
                    for idx, p in enumerate(plugins[:20], 1):
                        logger("    {}. Plugin: {}".format(idx, p))
                if themes:
                    for idx, t in enumerate(themes[:10], 1):
                        logger("    {}. Theme: {}".format(idx, t))
                if len(plugins) == 0 and callbacks:
                    logger("[*] Tip: Browse more pages through Burp to discover plugins!")
            
            if logger:
                logger("[*] Querying WPScan API...")
            
            # WPScan API expects version without dots
            if not version:
                result["error"] = "Invalid version format"
                return result
            # Convert to string to handle both Python and Java strings in Jython
            version = str(version)
            version_no_dots = version.replace('.', '')
            api_url = "https://wpscan.com/api/v3/wordpresses/{}".format(version_no_dots)
            req = urllib2.Request(api_url)
            req.add_header("Authorization", "Token token={}".format(api_key))
            req.add_header("User-Agent", "BurpWpsScan/1.0")
            
            response = None
            try:
                response = urllib2.urlopen(req, timeout=15)
                raw_data = response.read()
                if not raw_data:
                    result["error"] = "Empty API response"
                    return result
                data = json.loads(raw_data)
            finally:
                if response:
                    response.close()
            
            result["api_calls"].append({"type": "core", "version": version})
            if credit_callback:
                credit_callback()
            
            # Check both version formats in response
            version_key = None
            if version_no_dots in data:
                version_key = version_no_dots
            elif version in data:
                version_key = version
            
            if version_key and version_key in data:
                wp_data = data[version_key]
                if isinstance(wp_data, dict):
                    result["vulnerabilities"] = wp_data.get("vulnerabilities", [])
                    result["success"] = True
                    if logger:
                        logger("[+] Core: {} vulnerabilities".format(len(result["vulnerabilities"])))
                        for vuln in result["vulnerabilities"]:
                            logger("    - {} ({})".format(vuln.get("title", "Unknown"), vuln.get("vuln_type", "N/A")))
                else:
                    result["error"] = "Invalid API response format"
                    if logger:
                        logger("[!] Invalid API response format")
                    return result
            else:
                result["error"] = "Version {} not found in WPScan database".format(version)
                if logger:
                    logger("[!] Version not found in database")
                return result
            
            # Smart plugin scanning - scan all high-risk plugins
            plugins = WPScanAPI._prioritize_plugins(plugins)
            high_risk = [p for p in plugins if p.lower().replace('_', '-') in WPScanAPI._HIGH_RISK_PLUGINS]
            other = [p for p in plugins if p.lower().replace('_', '-') not in WPScanAPI._HIGH_RISK_PLUGINS]
            
            if logger and plugins:
                logger("[*] Found {} high-risk plugins (will scan all)".format(len(high_risk)))
                if other:
                    logger("[*] Found {} other plugins (will scan up to 3)".format(len(other)))
            
            # Scan ALL high-risk plugins
            for plugin in high_risk:
                if not plugin or len(plugin) > 100:
                    continue
                cache_key = WPScanAPI._get_cache_key("plugin", plugin)
                if not WPScanAPI._is_cache_valid(WPScanAPI._api_cache.get(cache_key)):
                    time.sleep(1.5)
                plugin_result = WPScanAPI.scan_plugin_theme(plugin, "plugin", api_key, logger, credit_callback, result["api_calls"])
                result["plugins"].append(plugin_result)
            
            # Scan up to 3 other plugins
            for plugin in other[:3]:
                if not plugin or len(plugin) > 100:
                    continue
                cache_key = WPScanAPI._get_cache_key("plugin", plugin)
                if not WPScanAPI._is_cache_valid(WPScanAPI._api_cache.get(cache_key)):
                    time.sleep(1.5)
                plugin_result = WPScanAPI.scan_plugin_theme(plugin, "plugin", api_key, logger, credit_callback, result["api_calls"])
                result["plugins"].append(plugin_result)
            
            if logger and len(other) > 3:
                logger("[*] {} other plugins not scanned (limit: 3)".format(len(other) - 3))
            
            # Scan only first theme (usually only 1 active theme)
            if themes and logger:
                logger("[*] Scanning active theme...")
            
            for theme in themes[:1]:
                if not theme or len(theme) > 100:
                    continue
                cache_key = WPScanAPI._get_cache_key("theme", theme)
                if not WPScanAPI._is_cache_valid(WPScanAPI._api_cache.get(cache_key)):
                    time.sleep(1.5)
                theme_result = WPScanAPI.scan_plugin_theme(theme, "theme", api_key, logger, credit_callback, result["api_calls"])
                result["themes"].append(theme_result)
                break  # Only scan first theme
            
            # Check for plugin updates
            if logger and plugins:
                logger("[*] Checking plugin updates...")
            result["plugin_updates"] = WPScanAPI.check_plugin_updates(plugins, logger)
            
            # Save API cache after all scans complete (batch save for performance)
            with WPScanAPI._cache_lock:
                if logger:
                    logger("[*] Saving API cache...")
            
            # Summary
            total_vulns = len(result["vulnerabilities"])
            plugin_vulns = sum(len(p.get("vulnerabilities", [])) for p in result["plugins"] if p.get("success"))
            theme_vulns = sum(len(t.get("vulnerabilities", [])) for t in result["themes"] if t.get("success"))
            total_vulns += plugin_vulns + theme_vulns
            
            if logger:
                logger("\n" + "="*50)
                logger("SCAN COMPLETE")
                logger("="*50)
                logger("API Credits Used: {} (1 core + {} plugins + {} themes)".format(
                    len(result["api_calls"]),
                    sum(1 for c in result["api_calls"] if c["type"] == "plugin"),
                    sum(1 for c in result["api_calls"] if c["type"] == "theme")
                ))
                
                # Core vulnerabilities
                if result["vulnerabilities"]:
                    logger("Core: {} vulnerabilities".format(len(result["vulnerabilities"])))
                    for idx, vuln in enumerate(result["vulnerabilities"], 1):
                        logger("  {}. {} - {}".format(idx, vuln.get("vuln_type", "N/A"), vuln.get("title", "Unknown")))
                
                # Plugin vulnerabilities
                if plugin_vulns > 0:
                    logger("Plugins: {} vulnerabilities".format(plugin_vulns))
                    for p in result["plugins"]:
                        if p.get("success") and p.get("vulnerabilities"):
                            logger("  - {}: {} vulnerabilities".format(p["slug"], len(p["vulnerabilities"])))
                            for vuln in p["vulnerabilities"]:
                                logger("    * {} ({})".format(vuln.get("title", "Unknown"), vuln.get("vuln_type", "N/A")))
                
                # Theme vulnerabilities
                if theme_vulns > 0:
                    logger("Themes: {} vulnerabilities".format(theme_vulns))
                    for t in result["themes"]:
                        if t.get("success") and t.get("vulnerabilities"):
                            logger("  - {}: {} vulnerabilities".format(t["slug"], len(t["vulnerabilities"])))
                            for vuln in t["vulnerabilities"]:
                                logger("    * {} ({})".format(vuln.get("title", "Unknown"), vuln.get("vuln_type", "N/A")))
                
                # Security findings
                xmlrpc = result.get("xmlrpc", {})
                if xmlrpc.get("enabled"):
                    logger("XML-RPC: Enabled")
                    if xmlrpc.get("pingback"):
                        logger("  [!] Pingback enabled (DDoS risk)")
                    if xmlrpc.get("multicall"):
                        logger("  [!] Multicall enabled (brute force risk)")
                
                rest = result.get("rest_api", {})
                if rest.get("endpoints"):
                    logger("REST API: {} endpoints accessible".format(len(rest["endpoints"])))
                    for ep in rest.get("endpoints", []):
                        logger("  - {} ({})".format(ep.get("name"), ep.get("path")))
                    if rest.get("users_exposed"):
                        logger("  [!] User enumeration via REST API")
                
                if result.get("users"):
                    logger("Users: {} enumerated".format(len(result["users"])))
                
                updates = result.get("plugin_updates", [])
                if updates:
                    logger("Plugin Updates: {} plugins checked".format(len(updates)))
                
                logger("Total vulnerabilities: {}".format(total_vulns))
                logger("="*50)
                logger("")
                
        except urllib2.HTTPError as e:
            if e.code == 401:
                result["error"] = "Invalid API key"
            elif e.code == 403:
                result["error"] = "Access forbidden - check API key permissions"
            elif e.code == 404:
                result["error"] = "Version {} not found in WPScan database".format(version)
            elif e.code == 429:
                result["error"] = "Rate limit exceeded - wait before retrying"
            else:
                result["error"] = "HTTP Error {}: {}".format(e.code, e.msg)
            if logger:
                logger("[!] HTTP Error {}: {}".format(e.code, str(e)))
        except urllib2.URLError as e:
            result["error"] = "Network error: {}".format(str(e.reason))
            if logger:
                logger("[!] Network error: {}".format(str(e)))
        except ValueError as e:
            result["error"] = "Invalid API response"
            if logger:
                logger("[!] JSON parse error: {}".format(str(e)))
        except KeyError as e:
            result["error"] = "Invalid API response"
            if logger:
                logger("[!] Missing key in response: {}".format(str(e)))
        
        return result

class ReportGenerator:
    """Generate vulnerability reports in multiple formats."""
    @staticmethod
    def generate_markdown(scan_result):
        """Generate markdown report"""
        url = scan_result.get("url", "Unknown")
        version = scan_result.get("wordpress_version", "Unknown")
        vulns = scan_result.get("vulnerabilities", [])
        plugins = scan_result.get("plugins", [])
        themes = scan_result.get("themes", [])
        timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date())
        
        total_vulns = len(vulns)
        for p in plugins:
            total_vulns += len(p.get("vulnerabilities", []))
        for t in themes:
            total_vulns += len(t.get("vulnerabilities", []))
        
        users = scan_result.get("users", [])
        xmlrpc = scan_result.get("xmlrpc", {})
        rest_api = scan_result.get("rest_api", {})
        plugin_updates = scan_result.get("plugin_updates", [])
        
        parts = [
            "# WordPress Vulnerability Report\n\n",
            "**Target**: {}\n".format(url),
            "**Scan Date**: {}\n".format(timestamp),
            "**WordPress Version**: {}\n\n".format(version),
            "---\n\n",
            "## Executive Summary\n\n",
            "- Core Vulnerabilities: {}\n".format(len(vulns)),
            "- Plugins Found: {}\n".format(len(plugins)),
            "- Themes Found: {}\n".format(len(themes)),
            "- Users Enumerated: {}\n".format(len(users)),
            "- XML-RPC Enabled: {}\n".format("Yes" if xmlrpc.get("enabled") else "No"),
            "- REST API Endpoints: {}\n".format(len(rest_api.get("endpoints", []))),
            "- Total Vulnerabilities: {}\n\n".format(total_vulns),
            "---\n\n"
        ]
        
        # Security findings
        if xmlrpc.get("enabled") or rest_api.get("endpoints"):
            parts.append("## Security Findings\n\n")
            
            if xmlrpc.get("enabled"):
                parts.append("### XML-RPC\n\n")
                parts.append("- **Status**: Enabled\n")
                if xmlrpc.get("pingback"):
                    parts.append("- **Risk**: Pingback enabled (DDoS amplification)\n")
                if xmlrpc.get("multicall"):
                    parts.append("- **Risk**: Multicall enabled (brute force amplification)\n")
                parts.append("\n")
            
            if rest_api.get("endpoints"):
                parts.append("### REST API\n\n")
                parts.append("**Accessible Endpoints**:\n")
                for ep in rest_api.get("endpoints", []):
                    parts.append("- {} - {}".format(ep.get("name"), ep.get("path")))
                    if "users" in ep.get("path", "").lower():
                        parts.append(" - **User enumeration possible**")
                    parts.append("\n")
                if rest_api.get("users_exposed"):
                    parts.append("\n**Security Risk**: User enumeration via REST API is possible\n")
                if rest_api.get("posts_exposed"):
                    parts.append("**Information Disclosure**: Posts/content accessible via REST API\n")
                parts.append("\n")
            
            parts.append("---\n\n")
        
        # Users section
        if users:
            parts.append("## Enumerated Users\n\n")
            for user in users:
                parts.append("- **{}** (ID: {}, Slug: {})\n".format(
                    user.get('name', 'Unknown'),
                    user.get('id', 'N/A'),
                    user.get('slug', 'N/A')
                ))
            parts.append("\n---\n\n")
        
        parts.append("## Core Vulnerabilities\n\n")
        
        for idx, vuln in enumerate(vulns, 1):
            parts.append("### {}. {}\n\n".format(idx, vuln.get("title", "Unknown")))
            parts.append("**Type**: {}\n".format(vuln.get("vuln_type", "N/A")))
            parts.append("**Fixed In**: {}\n\n".format(vuln.get("fixed_in", "N/A")))
            
            refs = vuln.get("references", {})
            if refs:
                parts.append("**References**:\n")
                for ref_type, ref_list in refs.items():
                    if isinstance(ref_list, list):
                        for ref in ref_list[:3]:
                            parts.append("- {}\n".format(ref))
            parts.append("\n---\n\n")
        
        # Plugin vulnerabilities
        parts.append("## Plugin Vulnerabilities\n\n")
        for plugin in plugins:
            plugin_vulns = plugin.get("vulnerabilities", [])
            if plugin_vulns:
                parts.append("### Plugin: {}\n\n".format(plugin.get("slug", "Unknown")))
                for vuln in plugin_vulns:
                    parts.append("- **{}**\n".format(vuln.get("title", "Unknown")))
                    parts.append("  - Type: {}\n".format(vuln.get("vuln_type", "N/A")))
                    parts.append("  - Fixed in: {}\n\n".format(vuln.get("fixed_in", "N/A")))
        
        # Theme vulnerabilities
        parts.append("## Theme Vulnerabilities\n\n")
        for theme in themes:
            theme_vulns = theme.get("vulnerabilities", [])
            if theme_vulns:
                parts.append("### Theme: {}\n\n".format(theme.get("slug", "Unknown")))
                for vuln in theme_vulns:
                    parts.append("- **{}**\n".format(vuln.get("title", "Unknown")))
                    parts.append("  - Type: {}\n".format(vuln.get("vuln_type", "N/A")))
                    parts.append("  - Fixed in: {}\n\n".format(vuln.get("fixed_in", "N/A")))
        
        parts.extend([
            "## Recommendations\n\n",
            "1. Update WordPress to the latest version\n",
            "2. Review and patch all identified vulnerabilities\n",
            "3. Implement Web Application Firewall\n",
            "4. Regular security audits\n"
        ])
        
        return ''.join(parts)
    
    @staticmethod
    def generate_ai_prompt(scan_result):
        """Generate AI-ready prompt"""
        url = scan_result.get("url", "Unknown")
        version = scan_result.get("wordpress_version", "Unknown")
        vulns = scan_result.get("vulnerabilities", [])
        plugins = scan_result.get("plugins", [])
        themes = scan_result.get("themes", [])
        
        total_vulns = len(vulns)
        for p in plugins:
            total_vulns += len(p.get("vulnerabilities", []))
        for t in themes:
            total_vulns += len(t.get("vulnerabilities", []))
        
        users = scan_result.get("users", [])
        xmlrpc = scan_result.get("xmlrpc", {})
        rest_api = scan_result.get("rest_api", {})
        
        parts = [
            "You are a penetration testing expert. Analyze the following WordPress vulnerability scan results and provide:\n\n",
            "1. Risk assessment for each vulnerability\n",
            "2. Exploitation difficulty (Easy/Medium/Hard)\n",
            "3. Potential impact on business\n",
            "4. Step-by-step exploitation guidance (for authorized testing only)\n",
            "5. Detailed remediation steps\n",
            "6. Additional security recommendations\n\n",
            "Format your response as a professional penetration testing report section.\n\n",
            "---\n\n",
            "SCAN RESULTS:\n\n",
            "Target: {}\n".format(url),
            "WordPress Version: {}\n".format(version),
            "Plugins Found: {}\n".format(len(plugins)),
            "Themes Found: {}\n".format(len(themes)),
            "Users Enumerated: {}\n".format(len(users)),
            "XML-RPC Enabled: {}\n".format("Yes" if xmlrpc.get("enabled") else "No"),
            "REST API Endpoints: {}\n".format(len(rest_api.get("endpoints", []))),
            "Total Vulnerabilities: {}\n\n".format(total_vulns)
        ]
        
        if xmlrpc.get("enabled"):
            parts.append("XML-RPC FINDINGS:\n")
            parts.append("  - Status: Enabled\n")
            if xmlrpc.get("pingback"):
                parts.append("  - Pingback available (DDoS amplification risk)\n")
            if xmlrpc.get("multicall"):
                parts.append("  - Multicall available (brute force amplification risk)\n")
            parts.append("\n")
        
        if rest_api.get("endpoints"):
            parts.append("REST API ENDPOINTS:\n")
            for ep in rest_api.get("endpoints", []):
                parts.append("  - {} - {}\n".format(ep.get("name"), ep.get("path")))
            if rest_api.get("users_exposed"):
                parts.append("  [!] User enumeration possible\n")
            parts.append("\n")
        
        if users:
            parts.append("ENUMERATED USERS:\n")
            for user in users:
                parts.append("  - {} (ID: {})\n".format(user.get('name'), user.get('id')))
            parts.append("\n")
        
        parts.append("CORE VULNERABILITIES:\n\n")
        
        for idx, vuln in enumerate(vulns, 1):
            parts.append("{}. {}\n".format(idx, vuln.get("title", "Unknown")))
            parts.append("   Type: {}\n".format(vuln.get("vuln_type", "N/A")))
            parts.append("   Fixed in: {}\n\n".format(vuln.get("fixed_in", "N/A")))
        
        parts.append("\nPLUGIN VULNERABILITIES:\n\n")
        for plugin in plugins:
            plugin_vulns = plugin.get("vulnerabilities", [])
            if plugin_vulns:
                parts.append("Plugin: {}\n".format(plugin.get("slug", "Unknown")))
                for vuln in plugin_vulns:
                    parts.append("  - {}\n".format(vuln.get("title", "Unknown")))
                    parts.append("    Type: {}\n".format(vuln.get("vuln_type", "N/A")))
                parts.append("\n")
        
        parts.append("THEME VULNERABILITIES:\n\n")
        for theme in themes:
            theme_vulns = theme.get("vulnerabilities", [])
            if theme_vulns:
                parts.append("Theme: {}\n".format(theme.get("slug", "Unknown")))
                for vuln in theme_vulns:
                    parts.append("  - {}\n".format(vuln.get("title", "Unknown")))
                    parts.append("    Type: {}\n".format(vuln.get("vuln_type", "N/A")))
                parts.append("\n")
        
        parts.extend([
            "---\n\n",
            "Provide your analysis below:\n"
        ])
        
        return ''.join(parts)
    
    @staticmethod
    def generate_json(scan_result):
        """Generate JSON export"""
        timestamp = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'").format(Date())
        
        export = {
            "scan_metadata": {
                "timestamp": timestamp,
                "target_url": scan_result.get("url", "Unknown"),
                "scanner": "WPScan API v3",
                "burp_extension": "BurpWpsScan v1.0"
            },
            "wordpress_info": {
                "version": scan_result.get("wordpress_version", "Unknown"),
                "outdated": len(scan_result.get("vulnerabilities", [])) > 0
            },
            "vulnerabilities": scan_result.get("vulnerabilities", []),
            "plugins": scan_result.get("plugins", []),
            "themes": scan_result.get("themes", []),
            "users": scan_result.get("users", []),
            "xmlrpc": scan_result.get("xmlrpc", {}),
            "rest_api": scan_result.get("rest_api", {}),
            "plugin_updates": scan_result.get("plugin_updates", []),
            "summary": {
                "core_vulnerabilities": len(scan_result.get("vulnerabilities", [])),
                "plugins_found": len(scan_result.get("plugins", [])),
                "themes_found": len(scan_result.get("themes", [])),
                "users_enumerated": len(scan_result.get("users", [])),
                "total_vulnerabilities": len(scan_result.get("vulnerabilities", [])) + 
                    sum(len(p.get("vulnerabilities", [])) for p in scan_result.get("plugins", [])) +
                    sum(len(t.get("vulnerabilities", [])) for t in scan_result.get("themes", []))
            }
        }
        
        return json.dumps(export, indent=2)

class AlternatingRowRenderer(ListCellRenderer):
    """Custom list cell renderer with alternating row colors and status indicators."""
    def __init__(self, extender):
        self.extender = extender
    
    def getListCellRendererComponent(self, list, value, index, isSelected, cellHasFocus):  # pylint: disable=invalid-name
        """Render list cell with custom styling."""
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.X_AXIS))
        panel.setOpaque(True)
        
        safe_value = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        text_label = JLabel(safe_value)
        text_label.setFont(Font("Monospaced", Font.PLAIN, 12))
        panel.add(text_label)
        
        if index in self.extender.http_history_indices:
            panel.add(Box.createHorizontalGlue())
            history_label = JLabel("[HTTP HISTORY]")
            history_label.setFont(Font("Monospaced", Font.BOLD, 12))
            history_label.setForeground(Color(0, 100, 200))
            panel.add(history_label)
        elif index in self.extender.imported_indices:
            panel.add(Box.createHorizontalGlue())
            imported_label = JLabel("[IMPORTED]")
            imported_label.setFont(Font("Monospaced", Font.BOLD, 12))
            imported_label.setForeground(Color(156, 39, 176))
            panel.add(imported_label)
        
        if isSelected:
            panel.setBackground(Color(184, 207, 229))
        else:
            status = self.extender._get_row_status(index)
            if status == "Scanning":
                panel.setBackground(Color(255, 249, 196))
            elif status == "Scanned":
                panel.setBackground(Color(200, 230, 201))
            elif status == "Error":
                panel.setBackground(Color(255, 205, 210))
            elif index % 2 == 0:
                panel.setBackground(Color.WHITE)
            else:
                panel.setBackground(Color(245, 245, 245))
        
        return panel

class DoubleClickListener(MouseAdapter):
    """Handle double-click events on WordPress site list."""
    def __init__(self, extender):
        self.extender = extender
    
    def mouseClicked(self, event):  # pylint: disable=invalid-name
        """Handle mouse click events."""
        if event.getClickCount() == 2:
            idx = self.extender.site_list.getSelectedIndex()
            if idx >= 0:
                key = self.extender.list_model.getElementAt(idx)
                url = self.extender._extract_url_from_key(key)
                if url:
                    confirm = JOptionPane.showConfirmDialog(
                        self.extender._panel,
                        "Scan {} with WPScan API?".format(url),
                        "Confirm Scan",
                        JOptionPane.YES_NO_OPTION
                    )
                    if confirm == JOptionPane.YES_OPTION:
                        self.extender.scan_selected()

class SearchListener(DocumentListener):
    """Listen for search field changes and apply filters."""
    def __init__(self, extender):
        self.extender = extender
    
    def insertUpdate(self, e):  # pylint: disable=invalid-name
        """Handle text insertion."""
        self.extender._apply_filters()
    
    def removeUpdate(self, e):  # pylint: disable=invalid-name
        """Handle text removal."""
        self.extender._apply_filters()
    
    def changedUpdate(self, e):  # pylint: disable=invalid-name
        """Handle text change."""
        self.extender._apply_filters()

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    """Main Burp Suite extension for WordPress vulnerability scanning."""
    def registerExtenderCallbacks(self, callbacks):  # pylint: disable=invalid-name
        """Initialize the extension."""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("WpsScan")
        
        self.wp_sites = {}
        self.all_sites_data = []
        self.site_status = self._load_status()
        self.http_history_indices = set()
        self.imported_indices = set()
        self.cached_versions = {}
        self.list_model = DefaultListModel()
        self.site_list = JList(self.list_model)
        self.site_list.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.site_list.setCellRenderer(AlternatingRowRenderer(self))
        self.site_list.addMouseListener(DoubleClickListener(self))
        
        self.api_key = self._load_api_key()
        self.live_scan_enabled = True
        self.scan_running = False
        self.last_api_call = 0
        self.min_api_interval = 2
        self.rate_limited_until = 0
        self._load_api_cache()
        self.api_call_count = self._load_api_count()
        self.api_count_date = self._get_today_date()
        self.api_credits_used = self._load_api_credits()
        self.api_credits_date = self._get_today_date()
        
        self.log_area = JTextArea()
        self.log_area.setEditable(False)
        self.log_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        
        self._panel = JPanel(BorderLayout())
        self._panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        top_container = JPanel(BorderLayout())
        
        api_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        api_panel.add(JLabel("WPScan API Key:"))
        self.api_key_field = JTextField(40)
        if self.api_key:
            self.api_key_field.setText(self.api_key)
        api_panel.add(self.api_key_field)
        save_key_btn = JButton("Save Key")
        save_key_btn.setFont(Font("Dialog", Font.BOLD, 12))
        save_key_btn.addActionListener(lambda e: self._save_api_key())
        api_panel.add(save_key_btn)
        
        counter_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        counter_panel.setBorder(BorderFactory.createLineBorder(Color.GRAY, 2))
        self.api_counter_label = JLabel("Websites Scanned: 0")
        self.api_counter_label.setFont(Font("Monospaced", Font.BOLD, 14))
        counter_panel.add(self.api_counter_label)
        self.api_credits_label = JLabel("API Credits: 0")
        self.api_credits_label.setFont(Font("Monospaced", Font.BOLD, 14))
        counter_panel.add(self.api_credits_label)
        reset_counter_btn = JButton("Reset")
        reset_counter_btn.setFont(Font("Dialog", Font.BOLD, 12))
        reset_counter_btn.addActionListener(lambda e: self._reset_api_counter())
        counter_panel.add(reset_counter_btn)
        api_panel.add(counter_panel)
        self._update_api_counter_display()
        self._update_api_credits_display()
        top_container.add(api_panel, BorderLayout.NORTH)
        
        btn_panel = JPanel(GridLayout(3, 3, 5, 5))
        btn_panel.setBorder(BorderFactory.createEmptyBorder(5, 0, 10, 0))
        
        self.live_scan_btn = JButton(u"\u25B6 Live Scan: ON")
        self.live_scan_btn.setFont(Font("Dialog", Font.BOLD, 12))
        self.live_scan_btn.setBackground(Color(46, 125, 50))
        self.live_scan_btn.setForeground(Color.WHITE)
        self.live_scan_btn.addActionListener(lambda e: self._toggle_live_scan())
        
        history_scan_btn = JButton(u"\u23F1 Scan HTTP History")
        history_scan_btn.setFont(Font("Dialog", Font.BOLD, 12))
        history_scan_btn.setBackground(Color(25, 118, 210))
        history_scan_btn.setForeground(Color.WHITE)
        history_scan_btn.addActionListener(lambda e: self._scan_http_history())
        
        import_urls_btn = JButton(u"\u2191 Import URLs")
        import_urls_btn.setFont(Font("Dialog", Font.BOLD, 12))
        import_urls_btn.setBackground(Color(94, 53, 177))
        import_urls_btn.setForeground(Color.WHITE)
        import_urls_btn.addActionListener(lambda e: self._show_import_dialog())
        
        scan_all_btn = JButton(u"\u2699 Scan All")
        scan_all_btn.setFont(Font("Dialog", Font.BOLD, 12))
        scan_all_btn.setBackground(Color(251, 140, 0))
        scan_all_btn.setForeground(Color.WHITE)
        scan_all_btn.addActionListener(lambda e: self._scan_all())
        
        export_btn = JButton(u"\u2193 Export Reports")
        export_btn.setFont(Font("Dialog", Font.BOLD, 12))
        export_btn.setBackground(Color(69, 90, 100))
        export_btn.setForeground(Color.WHITE)
        export_btn.addActionListener(lambda e: self.export_reports())
        
        clear_btn = JButton(u"\u2716 Clear List")
        clear_btn.setFont(Font("Dialog", Font.BOLD, 12))
        clear_btn.setBackground(Color(183, 28, 28))
        clear_btn.setForeground(Color.WHITE)
        clear_btn.addActionListener(lambda e: self._clear_list())
        
        btn_panel.add(self.live_scan_btn)
        btn_panel.add(history_scan_btn)
        btn_panel.add(import_urls_btn)
        btn_panel.add(scan_all_btn)
        btn_panel.add(export_btn)
        btn_panel.add(clear_btn)
        
        top_container.add(btn_panel, BorderLayout.CENTER)
        self._panel.add(top_container, BorderLayout.NORTH)
        
        center_panel = JPanel(BorderLayout())
        
        search_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        search_panel.add(JLabel("Search:"))
        self.search_field = JTextField(30)
        self.search_field.getDocument().addDocumentListener(SearchListener(self))
        search_panel.add(self.search_field)
        search_panel.add(JLabel("Sort:"))
        self.sort_combo = JComboBox(["Default", "Host", "Status", "Detection Time"])
        self.sort_combo.addActionListener(lambda e: self._apply_filters())
        search_panel.add(self.sort_combo)
        center_panel.add(search_panel, BorderLayout.NORTH)
        
        list_scroll = JScrollPane(self.site_list)
        list_scroll.setBorder(BorderFactory.createTitledBorder("WordPress Sites (Double-click to scan)"))
        center_panel.add(list_scroll, BorderLayout.CENTER)
        
        status_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.scanned_cb = JCheckBox("Scanned")
        self.vulnerable_cb = JCheckBox("Vulnerable")
        self.fp_cb = JCheckBox("False Positive")
        self.scanned_cb.addActionListener(lambda e: self._update_status())
        self.vulnerable_cb.addActionListener(lambda e: self._update_status())
        self.fp_cb.addActionListener(lambda e: self._update_status())
        clear_status_btn = JButton("Clear Tags")
        clear_status_btn.setFont(Font("Dialog", Font.BOLD, 12))
        clear_status_btn.addActionListener(lambda e: self._clear_status())
        status_panel.add(self.scanned_cb)
        status_panel.add(self.vulnerable_cb)
        status_panel.add(self.fp_cb)
        status_panel.add(clear_status_btn)
        center_panel.add(status_panel, BorderLayout.SOUTH)
        
        log_scroll = JScrollPane(self.log_area)
        log_scroll.setBorder(BorderFactory.createTitledBorder("Scan Log"))
        
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, center_panel, log_scroll)
        split_pane.setResizeWeight(0.7)
        split_pane.setDividerLocation(400)
        
        self._panel.add(split_pane, BorderLayout.CENTER)
        self.site_list.addListSelectionListener(lambda e: self._on_selection_change() if not e.getValueIsAdjusting() else None)
        
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        
        self._callbacks.printOutput("[+] WpsScan extension loaded successfully")
        self._log("[+] WpsScan extension loaded successfully")
        if self.api_key:
            thread = Thread(target=self._verify_api_key)
            thread.daemon = True
            thread.start()
        else:
            self._callbacks.printError("[!] Warning: WPScan API key not configured. Enter key in UI and click Save Key.")
            self._log("[!] Warning: WPScan API key not configured. Enter key in UI and click Save Key.")
    
    def getTabCaption(self):  # pylint: disable=invalid-name
        """Return tab caption."""
        count = self.list_model.getSize()
        return "WpsScan" if count == 0 else "WpsScan ({})".format(count)
    
    def getUiComponent(self):  # pylint: disable=invalid-name
        """Return UI component."""
        return self._panel
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):  # pylint: disable=invalid-name
        """Process HTTP messages for WordPress detection."""
        if messageIsRequest or not self.live_scan_enabled:
            return
        
        try:
            _init_patterns()
            response = messageInfo.getResponse()
            if not response:
                return
            
            response_str = self._helpers.bytesToString(response)
            response_info = self._helpers.analyzeResponse(response)
            
            # Check response body for WordPress patterns
            wp_detected = any(pattern.search(response_str) for pattern in PatternCache.WP_PATTERNS)
            
            # Extract version if found
            version_match = None
            if wp_detected:
                for pattern in PatternCache.VERSION_PATTERNS:
                    version_match = pattern.search(response_str)
                    if version_match:
                        break
            
            # Also check headers for WordPress indicators
            if not wp_detected:
                try:
                    headers = response_info.getHeaders()
                    for header in headers:
                        header_str = str(header).lower()
                        if 'wordpress' in header_str:
                            wp_detected = True
                            break
                except AttributeError as e:
                    self._callbacks.printError("[!] Header check attribute error: {}".format(str(e)))
                except TypeError as e:
                    self._callbacks.printError("[!] Header check type error: {}".format(str(e)))
            
            if wp_detected:
                service = messageInfo.getHttpService()
                protocol = service.getProtocol()
                host = service.getHost()
                port = service.getPort()
                
                if (protocol == "https" and port == 443) or (protocol == "http" and port == 80):
                    url = "{}://{}".format(protocol, host)
                else:
                    url = "{}://{}:{}".format(protocol, host, port)
                
                request_info = self._helpers.analyzeRequest(messageInfo)
                req_url = str(request_info.getUrl())
                
                wp_base = self._extract_wp_base(req_url)
                if wp_base:
                    url = wp_base
                
                normalized = self._normalize_url(url)
                if version_match:
                    self.cached_versions[normalized] = version_match.group(1)
                
                self._add_wp_site(url, host)
        except AttributeError as e:
            self._callbacks.printError("[!] processHttpMessage attribute error: {}".format(str(e)))
        except TypeError as e:
            self._callbacks.printError("[!] processHttpMessage type error: {}".format(str(e)))
        except RuntimeError as e:
            self._callbacks.printError("[!] processHttpMessage runtime error: {}".format(str(e)))
    
    def _load_api_key(self):
        reader = None
        try:
            export_dir = self._get_export_dir()
            if not export_dir:
                return None
            
            import os
            config_path = os.path.join(export_dir, "wpsscan_config.txt")
            f = File(config_path)
            if not f.exists():
                return None
            
            reader = BufferedReader(FileReader(f))
            line = reader.readLine()
            while line:
                if line.strip().startswith("WPSSCAN_API_KEY="):
                    return line.split("=", 1)[1].strip()
                line = reader.readLine()
        except IOError as e:
            self._callbacks.printError("[!] _load_api_key IO error: {}".format(str(e)))
        except RuntimeError as e:
            self._callbacks.printError("[!] _load_api_key runtime error: {}".format(str(e)))
        finally:
            if reader:
                try:
                    reader.close()
                except IOError as e:
                    self._callbacks.printError("[!] Failed to close reader: {}".format(str(e)))
        return None
    
    def _extract_wp_base(self, full_url):
        """Extract WordPress base URL from full URL"""
        try:
            # Look for common WP paths and extract base
            wp_indicators = ['/wp-content/', '/wp-includes/', '/wp-admin/', '/wp-json/']
            for indicator in wp_indicators:
                if indicator in full_url:
                    base = full_url.split(indicator)[0]
                    return base
        except AttributeError as e:
            self._callbacks.printError("[!] _extract_wp_base attribute error: {}".format(str(e)))
        except ValueError as e:
            self._callbacks.printError("[!] _extract_wp_base value error: {}".format(str(e)))
        return None
    
    def _get_root_domain(self, url):
        """Extract root domain from URL (e.g., cd.krytter.com -> krytter.com)"""
        try:
            match = re.match(r'https?://([^/:]+)', url)
            if not match:
                return url
            domain = match.group(1)
            parts = domain.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return domain
        except (AttributeError, ValueError, IndexError) as e:
            self._callbacks.printError("[!] _get_root_domain error: {}".format(str(e)))
            return url
    
    def _normalize_url(self, url):
        """Normalize URL to root domain, keeping protocol"""
        # Remove port if standard
        url = re.sub(r':443$', '', url)
        url = re.sub(r':80$', '', url)
        # Remove trailing slash
        url = url.rstrip('/')
        
        # Extract protocol and root domain
        match = re.match(r'(https?)://([^/:]+)', url)
        if match:
            protocol = match.group(1)
            root = self._get_root_domain(url)
            return "{}://{}".format(protocol, root)
        return url
    
    def _add_wp_site(self, url, host, from_history=False, from_import=False):
        # Normalize to root domain
        normalized = self._normalize_url(url)
        
        # For HTTP history or import, allow adding even if it exists
        if normalized in self.wp_sites and not from_history and not from_import:
            return
        
        timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date())
        self.wp_sites[normalized] = {
            "host": host,
            "detected_time": timestamp,
            "status": "Detected",
            "scan_result": None
        }
        
        root = self._get_root_domain(normalized)
        key = "[{}] {} - Detected - {}".format(len(self.wp_sites), normalized, timestamp)
        self.list_model.addElement(key)
        self.all_sites_data.append({"key": key, "url": normalized, "host": root, "status": "Detected", "time": timestamp})
        
        if from_history:
            self.http_history_indices.add(len(self.all_sites_data) - 1)
        elif from_import:
            self.imported_indices.add(len(self.all_sites_data) - 1)
        
        self._callbacks.setExtensionName("WpsScan ({})".format(len(self.wp_sites)))
        self._callbacks.printOutput("[+] WordPress detected: {}".format(normalized))
        self._log("[+] WordPress detected: {}".format(normalized))
    
    def _get_row_status(self, index):
        if index < len(self.all_sites_data):
            return self.all_sites_data[index].get("status", "Detected")
        return "Detected"
    
    def _extract_url_from_key(self, key):
        match = re.search(r'\] (https?://[^\s]+) -', key)
        if match:
            return match.group(1)
        return None
    
    def _verify_api_key(self):
        response = None
        try:
            req = urllib2.Request("https://wpscan.com/api/v3/wordpresses/64")
            req.add_header("Authorization", "Token token={}".format(self.api_key))
            response = urllib2.urlopen(req, timeout=10)
            self._callbacks.printOutput("[+] WPScan API key validated successfully")
            self._log("[+] WPScan API key validated successfully")
        except urllib2.HTTPError as e:
            if e.code == 401:
                self._callbacks.printError("[!] Invalid WPScan API key")
            elif e.code == 429:
                self.rate_limited_until = time.time() + 60
                self._callbacks.printOutput("[+] WPScan API key valid (rate limit reached)")
                self._log("[+] WPScan API key valid (rate limit reached)")
        except urllib2.URLError as e:
            self._callbacks.printError("[!] Network error verifying API key: {}".format(str(e)))
        finally:
            if response:
                response.close()
    
    def _save_api_key(self):
        new_key = self.api_key_field.getText().strip()
        if not new_key:
            self._log("[!] API key field is empty. Please enter your WPScan API key.")
            JOptionPane.showMessageDialog(
                self._panel,
                "Please enter your WPScan API key in the field above.\n\nGet a free API key at: https://wpscan.com/api",
                "API Key Required",
                JOptionPane.WARNING_MESSAGE
            )
            return
        
        if len(new_key) < 10 or len(new_key) > 200:
            self._log("[!] API key format appears invalid (expected 10-100 characters)")
            JOptionPane.showMessageDialog(
                self._panel,
                "The API key format appears invalid.\n\nExpected: 10-200 characters\nReceived: {} characters\n\nPlease check your API key and try again.".format(len(new_key)),
                "Invalid API Key Format",
                JOptionPane.ERROR_MESSAGE
            )
            return
        
        # Reset rate limit if key changed
        if self.api_key != new_key:
            self.rate_limited_until = 0
            self._log("[*] API key changed - rate limit reset")
        
        self.api_key = new_key
        
        writer = None
        try:
            import os
            self._callbacks.printOutput("[DEBUG] os.name = {}".format(os.name))
            export_dir = self._get_export_dir()
            self._callbacks.printOutput("[DEBUG] export_dir = {}".format(export_dir))
            if not export_dir:
                self._log("[!] Failed to create configuration directory")
                JOptionPane.showMessageDialog(
                    self._panel,
                    "Unable to create configuration directory.\n\nPlease check file system permissions.",
                    "Configuration Error",
                    JOptionPane.ERROR_MESSAGE
                )
                return
            
            env_path = os.path.join(export_dir, "wpsscan_config.txt")
            
            writer = FileWriter(env_path)
            writer.write("# WPScan API Key\n")
            writer.write("WPSSCAN_API_KEY={}\n".format(new_key))
            writer.write("\n# OpenRouter API Key\n")
            writer.write("OPENROUTER_API_KEY=\n")
            
            self._log("[+] API key saved to: {}".format(env_path))
            self._callbacks.printOutput("[+] API key saved to: {}".format(env_path))
            thread = Thread(target=self._verify_and_notify)
            thread.daemon = True
            thread.start()
        except IOError as e:
            self._log("[!] Failed to save (IO error): {}".format(str(e)))
            self._callbacks.printError("[!] API key save failed: {}".format(str(e)))
        except RuntimeError as e:
            self._log("[!] Failed to save (runtime error): {}".format(str(e)))
            self._callbacks.printError("[!] API key save failed: {}".format(str(e)))
        finally:
            if writer:
                try:
                    writer.close()
                except IOError as e:
                    self._callbacks.printError("[!] Failed to close writer: {}".format(str(e)))
    
    def _verify_and_notify(self):
        self._log("[*] Validating API key...")
        response = None
        try:
            req = urllib2.Request("https://wpscan.com/api/v3/wordpresses/64")
            req.add_header("Authorization", "Token token={}".format(self.api_key))
            response = urllib2.urlopen(req, timeout=10)
            self._log("[+] API key validated successfully")
            self._callbacks.printOutput("[+] WPScan API key validated")
        except urllib2.HTTPError as e:
            if e.code == 401:
                self._log("[!] Invalid WPScan API key")
                self._callbacks.printError("[!] Invalid WPScan API key")
            elif e.code == 429:
                self.rate_limited_until = time.time() + 60
                self._callbacks.printOutput("[+] WPScan API key valid (rate limit reached)")
                self._log("[+] API key valid (rate limit reached)")
        except urllib2.URLError as e:
            self._log("[!] Network error: {}".format(str(e)))
            self._callbacks.printError("[!] Could not verify WPScan API key")
        finally:
            if response:
                response.close()
    
    def scan_selected(self):
        # 1. Check API key
        current_key = self.api_key_field.getText().strip()
        if not current_key:
            self._log("[!] No API key configured")
            return
        
        # 2. Check rate limit
        current_time = time.time()
        if current_time < self.rate_limited_until:
            wait_time = int(self.rate_limited_until - current_time) + 1
            self._log("[!] Rate limited: {} seconds remaining (or change API key)".format(wait_time))
            return
        
        # 3. Proceed with scan
        if self.scan_running:
            return
        
        idx = self.site_list.getSelectedIndex()
        if idx < 0:
            return
        
        self.api_key = current_key
        key = self.list_model.getElementAt(idx)
        url = self._extract_url_from_key(key)
        
        if not url:
            return
        
        thread = Thread(target=self._scan_worker, args=(idx, url))
        thread.daemon = True
        thread.start()
    
    def _scan_all(self):
        # 1. Check API key
        current_key = self.api_key_field.getText().strip()
        if not current_key:
            self._log("[!] No API key configured")
            return
        
        # 2. Check rate limit
        current_time = time.time()
        if current_time < self.rate_limited_until:
            wait_time = int(self.rate_limited_until - current_time) + 1
            self._log("[!] Rate limited: {} seconds remaining (or change API key)".format(wait_time))
            return
        
        # 3. Proceed with scan
        if self.scan_running or len(self.all_sites_data) == 0:
            return
        
        self.api_key = current_key
        thread = Thread(target=self._scan_all_worker)
        thread.daemon = True
        thread.start()
    
    def _scan_all_worker(self):
        try:
            self.scan_running = True
            # Get URLs in current list display order that haven't been scanned yet
            seen = set()
            unique_urls = []
            for i in range(self.list_model.getSize()):
                key = self.list_model.getElementAt(i)
                url = self._extract_url_from_key(key)
                if url and url not in seen and not self.wp_sites[url].get("scan_result"):
                    unique_urls.append(url)
                    seen.add(url)
            total = len(unique_urls)
            if total == 0:
                self._log("[*] All sites already scanned. No new scans needed.")
                return
            self._log("\n" + "="*60)
            self._log("[*] Starting batch scan of {} unique sites".format(total))
            self._log("="*60)
            
            for idx, url in enumerate(unique_urls):
                # Check if rate limited BEFORE each scan
                current_time = time.time()
                if current_time < self.rate_limited_until:
                    wait_time = int(self.rate_limited_until - current_time) + 1
                    self._log("\n[!] API rate limited - {} seconds remaining".format(wait_time))
                    self._log("[*] Stopping batch scan. Change API key or wait.")
                    JOptionPane.showMessageDialog(
                        self._panel,
                        "WPScan API rate limit reached.\n\nScanned: {}/{}\nTime remaining: {} seconds\n\nOptions:\n1. Wait for rate limit to expire\n2. Change API key to continue".format(idx, total, wait_time),
                        "Rate Limited",
                        JOptionPane.WARNING_MESSAGE
                    )
                    break
                
                self._log("\n" + "="*60)
                self._log("[*] Progress: {}/{} - Scanning: {}".format(idx + 1, total, url))
                self._log("="*60)
                self._callbacks.printOutput(
                    "[*] Batch scan progress: {}/{}  - {}".format(
                        idx + 1, total, url
                    )
                )
                
                # Update status in all_sites_data entries for this URL
                for site_idx, site_data in enumerate(self.all_sites_data):
                    if site_data["url"] == url:
                        self.all_sites_data[site_idx]["status"] = "Scanning"
                self.site_list.repaint()
                
                # Rate limiting
                time_since_last = current_time - self.last_api_call
                if time_since_last < self.min_api_interval:
                    wait_time = self.min_api_interval - time_since_last
                    time.sleep(wait_time)
                
                cached_ver = self.cached_versions.get(url)
                result = WPScanAPI.scan_site(url, self.api_key, self._log, cached_ver, self._callbacks, self._helpers, self._increment_api_credits)
                self.last_api_call = time.time()
                self._increment_api_counter()
                
                # Handle rate limiting
                if not result["success"] and "Rate limit" in result.get("error", ""):
                    self.rate_limited_until = time.time() + 60
                    self._log("[!] RATE LIMIT REACHED - 60 second cooldown active")
                
                if result["success"]:
                    # Update all entries with this URL
                    for site_idx, site_data in enumerate(self.all_sites_data):
                        if site_data["url"] == url:
                            self.all_sites_data[site_idx]["status"] = "Scanned"
                    self.wp_sites[url]["scan_result"] = result
                    self.wp_sites[url]["status"] = "Scanned"
                    vuln_count = len(result.get("vulnerabilities", []))
                    for p in result.get("plugins", []):
                        vuln_count += len(p.get("vulnerabilities", []))
                    for t in result.get("themes", []):
                        vuln_count += len(t.get("vulnerabilities", []))
                    self._log("[+] Scan complete: {} total vulnerabilities".format(vuln_count))
                else:
                    # Update all entries with this URL
                    for site_idx, site_data in enumerate(self.all_sites_data):
                        if site_data["url"] == url:
                            self.all_sites_data[site_idx]["status"] = "Error"
                    error_msg = result.get("error", "Unknown error")
                    self._log("[!] Scan failed: {}".format(error_msg))
                
                self.site_list.repaint()
            
            # Save cache after batch scan completes
            self._save_api_cache()
            
            # Count successful scans and generate summary
            success_count = sum(1 for url in unique_urls if self.wp_sites[url].get("scan_result", {}).get("success", False))
            self._log("\n" + "="*60)
            self._log("[+] Batch scan complete: {}/{} sites scanned successfully".format(success_count, total))
            self._log("[*] Total API credits used: {}".format(self.api_credits_used))
            self._log("="*60)
            
            # Summary by website
            if success_count > 0:
                self._log("\nVULNERABILITY SUMMARY BY WEBSITE:")
                self._log("="*60)
                for url in unique_urls:
                    result = self.wp_sites[url].get("scan_result")
                    if result and result.get("success"):
                        core_vulns = len(result.get("vulnerabilities", []))
                        plugin_vulns = sum(len(p.get("vulnerabilities", [])) for p in result.get("plugins", []) if p.get("success"))
                        theme_vulns = sum(len(t.get("vulnerabilities", [])) for t in result.get("themes", []) if t.get("success"))
                        total_vulns = core_vulns + plugin_vulns + theme_vulns
                        
                        self._log("\n[*] {}".format(url))
                        self._log("    Version: {}".format(result.get("wordpress_version", "Unknown")))
                        self._log("    Core: {} vulnerabilities".format(core_vulns))
                        if core_vulns > 0:
                            for vuln in result.get("vulnerabilities", []):
                                self._log("      - {}".format(vuln.get("title", "Unknown")))
                        if plugin_vulns > 0:
                            self._log("    Plugins: {} vulnerabilities".format(plugin_vulns))
                            for p in result.get("plugins", []):
                                if p.get("success") and p.get("vulnerabilities"):
                                    self._log("      - {}: {} vulns".format(p["slug"], len(p["vulnerabilities"])))
                        if theme_vulns > 0:
                            self._log("    Themes: {} vulnerabilities".format(theme_vulns))
                        if result.get("users"):
                            self._log("    Users: {} enumerated".format(len(result["users"])))
                        self._log("    Total: {} vulnerabilities".format(total_vulns))
                self._log("\n" + "="*60)
            
            self._log("[*] Use 'Export Reports' to save detailed findings")
            self._log("="*60)
            JOptionPane.showMessageDialog(
                self._panel,
                "Batch scan completed!\n\n{} sites scanned.\n\nUse 'Export Reports' to save detailed findings.".format(total),
                "Scan Complete",
                JOptionPane.INFORMATION_MESSAGE
            )
        except KeyboardInterrupt:
            self._log("[!] Batch scan was interrupted by user")
            self._log("[*] Partial results may be available - check the list above")
        except RuntimeError as e:
            self._log("[!] Batch scan runtime error: {}".format(str(e)))
            self._log("[*] Partial results may be available - check the list above")
        finally:
            self.scan_running = False
    
    def _scan_worker(self, idx, url):
        """Worker thread for scanning"""
        try:
            self.scan_running = True
            self.all_sites_data[idx]["status"] = "Scanning"
            self.site_list.repaint()
            
            self._log("\n" + "="*60)
            self._log("[*] Scanning: {}".format(url))
            self._log("="*60)
            self._callbacks.printOutput("[*] Scanning: {}".format(url))
            
            # Rate limiting
            current_time = time.time()
            time_since_last = current_time - self.last_api_call
            if time_since_last < self.min_api_interval:
                wait_time = self.min_api_interval - time_since_last
                self._log("[*] Rate limiting: waiting {:.1f}s".format(wait_time))
                time.sleep(wait_time)
            
            cached_ver = self.cached_versions.get(url)
            result = WPScanAPI.scan_site(url, self.api_key, self._log, cached_ver, self._callbacks, self._helpers, self._increment_api_credits)
            self.last_api_call = time.time()
            self._increment_api_counter()
            
            # Save cache after scan completes
            self._save_api_cache()
            
            # Handle rate limiting
            if not result["success"] and "Rate limit" in result.get("error", ""):
                self.rate_limited_until = time.time() + 60
                self._log("[!] RATE LIMIT REACHED - 60 second cooldown active")
            
            if result["success"]:
                self.all_sites_data[idx]["status"] = "Scanned"
                self.wp_sites[url]["scan_result"] = result
                self.wp_sites[url]["status"] = "Scanned"
                
                vuln_count = len(result.get("vulnerabilities", []))
                for p in result.get("plugins", []):
                    vuln_count += len(p.get("vulnerabilities", []))
                for t in result.get("themes", []):
                    vuln_count += len(t.get("vulnerabilities", []))
                self._log("[+] Scan complete: {} total vulnerabilities".format(vuln_count))
                self._log("[*] Use 'Export Reports' to save detailed results")
                self._callbacks.printOutput("[+] Scan complete: {} ({} vulnerabilities)".format(url, vuln_count))
            else:
                self.all_sites_data[idx]["status"] = "Error"
                error_msg = result.get("error", "Unknown error")
                self._log("[!] Scan failed: {}".format(error_msg))
                self._callbacks.printError("[!] Scan failed for {}: {}".format(url, error_msg))
            
            self.site_list.repaint()
        except KeyboardInterrupt:
            self._log("[!] Scan interrupted by user")
            self.all_sites_data[idx]["status"] = "Error"
            self.site_list.repaint()
        except RuntimeError as e:
            self._log("[!] Scan runtime error: {}".format(str(e)))
            self.all_sites_data[idx]["status"] = "Error"
            self.site_list.repaint()
        finally:
            self.scan_running = False
    

    def export_reports(self):
        import os
        self._callbacks.printOutput("[DEBUG] Export: wp_sites has {} entries".format(len(self.wp_sites)))
        for url, data in self.wp_sites.items():
            self._callbacks.printOutput("[DEBUG] Site {}: has scan_result = {}".format(url, data.get("scan_result") is not None))
        
        scanned = [(url, data) for url, data in self.wp_sites.items() if data.get("scan_result")]
        
        if not scanned:
            self._log("[!] No scan results available to export. Please scan sites first.")
            JOptionPane.showMessageDialog(
                self._panel,
                "No scan results available to export.\n\nPlease:\n1. Select a WordPress site from the list\n2. Double-click or use 'Scan Selected' to scan it\n3. Try exporting again after scan completes",
                "No Results to Export",
                JOptionPane.INFORMATION_MESSAGE
            )
            return
        
        timestamp = SimpleDateFormat("yyyyMMdd_HHmmss").format(Date())
        base_dir = self._get_export_dir("scan_{}".format(timestamp))
        
        if not base_dir:
            self._log("[!] Cannot create export directory")
            return
        
        for url, data in scanned:
            scan_result = data["scan_result"]
            site_dir = os.path.join(base_dir, self._sanitize_filename(url))
            File(site_dir).mkdirs()
            
            self._write_file(os.path.join(site_dir, "raw_wpscan.json"), ReportGenerator.generate_json(scan_result))
            self._write_file(os.path.join(site_dir, "report.md"), ReportGenerator.generate_markdown(scan_result))
            self._write_file(os.path.join(site_dir, "ai_prompt.txt"), ReportGenerator.generate_ai_prompt(scan_result))
        
        self._log("[+] Successfully exported {} site(s) to: {}".format(len(scanned), base_dir))
        self._log("[*] Each site has: raw_wpscan.json, report.md, and ai_prompt.txt")
        self._callbacks.printOutput("[+] Exported to: {}".format(base_dir))
        JOptionPane.showMessageDialog(
            self._panel,
            "Export successful!\n\n{} site(s) exported to:\n{}\n\nEach site includes:\n- raw_wpscan.json (API data)\n- report.md (formatted report)\n- ai_prompt.txt (AI analysis ready)".format(len(scanned), base_dir),
            "Export Complete",
            JOptionPane.INFORMATION_MESSAGE
        )
    
    def _try_windows_drives(self, subdir):
        import os
        for drive in ['C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']:
            base = "{}:\\burpwpscan_exports".format(drive)
            path = os.path.join(base, subdir) if subdir else base
            f = File(path)
            if f.mkdirs() or f.exists():
                return path
        return None
    
    def _get_export_dir(self, subdir=""):
        import os
        
        # Try Windows drives
        path = self._try_windows_drives(subdir)
        if path:
            return path
        
        # Not Windows, try /tmp
        base = "/tmp/burpwpscan_exports"
        path = os.path.join(base, subdir) if subdir else base
        f = File(path)
        if f.mkdirs() or f.exists():
            return path
        
        self._callbacks.printError("[!] Failed to create export directory")
        return None
    
    def _sanitize_filename(self, url):
        # Remove protocol and special chars, prevent path traversal
        sanitized = re.sub(r'^https?://', '', url)
        sanitized = re.sub(r'[\\/]', '_', sanitized)
        sanitized = re.sub(r'[^\w\-_]', '_', sanitized)
        sanitized = sanitized.replace('..', '_').replace('~', '_')
        if len(sanitized) > 200:
            sanitized = sanitized[:200]
        return sanitized if sanitized else 'unknown_site'
    
    def _write_file(self, filepath, content):
        writer = None
        try:
            f = File(filepath)
            canonical = f.getCanonicalPath()
            export_base = File(self._get_export_dir()).getCanonicalPath()
            if not canonical.startswith(export_base):
                self._callbacks.printError("[!] Path traversal attempt blocked: {}".format(filepath))
                return False
            writer = FileWriter(filepath)
            writer.write(content)
            return True
        except IOError as e:
            self._callbacks.printError("[!] Write file IO error: {}".format(str(e)))
            return False
        except RuntimeError as e:
            self._callbacks.printError("[!] Write file runtime error: {}".format(str(e)))
            return False
        finally:
            if writer:
                try:
                    writer.close()
                except IOError as e:
                    self._callbacks.printError("[!] Failed to close writer: {}".format(str(e)))
    
    def _load_status(self):
        status_file = self._get_status_file()
        if not status_file:
            self._callbacks.printError("[!] Cannot load status: status file unavailable")
            return {}
        content = self._read_file(status_file)
        if content:
            try:
                return json.loads(content)
            except ValueError as e:
                self._callbacks.printError("[!] Failed to parse status file (invalid JSON): {}".format(str(e)))
            except TypeError as e:
                self._callbacks.printError("[!] Failed to parse status file (type error): {}".format(str(e)))
        return {}
    
    
    def _save_status(self):
        import os
        export_dir = self._get_export_dir()
        if not export_dir:
            return
        status_file = os.path.join(export_dir, "wpsscan_status.json")
        self._write_file(status_file, json.dumps(self.site_status, indent=2))
        self._save_api_cache()
    
    def _get_status_file(self):
        import os
        export_dir = self._get_export_dir()
        if export_dir:
            return os.path.join(export_dir, "wpsscan_status.json")
        return None
    
    def _read_file(self, filepath):
        if not filepath:
            return None
        reader = None
        try:
            f = File(filepath)
            if not f.exists():
                return None
            canonical = f.getCanonicalPath()
            export_base = File(self._get_export_dir()).getCanonicalPath()
            if not canonical.startswith(export_base):
                self._callbacks.printError("[!] Path traversal attempt blocked: {}".format(filepath))
                return None
            reader = BufferedReader(FileReader(f))
            content = []
            line = reader.readLine()
            while line:
                content.append(line)
                line = reader.readLine()
            return ''.join(content)
        except IOError as e:
            self._callbacks.printError("[!] Read file IO error: {}".format(str(e)))
            return None
        except RuntimeError as e:
            self._callbacks.printError("[!] Read file runtime error: {}".format(str(e)))
            return None
        finally:
            if reader:
                try:
                    reader.close()
                except IOError as e:
                    self._callbacks.printError("[!] Failed to close reader: {}".format(str(e)))
    
    def _load_api_cache(self):
        import os
        export_dir = self._get_export_dir()
        if not export_dir:
            self._callbacks.printError("[!] Cannot load API cache: export directory unavailable")
            return
        cache_file = os.path.join(export_dir, "wpsscan_api_cache.json")
        content = self._read_file(cache_file)
        if content:
            try:
                with WPScanAPI._cache_lock:
                    WPScanAPI._api_cache = json.loads(content)
                    valid_count = sum(1 for v in WPScanAPI._api_cache.values() if WPScanAPI._is_cache_valid(v))
                    self._callbacks.printOutput("[+] Loaded {} cached API responses ({} valid)".format(len(WPScanAPI._api_cache), valid_count))
            except (ValueError, TypeError) as e:
                self._callbacks.printError("[!] Failed to load API cache (parse error): {}".format(str(e)))
    
    def _save_api_cache(self):
        import os
        export_dir = self._get_export_dir()
        if not export_dir:
            self._callbacks.printError("[!] Cannot save API cache: export directory unavailable")
            return
        cache_file = os.path.join(export_dir, "wpsscan_api_cache.json")
        with WPScanAPI._cache_lock:
            self._write_file(cache_file, json.dumps(WPScanAPI._api_cache, indent=2))
    
    def _on_selection_change(self):
        idx = self.site_list.getSelectedIndex()
        if idx >= 0:
            url = self.all_sites_data[idx]["url"]
            status = self.site_status.get(url, {})
            self.scanned_cb.setSelected(status.get("scanned", False))
            self.vulnerable_cb.setSelected(status.get("vulnerable", False))
            self.fp_cb.setSelected(status.get("fp", False))
    
    def _update_status(self):
        idx = self.site_list.getSelectedIndex()
        if idx >= 0:
            url = self.all_sites_data[idx]["url"]
            self.site_status[url] = {
                "scanned": self.scanned_cb.isSelected(),
                "vulnerable": self.vulnerable_cb.isSelected(),
                "fp": self.fp_cb.isSelected()
            }
            self._save_status()
    
    def _clear_status(self):
        idx = self.site_list.getSelectedIndex()
        if idx >= 0:
            url = self.all_sites_data[idx]["url"]
            if url in self.site_status:
                del self.site_status[url]
            self._save_status()
            self.scanned_cb.setSelected(False)
            self.vulnerable_cb.setSelected(False)
            self.fp_cb.setSelected(False)
    
    def _apply_filters(self):
        search_text = self.search_field.getText().lower()
        filtered = [d for d in self.all_sites_data if search_text in d["key"].lower()]
        
        sort_by = self.sort_combo.getSelectedItem()
        if sort_by == "Host":
            filtered.sort(key=lambda x: x["host"])
        elif sort_by == "Status":
            filtered.sort(key=lambda x: x["status"])
        elif sort_by == "Detection Time":
            filtered.sort(key=lambda x: x["time"])
        
        self.list_model.clear()
        for d in filtered:
            self.list_model.addElement(d["key"])
        
        self._callbacks.setExtensionName("WpsScan ({})".format(len(filtered)))
    
    def _refresh_list(self):
        self._apply_filters()
        self.site_list.repaint()
    
    def _toggle_live_scan(self):
        self.live_scan_enabled = not self.live_scan_enabled
        if self.live_scan_enabled:
            self.live_scan_btn.setText(u"\u25B6 Live Scan: ON")
            self.live_scan_btn.setBackground(Color(46, 125, 50))
            self._callbacks.printOutput("[+] Live WordPress detection enabled")
        else:
            self.live_scan_btn.setText(u"\u23F8 Live Scan: OFF")
            self.live_scan_btn.setBackground(Color(183, 28, 28))
            self._callbacks.printOutput("[-] Live WordPress detection disabled")
    
    def _scan_http_history(self):
        _init_patterns()
        self._callbacks.printOutput("[*] Scanning HTTP history for WordPress sites...")
        found_sites = set()
        
        proxy_history = self._callbacks.getProxyHistory()
        if not proxy_history:
            self._log(
                "[!] No HTTP history available. "
                "Browse sites through Burp Proxy first."
            )
            JOptionPane.showMessageDialog(
                self._panel,
                "No HTTP history found in Burp.\n\n"
                "To use this feature:\n"
                "1. Browse target websites through Burp Proxy\n"
                "2. Return here and click 'Scan HTTP History' again",
                "No History Available",
                JOptionPane.INFORMATION_MESSAGE
            )
            return
        
        for item in proxy_history:
            try:
                request_info = self._helpers.analyzeRequest(item)
                req_url = str(request_info.getUrl())
                
                # Check request URL for WordPress indicators
                wp_detected = self._extract_wp_base(req_url) is not None
                
                # If not found in URL, check response
                if not wp_detected:
                    response = item.getResponse()
                    if response:
                        response_str = self._helpers.bytesToString(response)
                        response_info = self._helpers.analyzeResponse(response)
                        
                        wp_detected = any(pattern.search(response_str) for pattern in PatternCache.WP_PATTERNS)
                        
                        if not wp_detected:
                            try:
                                headers = response_info.getHeaders()
                                for header in headers:
                                    header_str = str(header).lower()
                                    if 'wordpress' in header_str:
                                        wp_detected = True
                                        break
                            except AttributeError as e:
                                self._callbacks.printError("[!] History header attribute error: {}".format(str(e)))
                            except TypeError as e:
                                self._callbacks.printError("[!] History header type error: {}".format(str(e)))
                
                if wp_detected:
                    service = item.getHttpService()
                    protocol = service.getProtocol()
                    host = service.getHost()
                    port = service.getPort()
                    
                    if ((protocol == "https" and port == 443) or
                            (protocol == "http" and port == 80)):
                        url = "{}://{}".format(protocol, host)
                    else:
                        url = "{}://{}:{}".format(protocol, host, port)
                    
                    wp_base = self._extract_wp_base(req_url)
                    if wp_base:
                        url = wp_base
                    
                    normalized = self._normalize_url(url)
                    
                    # Cache version if found
                    for pattern in PatternCache.VERSION_PATTERNS:
                        version_match = pattern.search(response_str)
                        if version_match:
                            self.cached_versions[normalized] = version_match.group(1)
                            break
                    
                    if normalized not in found_sites:
                        found_sites.add(normalized)
                        self._add_wp_site(url, host, from_history=True)
            except AttributeError as e:
                self._callbacks.printError("[!] History scan attribute error: {}".format(str(e)))
            except TypeError as e:
                self._callbacks.printError("[!] History scan type error: {}".format(str(e)))
            except RuntimeError as e:
                self._callbacks.printError("[!] History scan runtime error: {}".format(str(e)))
        
        if len(found_sites) > 0:
            self._log(
                "[+] Found {} WordPress site(s) in HTTP history".format(
                    len(found_sites)
                )
            )
            self._log("[*] Sites marked with [HTTP HISTORY] label in blue")
            self._callbacks.printOutput(
                "[+] Found {} WordPress sites in HTTP history".format(
                    len(found_sites)
                )
            )
            JOptionPane.showMessageDialog(
                self._panel,
                "HTTP history scan complete!\n\n"
                "Found {} WordPress site(s).\n\n"
                "They are now listed above with [HTTP HISTORY] labels.".format(
                    len(found_sites)
                ),
                "Scan Complete",
                JOptionPane.INFORMATION_MESSAGE
            )
        else:
            self._log("[*] No WordPress sites found in HTTP history")
            self._log("[*] Try browsing WordPress sites through Burp Proxy first")
            JOptionPane.showMessageDialog(
                self._panel,
                "No WordPress sites found in HTTP history.\n\n"
                "This could mean:\n"
                "- No WordPress sites in browsing history\n"
                "- Sites haven't been proxied through Burp yet\n\n"
                "Try browsing target sites through Burp Proxy.",
                "No Sites Found",
                JOptionPane.INFORMATION_MESSAGE
            )
    
    def _log(self, message):
        """Add message to log area"""
        def update_ui():
            self.log_area.append(message + "\n")
            self.log_area.setCaretPosition(self.log_area.getDocument().getLength())
        SwingUtilities.invokeLater(update_ui)
    
    def _clear_list(self):
        confirm = JOptionPane.showConfirmDialog(
            self._panel,
            "Clear all detected sites?",
            "Confirm",
            JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            self.wp_sites.clear()
            self.all_sites_data = []
            self.list_model.clear()
            self._callbacks.setExtensionName("WpsScan")
    
    def _get_today_date(self):
        return SimpleDateFormat("yyyy-MM-dd").format(Date())
    
    def _load_api_count(self):
        import os
        export_dir = self._get_export_dir()
        if not export_dir:
            self._callbacks.printError("[!] Cannot load API count: export directory unavailable")
            return 0
        count_file = os.path.join(export_dir, "wpsscan_api_count.json")
        content = self._read_file(count_file)
        if content:
            try:
                data = json.loads(content)
                if data.get("date") == self._get_today_date():
                    count = data.get("count", 0)
                    self._callbacks.printOutput("[+] Loaded websites scanned: {} today".format(count))
                    return count
            except (ValueError, TypeError) as e:
                self._callbacks.printError("[!] Failed to parse API count file: {}".format(str(e)))
        return 0
    
    def _load_api_credits(self):
        import os
        export_dir = self._get_export_dir()
        if not export_dir:
            self._callbacks.printError("[!] Cannot load API credits: export directory unavailable")
            return 0
        credits_file = os.path.join(export_dir, "wpsscan_api_credits.json")
        content = self._read_file(credits_file)
        if content:
            try:
                data = json.loads(content)
                if data.get("date") == self._get_today_date():
                    credits = data.get("credits", 0)
                    self._callbacks.printOutput("[+] Loaded API credits: {} used today".format(credits))
                    return credits
            except (ValueError, TypeError) as e:
                self._callbacks.printError("[!] Failed to parse API credits file: {}".format(str(e)))
        return 0
    
    def _save_api_count(self):
        import os
        export_dir = self._get_export_dir()
        if not export_dir:
            self._callbacks.printError("[!] Cannot save API count: export directory unavailable")
            return
        count_file = os.path.join(export_dir, "wpsscan_api_count.json")
        data = {"date": self.api_count_date, "count": self.api_call_count}
        if not self._write_file(count_file, json.dumps(data)):
            self._callbacks.printError("[!] Failed to save API count to file")
    
    def _save_api_credits(self):
        import os
        export_dir = self._get_export_dir()
        if not export_dir:
            self._callbacks.printError("[!] Cannot save API credits: export directory unavailable")
            return
        credits_file = os.path.join(export_dir, "wpsscan_api_credits.json")
        data = {"date": self.api_credits_date, "credits": self.api_credits_used}
        if not self._write_file(credits_file, json.dumps(data)):
            self._callbacks.printError("[!] Failed to save API credits to file")
    
    def _increment_api_counter(self):
        today = self._get_today_date()
        if today != self.api_count_date:
            self.api_count_date = today
            self.api_call_count = 0
        self.api_call_count += 1
        self._save_api_count()
        self._update_api_counter_display()
    
    def _increment_api_credits(self):
        today = self._get_today_date()
        if today != self.api_credits_date:
            self.api_credits_date = today
            self.api_credits_used = 0
        self.api_credits_used += 1
        self._save_api_credits()
        self._update_api_credits_display()
    
    def _update_api_counter_display(self):
        def update():
            self.api_counter_label.setText(" Websites Scanned: {} ".format(self.api_call_count))
            self.api_counter_label.setForeground(Color(0, 100, 200))
        SwingUtilities.invokeLater(update)
    
    def _update_api_credits_display(self):
        def update():
            self.api_credits_label.setText(" API Credits: {} ".format(self.api_credits_used))
            if self.api_credits_used >= 25:
                self.api_credits_label.setForeground(Color.RED)
            elif self.api_credits_used >= 20:
                self.api_credits_label.setForeground(Color.ORANGE)
            else:
                self.api_credits_label.setForeground(Color(0, 128, 0))
        SwingUtilities.invokeLater(update)
    
    def _reset_api_counter(self):
        confirm = JOptionPane.showConfirmDialog(
            self._panel,
            "Reset both counters to 0?\n\nThis will reset:\n- Websites Scanned\n- API Credits\n\nNote: This won't affect your actual API usage.",
            "Reset Counters",
            JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            self.api_call_count = 0
            self.api_credits_used = 0
            self._save_api_count()
            self._save_api_credits()
            self._update_api_counter_display()
            self._update_api_credits_display()
            self._log("[*] Counters reset to 0")
    
    def _show_import_dialog(self):
        from javax.swing import JDialog, JTextArea, JButton, JPanel, JScrollPane
        from java.awt import BorderLayout, Dimension
        
        dialog = JDialog()
        dialog.setTitle("Import URLs")
        dialog.setSize(Dimension(600, 400))
        dialog.setLocationRelativeTo(self._panel)
        dialog.setModal(True)
        
        text_area = JTextArea()
        text_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        text_area.setLineWrap(True)
        text_area.setWrapStyleWord(False)
        scroll = JScrollPane(text_area)
        scroll.setBorder(BorderFactory.createTitledBorder("Paste URLs (one per line)"))
        
        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        import_btn = JButton("Import")
        cancel_btn = JButton("Cancel")
        
        def do_import(e):
            dialog.dispose()
            urls = text_area.getText().strip().split('\n')
            thread = Thread(target=self._import_urls_worker, args=(urls,))
            thread.daemon = True
            thread.start()
        
        import_btn.addActionListener(do_import)
        cancel_btn.addActionListener(lambda e: dialog.dispose())
        btn_panel.add(import_btn)
        btn_panel.add(cancel_btn)
        
        dialog.add(scroll, BorderLayout.CENTER)
        dialog.add(btn_panel, BorderLayout.SOUTH)
        dialog.setVisible(True)
    
    def _import_urls_worker(self, urls):
        _init_patterns()
        imported = 0
        checked = 0
        self._log("[*] Verifying WordPress sites...")
        
        for url in urls:
            url = url.strip()
            if not url or not (url.startswith('http://') or url.startswith('https://')):
                continue
            
            checked += 1
            self._log("[*] Checking {}".format(url))
            
            if self._verify_wordpress(url):
                try:
                    from urlparse import urlparse
                except ImportError:
                    from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.hostname if hasattr(parsed, 'hostname') else parsed.netloc.split(':')[0]
                self._add_wp_site(url, host, from_history=False, from_import=True)
                imported += 1
                self._log("[+] WordPress confirmed: {}".format(url))
            else:
                self._log("[-] Not WordPress: {}".format(url))
        
        self._log("[+] Import complete: {}/{} sites are WordPress".format(imported, checked))
    
    def _verify_wordpress(self, url):
        response = None
        try:
            req = urllib2.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            response = urllib2.urlopen(req, timeout=10)
            content = str(response.read(524288))
            return any(pattern.search(content) for pattern in PatternCache.WP_PATTERNS)
        except urllib2.HTTPError:
            return False
        except urllib2.URLError:
            return False
        except IOError:
            return False
        finally:
            if response:
                try:
                    response.close()
                except IOError as e:
                    self._callbacks.printError("[!] Failed to close response: {}".format(str(e)))
