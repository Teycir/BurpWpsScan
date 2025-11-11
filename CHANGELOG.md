# Changelog

All notable changes to BurpWpsScan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- OpenRouter AI integration for automated vulnerability analysis
- Automated PoC script generation
- HTML report export format
- Continuous monitoring mode with notifications
- Settings dialog for configuration
- Integration with Burp Scanner findings

---

## [1.3.1] - 2024-01-17

### Fixed
- **Scan Order**: "Scan All" now respects current list display order including search/filter/sort results
- **Thread Safety**: Added proper locking for API cache operations to prevent race conditions
- **Exception Handling**: Replaced bare `pass` statements with proper error logging
- **Plugin Matching**: Improved plugin name normalization to handle variations
- **API Counter**: Fixed logic error in `_load_api_count()` that always returned 0

### Enhanced
- **Error Visibility**: All exceptions now logged with context for better debugging
- **Code Quality**: Standardized exception handling patterns across codebase
- **Resource Management**: Ensured all HTTP responses properly closed in finally blocks

### Technical
- Added `Lock()` for thread-safe cache operations
- Improved `_prioritize_plugins()` with better normalization function
- Fixed `_load_api_count()` return value handling
- Enhanced error logging in file operations and cache management
- "Scan All" now iterates through `list_model` instead of `wp_sites.keys()`

---

## [1.3.0] - 2024-01-16

### Added
- **XML-RPC Security Testing**: Automatic detection of XML-RPC endpoint vulnerabilities
  - Tests `/xmlrpc.php` for enabled status
  - Detects `pingback.ping` method (DDoS amplification risk)
  - Detects `system.multicall` method (brute force amplification risk)
  - Zero WPScan API credits used
- **REST API Endpoint Discovery**: Comprehensive WordPress REST API testing
  - Enumerates `/wp-json/wp/v2/` endpoints (users, posts, pages, media)
  - Flags user enumeration vulnerabilities
  - Identifies publicly accessible content endpoints
  - Zero WPScan API credits used
- **Plugin Update Monitoring**: Proactive security through version tracking
  - Queries WordPress.org API for latest plugin versions
  - Checks up to 10 plugins to avoid rate limits
  - Identifies outdated plugins that may need updates
  - Zero WPScan API credits used
- **Burp Intruder Payload Generation**: Automatic exploit configuration
  - Generates XSS payloads: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
  - Generates SQL injection payloads: `' OR '1'='1`, `1' UNION SELECT NULL--`
  - Generates file upload payloads: `shell.php`, `test.php5`, `file.phtml`
  - Provides CSRF testing guidance
  - Plugin-specific payload targeting
  - All configs included in report exports

### Enhanced
- **Scan Output**: Real-time display of security findings during scans
  - XML-RPC status and risks shown immediately
  - REST API endpoints displayed as discovered
  - Plugin update information shown during scan
  - Intruder configuration count displayed
- **Report Exports**: All formats now include new security findings
  - JSON exports include `xmlrpc`, `rest_api`, `plugin_updates`, `intruder_configs` fields
  - Markdown reports include dedicated "Security Findings" section
  - Markdown reports include "Burp Intruder Configurations" section with payloads
  - AI prompts updated to include new security context
- **Security Coverage**: Comprehensive attack surface assessment beyond vulnerability scanning
  - Tests for common WordPress misconfigurations
  - Identifies information disclosure vectors
  - Provides actionable exploitation guidance

### Technical
- Added `test_xmlrpc()` method to WPScanAPI class
- Added `discover_rest_endpoints()` method to WPScanAPI class
- Added `check_plugin_updates()` method to WPScanAPI class
- Added `generate_intruder_config()` method to WPScanAPI class
- Integrated security tests into `scan_site()` workflow
- Updated ReportGenerator to include new findings in all formats
- Enhanced scan summary logging with security findings

---

## [1.2.1] - 2025-11-15

### Enhanced
- **Real-Time Vulnerability Details**: Vulnerability title and type now displayed immediately as each component is scanned
- **Improved Transparency**: Core, plugin, and theme vulnerabilities show detailed information in real-time
- **Better User Experience**: No need to wait for final summary to see which vulnerabilities were found

---

## [1.2.0] - 2025-11-14

### Added
- **Bulk URL Import**: Paste multiple URLs directly into UI for batch WordPress detection
- **API Credit Counter**: Real-time tracking of daily API usage with color indicators
  - Green: 0-19 calls (safe)
  - Orange: 20-24 calls (warning)
  - Red: 25+ calls (limit reached)
  - Auto-resets at midnight
  - Persistent across Burp restarts

---

## [1.1.0] - 2025-11-13

### Added
- **HTTP History Scanning**: Scan Burp's HTTP history to find WordPress sites from past traffic
- **Visual Labels**: Sites from HTTP history marked with [HTTP HISTORY] label in blue
- **URL Normalization**: Automatically normalizes subdomains to root domains
- **Smart Plugin Prioritization**: 80+ high-risk plugins scanned first
- **24-Hour API Cache**: Plugin/theme results cached for 24 hours
- **Comprehensive High-Risk Scanning**: Scans ALL high-risk plugins found

### Enhanced
- API credit optimization (60-90% reduction)
- Cache persistence across Burp restarts
- Dual detection modes (live + history)

---

## [1.0.0] - 2025-11-10 

### Added
- Initial release of BurpWpsScan extension
- Passive WordPress detection using regex patterns
- HTTP traffic monitoring for WordPress signatures
- WPScan API integration for vulnerability scanning
- Manual scan trigger via right-click context menu
- Scan Selected and Scan All functionality
- Status tracking with persistent storage (Scanned, Vulnerable, False Positive)
- Export functionality with timestamped directories
- JSON export format with complete scan data
- Markdown report generation for human readability
- AI-ready prompt generation for post-processing
- Search and filter capabilities for detected sites
- Sort by URL, Host, Status, or Detection Time
- Color-coded status indicators in UI
- Alternating row colors for better readability
- Double-click to copy URL to clipboard
- Tab caption with site count
- Rate limiting for API requests (free tier friendly)
- Error handling for network and API failures
- `.env` file support for API key management
- Automatic export directory creation
- Statistics generation for scan summaries
- README.txt generation in export folders

### UI Features
- Clean tabbed interface in Burp Suite
- Action button grid (Scan Selected, Scan All, Export, etc.)
- WordPress sites list with custom renderer
- Status checkboxes for tagging sites
- Search field with real-time filtering
- Sort dropdown with multiple options
- Right-click context menu

### Detection Patterns
- `/wp-content/` directory detection
- `/wp-includes/` directory detection
- `/wp-admin/` directory detection
- `/wp-json/` API endpoint detection
- `xmlrpc.php` file detection
- `wp-login.php` file detection
- WordPress generator meta tag detection
- `wp-emoji-release.min.js` script detection
- WordPress themes directory detection
- WordPress plugins directory detection

### Export Formats
- **JSON**: Machine-readable with complete metadata
- **Markdown**: Human-readable formatted report
- **AI Prompt**: Structured prompt for AI analysis
- **Stats**: Summary statistics in JSON format
- **README**: Quick overview of scan results

### Security Features
- API keys stored in `.env` file (gitignored)
- No sensitive data logged
- Rate limiting to respect API quotas
- Error messages without exposing credentials

---

## [0.9.0]

### Added
- Beta release for internal testing
- Basic WordPress detection
- WPScan API proof of concept
- Simple UI with list view
- Manual scan functionality

### Known Issues
- No persistent storage
- Limited error handling
- No export functionality

---

## [0.5.0] 

### Added
- Alpha release for proof of concept
- Passive HTTP traffic monitoring
- Basic regex pattern matching
- Console output for detected sites

### Known Issues
- No UI
- No WPScan integration
- Manual testing only


---

## Upgrade Guide

### From 1.2.x to 1.3.0
1. Unload old extension in Burp Suite
2. Replace `WpsScan.py` with new version
3. Reload extension
4. Existing scan results will automatically include new security tests on next scan
5. Re-export reports to include new security findings

### From 1.1.x to 1.2.x
1. Unload old extension
2. Replace `WpsScan.py`
3. Reload extension
4. API counter starts fresh (expected behavior)

### From 1.0.x to 1.1.x
1. Unload old extension
2. Replace `WpsScan.py`
3. Reload extension
4. Cache file will be created automatically

### From 0.9.0 to 1.0.0
1. Unload old extension in Burp Suite
2. Replace `WpsScan.py` with new version
3. Create `.env` file with API keys
4. Reload extension
5. Previous detections will not be migrated (fresh start)

### From 0.5.0 to 1.0.0
- Complete rewrite, no migration path
- Follow fresh installation instructions

---

## Breaking Changes

### 1.3.0
- None (backward compatible)

### 1.2.1
- None (backward compatible)

### 1.2.0
- None (backward compatible)

### 1.1.0
- None (backward compatible)

### 1.0.0
- None (initial stable release)

---

## Deprecations

### 1.0.0
- None

---

## Bug Fixes

### 1.3.0
- None

### 1.2.1
- None

### 1.2.0
- None

### 1.1.0
- Fixed: Cache not persisting across Burp restarts
- Fixed: HTTP history duplicate detection

### 1.0.0
- Fixed: Duplicate site detection
- Fixed: Memory leak in HTTP listener
- Fixed: Export directory creation on Windows
- Fixed: API key loading from .env file
- Fixed: Status persistence across Burp restarts
- Fixed: UI freezing during long scans
- Fixed: Regex pattern false positives

---

## Performance Improvements

### 1.3.0
- Security tests run in parallel with minimal overhead
- Plugin update checks limited to 10 plugins to avoid rate limits
- Intruder config generation uses efficient pattern matching

### 1.2.1
- Real-time logging reduces perceived scan time

### 1.2.0
- API counter uses minimal disk I/O

### 1.1.0
- 60-90% API credit reduction through smart caching
- Faster scans with cached plugin/theme results

### 1.0.0
- Optimized regex pattern matching
- Reduced memory footprint for large site lists
- Improved UI responsiveness during scans
- Faster export generation for multiple sites

---

## Documentation

### 1.0.0
- Added comprehensive README.md
- Added detailed PLAN.md
- Added this CHANGELOG.md
- Added inline code comments
- Added API documentation

---

## Contributors

### 1.0.0
- **Your Name** - Initial development and release

---

## Acknowledgments

- WPScan Team for the vulnerability database API
- PortSwigger for Burp Suite extensibility framework
- CopyIssues extension for UI/UX inspiration
- Community testers and feedback providers

---

[Unreleased]: https://github.com/yourusername/BurpWpsScan/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/yourusername/BurpWpsScan/releases/tag/v1.3.0
[1.2.1]: https://github.com/yourusername/BurpWpsScan/releases/tag/v1.2.1
[1.2.0]: https://github.com/yourusername/BurpWpsScan/releases/tag/v1.2.0
[1.1.0]: https://github.com/yourusername/BurpWpsScan/releases/tag/v1.1.0
[1.0.0]: https://github.com/yourusername/BurpWpsScan/releases/tag/v1.0.0
[0.9.0]: https://github.com/yourusername/BurpWpsScan/releases/tag/v0.9.0
[0.5.0]: https://github.com/yourusername/BurpWpsScan/releases/tag/v0.5.0


---

## [1.3.1] - 2025-11-17

### Security Fixes
- **Critical**: Fixed JSON parsing without proper encoding handling (prevents Unicode decode errors and injection vulnerabilities)
- **Critical**: Fixed path traversal vulnerabilities in file read/write operations with enhanced validation
- **High**: Fixed XSS vulnerability in UI list renderer with comprehensive HTML entity encoding
- **High**: Prevented API key exposure in logs by using unredirected headers
- **High**: Added memory exhaustion protection with response size limits (512KB-1MB)
- **Medium**: Enhanced filename sanitization to prevent path traversal attacks
- **Medium**: Improved error handling across all HTTP operations

### Technical
- All JSON parsing now uses UTF-8 decoding with error replacement
- Response size limits enforced on all HTTP reads
- Canonical path validation for all file operations
- Enhanced XSS prevention in UI components
- API keys no longer logged in debug output
- Improved thread safety in cache operations

---
