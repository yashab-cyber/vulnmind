# 💻 VulnMind Commands Reference

Complete command-line reference for VulnMind - AI-Powered Self-Aware DAST Scanner.

## 📋 Table of Contents

- [Basic Usage](#basic-usage)
- [Core Options](#core-options)
- [Target Configuration](#target-configuration)
- [AI & Self-Awareness](#ai--self-awareness)
- [Plugin Management](#plugin-management)
- [Report Generation](#report-generation)
- [Performance & Concurrency](#performance--concurrency)
- [Logging & Debug](#logging--debug)
- [Authentication](#authentication)
- [Network Configuration](#network-configuration)
- [Advanced Options](#advanced-options)
- [Examples](#examples)
- [Environment Variables](#environment-variables)

---

## 🚀 Basic Usage

### **Simple Scan**
```bash
python -m vulnmind --target https://example.com
```
Performs a basic vulnerability scan on the target URL with default settings.

### **Help Command**
```bash
python -m vulnmind --help
python -m vulnmind -h
```
Display help information and all available options.

### **Version Information**
```bash
python -m vulnmind --version
```
Show VulnMind version and build information.

---

## 🎯 Core Options

### **--target** (Required)
```bash
python -m vulnmind --target <URL>
python -m vulnmind -t <URL>
```
- **Description**: Primary target URL to scan
- **Format**: Full URL including protocol (http/https)
- **Example**: `--target https://example.com`
- **Required**: Yes (unless using --target-file)

### **--target-file**
```bash
python -m vulnmind --target-file urls.txt
```
- **Description**: File containing multiple URLs to scan (one per line)
- **Format**: Plain text file with URLs
- **Example**: `--target-file my_targets.txt`
- **Alternative to**: --target

### **--config**
```bash
python -m vulnmind --config config.yaml
python -m vulnmind -c config.yaml
```
- **Description**: Load configuration from YAML file
- **Format**: YAML configuration file
- **Default**: Uses built-in defaults if not specified
- **Example**: `--config custom_scan_config.yaml`

---

## 🤖 AI & Self-Awareness

### **--ai-mode**
```bash
python -m vulnmind --target https://example.com --ai-mode
```
- **Description**: Enable AI-powered vulnerability analysis
- **Dependencies**: Requires OpenAI API key
- **Benefits**: Reduces false positives, provides context-aware analysis
- **Environment**: Set `OPENAI_API_KEY` environment variable

### **--ai-model**
```bash
python -m vulnmind --target https://example.com --ai-mode --ai-model gpt-4
python -m vulnmind --target https://example.com --ai-mode --ai-model gpt-3.5-turbo
```
- **Description**: Specify AI model for analysis
- **Default**: `gpt-4`
- **Options**: 
  - `gpt-4` (recommended, higher accuracy)
  - `gpt-3.5-turbo` (faster, lower cost)
- **Requires**: --ai-mode flag

### **--self-aware**
```bash
python -m vulnmind --target https://example.com --self-aware
```
- **Description**: Enable self-awareness and adaptive scanning
- **Features**: 
  - Performance monitoring
  - Dynamic scan adjustment
  - Strategy optimization
- **Best with**: --ai-mode for maximum effectiveness

### **--ai-temperature**
```bash
python -m vulnmind --target https://example.com --ai-mode --ai-temperature 0.3
```
- **Description**: Control AI response randomness
- **Range**: 0.0 to 1.0
- **Default**: 0.3
- **Lower values**: More consistent, deterministic responses
- **Higher values**: More creative, varied responses

---

## 🔌 Plugin Management

### **--plugins**
```bash
python -m vulnmind --target https://example.com --plugins sql_injection,xss
python -m vulnmind --target https://example.com --plugins all
```
- **Description**: Specify which vulnerability plugins to use
- **Default**: All available plugins
- **Available plugins**:
  - `sql_injection` - SQL Injection detection
  - `xss` - Cross-Site Scripting detection
  - `csrf` - CSRF vulnerability detection
  - `open_redirect` - Open Redirect detection
  - `command_injection` - Command Injection detection
  - `directory_traversal` - Directory Traversal detection
  - `all` - All available plugins

### **--exclude-plugins**
```bash
python -m vulnmind --target https://example.com --exclude-plugins csrf,directory_traversal
```
- **Description**: Exclude specific plugins from scanning
- **Format**: Comma-separated list of plugin names
- **Use case**: Skip certain vulnerability types

### **--list-plugins**
```bash
python -m vulnmind --list-plugins
```
- **Description**: Display all available plugins and their descriptions
- **Output**: Plugin names, descriptions, and status

---

## 📊 Report Generation

### **--report**
```bash
python -m vulnmind --target https://example.com --report json
python -m vulnmind --target https://example.com --report html
python -m vulnmind --target https://example.com --report console
```
- **Description**: Specify output format for scan results
- **Options**:
  - `json` - Machine-readable JSON format
  - `html` - Human-readable HTML report
  - `console` - Colored terminal output (default)
- **Default**: console

### **--output-file**
```bash
python -m vulnmind --target https://example.com --report json --output-file results.json
python -m vulnmind --target https://example.com --report html --output-file report.html
python -m vulnmind -t https://example.com -r html -o report.html
```
- **Description**: Specify output file for reports
- **Short form**: `-o`
- **Format**: File path with appropriate extension
- **Auto-extension**: Adds correct extension if missing

### **--output-dir**
```bash
python -m vulnmind --target https://example.com --output-dir ./scan_results/
```
- **Description**: Directory to save all output files
- **Default**: Current directory
- **Behavior**: Creates directory if it doesn't exist

### **--report-template**
```bash
python -m vulnmind --target https://example.com --report html --report-template custom_template.html
```
- **Description**: Use custom HTML report template
- **Format**: Jinja2 template file
- **Use case**: Branded or customized reports

---

## ⚡ Performance & Concurrency

### **--max-concurrent**
```bash
python -m vulnmind --target https://example.com --max-concurrent 20
python -m vulnmind --target https://example.com --max-concurrent 5
```
- **Description**: Maximum number of concurrent requests
- **Default**: 10
- **Range**: 1-50 (recommended)
- **Impact**: Higher values = faster scans but more server load

### **--delay**
```bash
python -m vulnmind --target https://example.com --delay 0.5
python -m vulnmind --target https://example.com --delay 2.0
```
- **Description**: Delay between requests (seconds)
- **Default**: 0.1
- **Format**: Float value
- **Use case**: Respectful scanning, avoiding rate limits

### **--timeout**
```bash
python -m vulnmind --target https://example.com --timeout 10
python -m vulnmind --target https://example.com --timeout 30
```
- **Description**: Request timeout in seconds
- **Default**: 10
- **Range**: 5-60 seconds
- **Impact**: Longer timeouts for slow targets

### **--retries**
```bash
python -m vulnmind --target https://example.com --retries 3
python -m vulnmind --target https://example.com --retries 0
```
- **Description**: Number of retry attempts for failed requests
- **Default**: 2
- **Range**: 0-5
- **Use case**: Handling unreliable networks

---

## 📝 Logging & Debug

### **--log-level**
```bash
python -m vulnmind --target https://example.com --log-level DEBUG
python -m vulnmind --target https://example.com --log-level INFO
python -m vulnmind --target https://example.com --log-level WARNING
python -m vulnmind --target https://example.com --log-level ERROR
```
- **Description**: Set logging verbosity level
- **Options**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Default**: INFO
- **DEBUG**: Detailed execution information
- **INFO**: General operational messages
- **WARNING**: Potential issues
- **ERROR**: Error conditions only

### **--log-file**
```bash
python -m vulnmind --target https://example.com --log-file vulnmind.log
```
- **Description**: Save logs to file
- **Format**: Any text file path
- **Behavior**: Appends to existing file

### **--verbose**
```bash
python -m vulnmind --target https://example.com --verbose
python -m vulnmind --target https://example.com -v
```
- **Description**: Enable verbose output
- **Short form**: `-v`
- **Equivalent**: --log-level DEBUG

### **--quiet**
```bash
python -m vulnmind --target https://example.com --quiet
python -m vulnmind --target https://example.com -q
```
- **Description**: Minimal output (errors only)
- **Short form**: `-q`
- **Equivalent**: --log-level ERROR

---

## 🔐 Authentication

### **--auth-type**
```bash
python -m vulnmind --target https://example.com --auth-type basic --auth-creds user:password
python -m vulnmind --target https://example.com --auth-type bearer --auth-creds "token123"
```
- **Description**: Authentication method
- **Options**:
  - `basic` - HTTP Basic Authentication
  - `bearer` - Bearer Token Authentication
  - `oauth` - OAuth 2.0 Authentication
  - `cookie` - Cookie-based Authentication

### **--auth-creds**
```bash
# Basic Auth
python -m vulnmind --target https://example.com --auth-type basic --auth-creds "username:password"

# Bearer Token
python -m vulnmind --target https://example.com --auth-type bearer --auth-creds "your-token-here"

# Cookie
python -m vulnmind --target https://example.com --auth-type cookie --auth-creds "session=abc123; token=xyz789"
```
- **Description**: Authentication credentials
- **Format**: Depends on auth-type
- **Security**: Use environment variables for sensitive data

---

## 🌐 Network Configuration

### **--user-agent**
```bash
python -m vulnmind --target https://example.com --user-agent "VulnMind/1.0"
python -m vulnmind --target https://example.com --user-agent "Mozilla/5.0 (Custom Scanner)"
```
- **Description**: Custom User-Agent string
- **Default**: "VulnMind/1.0.0 (https://github.com/yashab-cyber/vulnmind)"
- **Use case**: Stealth scanning, mimicking browsers

### **--headers**
```bash
python -m vulnmind --target https://example.com --headers "X-API-Key:secret123,Accept:application/json"
```
- **Description**: Additional HTTP headers
- **Format**: Comma-separated key:value pairs
- **Example**: "Header1:value1,Header2:value2"

### **--proxy**
```bash
python -m vulnmind --target https://example.com --proxy http://proxy.example.com:8080
python -m vulnmind --target https://example.com --proxy socks5://127.0.0.1:1080
```
- **Description**: HTTP/SOCKS proxy server
- **Formats**: 
  - `http://host:port`
  - `https://host:port`
  - `socks5://host:port`
- **Authentication**: `http://user:pass@host:port`

### **--ignore-ssl**
```bash
python -m vulnmind --target https://example.com --ignore-ssl
```
- **Description**: Ignore SSL certificate errors
- **Use case**: Testing with self-signed certificates
- **Security**: Only use with trusted targets

### **--follow-redirects**
```bash
python -m vulnmind --target https://example.com --follow-redirects
python -m vulnmind --target https://example.com --max-redirects 5
```
- **Description**: Follow HTTP redirects
- **Default**: Enabled
- **Max redirects**: Configurable limit

---

## 🔧 Advanced Options

### **--scan-depth**
```bash
python -m vulnmind --target https://example.com --scan-depth 3
python -m vulnmind --target https://example.com --scan-depth 1
```
- **Description**: Depth of recursive scanning
- **Default**: 2
- **Range**: 1-5
- **1**: Target URL only
- **2**: Target + direct links
- **3+**: Deeper recursion

### **--scope**
```bash
python -m vulnmind --target https://example.com --scope subdomain
python -m vulnmind --target https://example.com --scope domain
python -m vulnmind --target https://example.com --scope path
```
- **Description**: Scan scope limitation
- **Options**:
  - `url` - Exact URL only
  - `path` - Same path and below
  - `domain` - Same domain only
  - `subdomain` - Same subdomain only
  - `all` - No restrictions

### **--rate-limit**
```bash
python -m vulnmind --target https://example.com --rate-limit 100
python -m vulnmind --target https://example.com --rate-limit 10
```
- **Description**: Requests per minute limit
- **Default**: 60
- **Use case**: Respectful scanning

### **--exclude-paths**
```bash
python -m vulnmind --target https://example.com --exclude-paths "/admin,/private,/logout"
```
- **Description**: Paths to exclude from scanning
- **Format**: Comma-separated path list
- **Use case**: Avoid sensitive or destructive endpoints

### **--include-paths**
```bash
python -m vulnmind --target https://example.com --include-paths "/api,/search,/login"
```
- **Description**: Only scan specified paths
- **Format**: Comma-separated path list
- **Use case**: Focused scanning

---

## 📚 Examples

### **Basic Vulnerability Scan**
```bash
python -m vulnmind --target https://example.com
```

### **AI-Enhanced Comprehensive Scan**
```bash
python -m vulnmind \
  --target https://example.com \
  --ai-mode \
  --self-aware \
  --report html \
  --output-file comprehensive_scan.html
```

### **Stealth Scan with Custom Settings**
```bash
python -m vulnmind \
  --target https://example.com \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  --delay 2.0 \
  --max-concurrent 5 \
  --report json \
  --quiet
```

### **Authenticated API Testing**
```bash
python -m vulnmind \
  --target https://api.example.com \
  --auth-type bearer \
  --auth-creds "$API_TOKEN" \
  --headers "Content-Type:application/json" \
  --plugins sql_injection,xss \
  --report json
```

### **Multiple Target Scan**
```bash
python -m vulnmind \
  --target-file targets.txt \
  --ai-mode \
  --report html \
  --output-dir ./scan_results/ \
  --log-file scan.log \
  --log-level INFO
```

### **High-Performance Scan**
```bash
python -m vulnmind \
  --target https://example.com \
  --max-concurrent 20 \
  --delay 0.1 \
  --timeout 5 \
  --retries 1 \
  --report json \
  --output-file fast_scan.json
```

### **Deep Security Analysis**
```bash
python -m vulnmind \
  --target https://example.com \
  --ai-mode \
  --ai-model gpt-4 \
  --self-aware \
  --scan-depth 3 \
  --plugins all \
  --report html \
  --report-template custom_template.html \
  --log-level DEBUG
```

### **CI/CD Integration**
```bash
python -m vulnmind \
  --target "$TARGET_URL" \
  --ai-mode \
  --report json \
  --output-file security_scan.json \
  --quiet \
  --timeout 30 \
  --max-concurrent 10
```

---

## 🌍 Environment Variables

### **OPENAI_API_KEY**
```bash
export OPENAI_API_KEY="sk-your-api-key-here"
python -m vulnmind --target https://example.com --ai-mode
```
- **Description**: OpenAI API key for AI features
- **Required for**: --ai-mode functionality
- **Security**: Never commit to version control

### **VULNMIND_CONFIG**
```bash
export VULNMIND_CONFIG="/path/to/config.yaml"
python -m vulnmind --target https://example.com
```
- **Description**: Default configuration file path
- **Override**: --config command line option

### **VULNMIND_LOG_LEVEL**
```bash
export VULNMIND_LOG_LEVEL="DEBUG"
python -m vulnmind --target https://example.com
```
- **Description**: Default log level
- **Override**: --log-level command line option

### **VULNMIND_USER_AGENT**
```bash
export VULNMIND_USER_AGENT="Custom Scanner/1.0"
python -m vulnmind --target https://example.com
```
- **Description**: Default User-Agent string
- **Override**: --user-agent command line option

### **HTTP_PROXY / HTTPS_PROXY**
```bash
export HTTP_PROXY="http://proxy.example.com:8080"
export HTTPS_PROXY="http://proxy.example.com:8080"
python -m vulnmind --target https://example.com
```
- **Description**: System-wide proxy settings
- **Override**: --proxy command line option

---

## 🔍 Exit Codes

VulnMind returns different exit codes based on scan results:

- **0**: Scan completed successfully, no vulnerabilities found
- **1**: Scan completed, vulnerabilities found
- **2**: Scan failed due to configuration error
- **3**: Scan failed due to network error
- **4**: Scan failed due to authentication error
- **5**: Scan failed due to permission error

### **Using Exit Codes in Scripts**
```bash
python -m vulnmind --target https://example.com --quiet
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ No vulnerabilities found"
elif [ $EXIT_CODE -eq 1 ]; then
    echo "⚠️ Vulnerabilities detected!"
    exit 1
else
    echo "❌ Scan failed with code $EXIT_CODE"
    exit $EXIT_CODE
fi
```

---

## 🛠️ Configuration File Format

### **Example YAML Configuration**
```yaml
# vulnmind_config.yaml
target: "https://example.com"
ai_mode: true
ai_model: "gpt-4"
self_aware: true

plugins:
  - sql_injection
  - xss
  - csrf

network:
  max_concurrent: 15
  delay: 0.5
  timeout: 15
  retries: 2
  user_agent: "VulnMind Scanner"

authentication:
  type: "bearer"
  credentials: "${API_TOKEN}"

reporting:
  format: "html"
  output_file: "security_report.html"
  template: "custom_template.html"

logging:
  level: "INFO"
  file: "vulnmind.log"
```

### **Using Configuration File**
```bash
python -m vulnmind --config vulnmind_config.yaml
```

---

## 🔗 Integration Examples

### **GitHub Actions**
```yaml
- name: Security Scan with VulnMind
  run: |
    python -m vulnmind \
      --target "${{ env.TARGET_URL }}" \
      --ai-mode \
      --report json \
      --output-file security_scan.json \
      --quiet
```

### **Jenkins Pipeline**
```groovy
stage('Security Scan') {
    steps {
        sh '''
            python -m vulnmind \
                --target "${TARGET_URL}" \
                --ai-mode \
                --report json \
                --output-file security_scan.json \
                --log-level WARNING
        '''
    }
}
```

### **Docker Usage**
```bash
docker run --rm \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -v $(pwd):/output \
  vulnmind:latest \
  --target https://example.com \
  --ai-mode \
  --report html \
  --output-file /output/report.html
```

---

## 📞 Support & Documentation

- **📖 Full Documentation**: [README.md](README.md)
- **🐛 Bug Reports**: [GitHub Issues](https://github.com/yashab-cyber/vulnmind/issues)
- **💬 Community Support**: [GitHub Discussions](https://github.com/yashab-cyber/vulnmind/discussions)
- **📧 Direct Support**: yashabalam707@gmail.com
- **🤝 Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)

---

**🛡️ Made with ❤️ by [Yashab Alam](https://github.com/yashab-cyber) and [ZehraSec](https://www.zehrasec.com)**

*Last Updated: August 10, 2025*
