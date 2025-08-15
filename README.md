# 🌐 NetworkMap - Advanced Network Monitoring & Visualization Platform

<div align="center">

![NetworkMap Logo](https://img.shields.io/badge/NetworkMap-v1.4.0-blue?style=for-the-badge&logo=network-wired)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg?style=for-the-badge&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/flask-2.3.3-green.svg?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)

*A comprehensive network monitoring and visualization platform with distributed agent architecture*

[Features](#-features) • [Quick Start](#-quick-start) • [Installation](#-installation) • [Documentation](#-documentation) • [API](#-api-reference)

</div>

---

## 📋 Executive Summary

**NetworkMap** is a powerful, web-based network monitoring and visualization platform designed for IT administrators, network engineers, and DevOps teams. The platform provides real-time network topology mapping, distributed monitoring through lightweight agents, and comprehensive network analysis tools.

### 🎯 Key Benefits

- **🔍 Real-time Network Discovery**: Automatically discover and map network devices, connections, and topology
- **🤖 Distributed Agent Architecture**: Deploy lightweight monitoring agents across your infrastructure
- **📊 Interactive Visualizations**: Multiple visualization modes including D3.js network diagrams and enhanced topology maps
- **⚡ Live Monitoring**: Real-time status updates, heartbeat monitoring, and instant scan triggers
- **🛠 Advanced Analytics**: Built-in tools for network analysis, performance monitoring, and security assessment
- **🔧 Easy Management**: Web-based interface for agent deployment, configuration, and monitoring
- **📈 Scalable Design**: Supports monitoring of small networks to enterprise-scale infrastructures

---

## ✨ Features

### 🖥 **Web Dashboard**
- **Interactive Network Maps**: Visual topology with drag-and-drop node positioning
- **Real-time Status Monitoring**: Live updates of host and agent status
- **Advanced Filtering**: Search, sort, and filter network components
- **Mobile Responsive**: Works on desktop, tablet, and mobile devices

### 🤖 **Distributed Agent System**
- **Lightweight Agents**: Minimal resource footprint monitoring agents
- **Auto-deployment**: One-click SSH-based agent deployment to multiple hosts
- **Real-time Communication**: Heartbeat monitoring and instant status updates
- **Configurable Scanning**: Customizable scan intervals and test suites
- **System Monitoring**: CPU, memory, network interfaces, and process monitoring

### 🔍 **Network Discovery & Analysis**
- **Multi-method Discovery**: ARP scanning, ping sweeps, port scanning
- **Topology Mapping**: Automatic network topology generation
- **Performance Testing**: Bandwidth testing, latency analysis, connectivity tests
- **Security Scanning**: Port scanning, service detection, vulnerability assessment
- **Traffic Analysis**: Network traffic monitoring and analysis

### 📊 **Visualization Modes**
- **Traditional Network Diagram**: Structured network diagrams with device icons
- **D3.js Interactive Map**: Dynamic, zoomable network topology
- **Enhanced Topology**: Comprehensive interconnection mapping
- **Real-time Updates**: Live visualization updates during scans

### 🛠 **Management Tools**
- **Host Management**: Add, edit, remove, and organize network hosts
- **Agent Lifecycle**: Deploy, update, configure, and remove agents
- **Bulk Operations**: Mass deployment, updates, and configuration changes
- **Configuration Management**: Centralized agent configuration and policies
- **Log Management**: Centralized logging and log analysis

### 📈 **Advanced Features**
- **Enhanced Network Scanner**: Advanced discovery using multiple network tools
- **Tool Installation**: Automatic installation of network analysis tools
- **Database Analytics**: SQLite-based data storage with analytics
- **API Integration**: RESTful API for integration with other systems
- **Export/Import**: Host configuration backup and restore

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Ubuntu/Debian server (recommended)
- SSH access to target hosts
- Network connectivity between server and monitored hosts

### 1. Clone and Setup Server
```bash
# Clone repository
git clone https://github.com/mightywomble/networktool.git
cd networktool

# Install dependencies
pip3 install -r requirements.txt

# Start the server
python3 app.py
```

### 2. Access Web Interface
Open your browser and navigate to:
```
http://your-server-ip:5150
```

### 3. Add Your First Host
1. Go to **Hosts** → **Add Host**
2. Enter hostname, IP address, and SSH credentials
3. Click **Save**

### 4. Deploy Your First Agent
1. Go to **Agents** 
2. Select a host and click **Deploy Agent**
3. Monitor deployment progress in real-time

### 5. Start Monitoring
1. Click **Run Agent Now** to trigger immediate scanning
2. View results in **View Last Data**
3. Explore network topology in **Network Map**

---

## 🔧 Installation

### Server Installation

#### Option 1: Manual Installation
```bash
# 1. Clone repository
git clone https://github.com/mightywomble/networktool.git
cd networktool

# 2. Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialize database
python3 -c "from database import Database; db = Database(); db.init_db()"

# 5. Start server
python3 app.py
```

#### Option 2: Production Deployment
```bash
# 1. Clone to production directory
sudo mkdir -p /opt/networkmap
sudo chown $USER:$USER /opt/networkmap
git clone https://github.com/mightywomble/networktool.git /opt/networkmap
cd /opt/networkmap

# 2. Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-venv nginx

# 3. Setup Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Create systemd service (see service file below)
sudo cp networkmap.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable networkmap
sudo systemctl start networkmap

# 5. Configure reverse proxy (optional)
# Configure nginx to proxy to localhost:5150
```

### SystemD Service File

Create `/etc/systemd/system/networkmap.service`:

```ini
[Unit]
Description=NetworkMap Monitoring Platform
After=network.target
Wants=network.target

[Service]
Type=simple
User=networkmap
Group=networkmap
WorkingDirectory=/opt/networkmap
Environment=PATH=/opt/networkmap/venv/bin
Environment=PYTHONUNBUFFERED=1
Environment=FLASK_ENV=production
ExecStart=/opt/networkmap/venv/bin/python /opt/networkmap/app.py
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
ReadWritePaths=/opt/networkmap /var/log/networkmap

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=networkmap

[Install]
WantedBy=multi-user.target
```

### User Setup for Production
```bash
# Create dedicated user
sudo useradd -r -s /bin/false networkmap
sudo chown -R networkmap:networkmap /opt/networkmap
sudo mkdir -p /var/log/networkmap
sudo chown networkmap:networkmap /var/log/networkmap
```

### Agent Deployment

Agents are automatically deployed via the web interface, but you can also deploy manually:

#### Automatic Deployment (Recommended)
1. **Web Interface**: Go to Agents → Select Host → Deploy Agent
2. **Bulk Deployment**: Select multiple hosts → Deploy Selected
3. **Monitor Progress**: Real-time deployment progress tracking

#### Manual Agent Installation
```bash
# On target host:
curl -o networkmap_agent.py http://your-server:5150/static/networkmap_agent.py
sudo python3 networkmap_agent.py --install --server-url http://your-server:5150
```

---

## 🔧 Configuration

### Server Configuration

#### Environment Variables
```bash
# Optional configuration via environment variables
export FLASK_SECRET_KEY="your-secret-key-here"
export DATABASE_PATH="/opt/networkmap/data/networkmap.db"
export LOG_LEVEL="INFO"
export BIND_HOST="0.0.0.0"
export BIND_PORT="5150"
```

#### Database Configuration
The application uses SQLite by default. For production deployments:

```python
# Edit database.py for custom database configuration
DATABASE_FILE = os.environ.get('DATABASE_PATH', 'networkmap.db')
```

### Agent Configuration

#### Default Configuration
```json
{
    "server_url": "http://your-server:5150",
    "scan_interval": 300,
    "heartbeat_interval": 60,
    "log_collection_enabled": true,
    "scan_enabled": true,
    "log_paths": ["/var/log", "/var/log/syslog", "/var/log/auth.log"]
}
```

#### Advanced Configuration
Configure agents via the web interface:
1. **Agents** → Select Agent → **Edit Configuration**
2. Modify scan intervals, test suites, and monitoring parameters
3. Changes applied automatically on next heartbeat

---

## 🌐 Network Architecture

### Deployment Models

#### Single Server Deployment
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   NetworkMap    │    │     Agent       │    │     Agent       │
│     Server      │◄──►│   (Host A)      │    │   (Host B)      │
│   (Web + API)   │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

#### Distributed Deployment
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   NetworkMap    │    │    Network      │    │    Network      │
│     Server      │◄──►│   Segment A     │    │   Segment B     │
│                 │    │  ┌───┐  ┌───┐   │    │  ┌───┐  ┌───┐   │
└─────────────────┘    │  │ A │  │ A │   │    │  │ A │  │ A │   │
                       │  └───┘  └───┘   │    │  └───┘  └───┘   │
                       └─────────────────┘    └─────────────────┘
```

### Communication Flow
1. **Discovery**: Server discovers hosts via ping, SSH, or manual configuration
2. **Deployment**: Automated agent deployment via SSH
3. **Registration**: Agents register with server on startup
4. **Monitoring**: Continuous heartbeat and data collection
5. **Analysis**: Real-time data processing and visualization

---

## 📊 API Reference

### Authentication
Currently uses basic session-based authentication. API endpoints are accessible via HTTP.

### Core Endpoints

#### Host Management
```http
GET    /api/hosts                    # List all hosts
POST   /api/hosts                    # Add new host
PUT    /api/hosts/{id}               # Update host
DELETE /api/hosts/{id}               # Remove host
```

#### Agent Management
```http
GET    /api/agents                   # List all agents
GET    /api/agent/last_data/{id}     # Get agent's latest data
POST   /api/agent/run_now            # Trigger immediate scan
GET    /api/agent/logs               # Get agent logs
POST   /api/deploy_agent             # Deploy agent to host
```

#### Network Operations
```http
POST   /api/scan_now                 # Trigger network scan
GET    /api/scan_status              # Get scan status
GET    /api/network_data             # Get topology data
POST   /api/build_topology           # Build network topology
```

#### System Management
```http
GET    /api/agent/versions           # Get agent version summary
POST   /api/agent/update             # Update specific agent
POST   /api/agent/cleanup/duplicates # Remove duplicate agents
POST   /api/agent/cleanup/stale      # Remove stale agents
```

### Example API Usage

#### Get Network Topology
```bash
curl -X GET http://localhost:5150/api/network_data
```

#### Trigger Agent Scan
```bash
curl -X POST http://localhost:5150/api/agent/run_now \
  -H "Content-Type: application/json" \
  -d '{"hostname":"server01","ip_address":"192.168.1.100"}'
```

#### Deploy Agent
```bash
curl -X POST http://localhost:5150/api/deploy_agent \
  -H "Content-Type: application/json" \
  -d '{"host_id":1,"server_url":"http://your-server:5150"}'
```

---

## 🛠 Tools & Dependencies

### Server Dependencies
```
Flask==2.3.3           # Web framework
paramiko==3.3.1        # SSH client library
Werkzeug==2.3.7        # WSGI utilities
Jinja2==3.1.2          # Template engine
```

### Network Tools (Auto-installed on agents)
```
nmap                    # Network discovery and port scanning
fping                   # Fast ping utility
arp-scan               # ARP-based network discovery
traceroute             # Network path tracing
mtr                    # Network diagnostics
tcpdump                # Packet capture
iftop                  # Network bandwidth monitoring
nethogs                # Process network usage
vnstat                 # Network statistics
iperf3                 # Network performance testing
```

### Frontend Technologies
- **Bootstrap 5**: Responsive UI framework
- **D3.js**: Data visualization library
- **Font Awesome**: Icon library
- **jQuery**: JavaScript library

---

## 🔒 Security Considerations

### Server Security
- **SSH Key Authentication**: Configure SSH key-based authentication for agent deployment
- **Firewall Configuration**: Restrict access to port 5150
- **HTTPS**: Use reverse proxy with SSL/TLS in production
- **User Permissions**: Run service with dedicated user account

### Agent Security
- **Minimal Privileges**: Agents run with minimal required permissions
- **Secure Communication**: All communication over HTTP(S)
- **Configuration Validation**: Server-side validation of agent configurations
- **Log Rotation**: Automatic log rotation to prevent disk space issues

### Network Security
```bash
# Example firewall configuration
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 5150/tcp    # NetworkMap (from monitoring network only)
sudo ufw enable
```

---

## 📚 Documentation

### Web Interface Guide
1. **Dashboard**: Overview of network status and recent activity
2. **Hosts**: Manage monitored hosts and their configurations
3. **Agents**: Deploy, configure, and monitor network agents
4. **Network Map**: Interactive network topology visualization
5. **Enhanced Topology**: Advanced network relationship mapping

### Common Tasks

#### Adding a New Network Segment
1. Add hosts via **Hosts** → **Add Host**
2. Deploy agents via **Agents** → **Deploy Selected**
3. Configure scan parameters via **Agent Configuration**
4. Monitor results in **Network Map**

#### Troubleshooting Connectivity
1. Check agent status in **Agents** dashboard
2. View recent logs via **View Logs**
3. Test connectivity via **Run Agent Now**
4. Check system status via **Health Dashboard**

#### Performance Optimization
1. Adjust scan intervals based on network size
2. Configure selective test suites for different host types
3. Monitor system resources on server and agents
4. Use bulk operations for configuration changes

---

## 🚨 Troubleshooting

### Common Issues

#### Agent Won't Deploy
```bash
# Check SSH connectivity
ssh user@target-host "echo 'SSH works'"

# Verify sudo access
ssh user@target-host "sudo whoami"

# Check system compatibility
ssh user@target-host "python3 --version"
```

#### Agent Not Reporting
```bash
# Check agent service status
ssh user@target-host "sudo systemctl status networkmap-agent"

# View agent logs
ssh user@target-host "sudo journalctl -u networkmap-agent -f"

# Test connectivity to server
ssh user@target-host "curl -s http://server:5150/api/test"
```

#### Performance Issues
```bash
# Check system resources
htop

# Monitor database size
du -h networkmap.db

# Check network latency
ping target-host
mtr target-host
```

### Log Locations
- **Server Logs**: `journalctl -u networkmap -f`
- **Agent Logs**: `journalctl -u networkmap-agent -f`
- **Application Logs**: Check console output or configured log files

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone repository
git clone https://github.com/mightywomble/networktool.git
cd networktool

# Create development environment
python3 -m venv dev-env
source dev-env/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available

# Run in development mode
python3 app.py
```

### Testing
```bash
# Run test suite
python3 -m pytest tests/

# Run specific tests
python3 test_basic.py
python3 test_agent_registration.py
```

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📧 Support

- **Issues**: [GitHub Issues](https://github.com/mightywomble/networktool/issues)
- **Documentation**: [Wiki](https://github.com/mightywomble/networktool/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/mightywomble/networktool/discussions)

---

## 🎯 Roadmap

### Upcoming Features
- [ ] **Multi-tenancy**: Support for multiple organizations/networks
- [ ] **Advanced Analytics**: Machine learning-based anomaly detection
- [ ] **Mobile App**: Native mobile application for monitoring
- [ ] **Alert System**: Configurable alerting and notifications
- [ ] **Integration APIs**: Integration with popular monitoring tools
- [ ] **Cloud Deployment**: Docker containers and Kubernetes deployment
- [ ] **Advanced Security**: Role-based access control and audit logging

### Version History
- **v1.4.0**: Enhanced agent data display, improved log formatting
- **v1.3.0**: Agent management system, real-time monitoring
- **v1.2.0**: Network topology visualization
- **v1.1.0**: Multi-host scanning capabilities
- **v1.0.0**: Initial release with basic monitoring

---

<div align="center">

**Made with ❤️ for network administrators and DevOps engineers worldwide**

[![GitHub stars](https://img.shields.io/github/stars/mightywomble/networktool?style=social)](https://github.com/mightywomble/networktool/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/mightywomble/networktool?style=social)](https://github.com/mightywomble/networktool/network/members)

</div>
