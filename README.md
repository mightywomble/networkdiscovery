# 🌐 NetworkMap - Advanced Network Monitoring & AI-Powered Analytics Platform

<div align="center">

![NetworkMap Logo](https://img.shields.io/badge/NetworkMap-v2.1.0-blue?style=for-the-badge&logo=network-wired)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg?style=for-the-badge&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/flask-2.3.3-green.svg?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com/)
[![PatternFly](https://img.shields.io/badge/PatternFly-4.224.5-red.svg?style=for-the-badge&logo=redhat)](https://www.patternfly.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)

*A comprehensive network monitoring platform with AI-powered analytics, modern PatternFly UI, and distributed agent architecture*

[🚀 Features](#-features) • [⚡ Quick Start](#-quick-start) • [🤖 AI Reports](#-ai-powered-analytics) • [📊 Dashboard](#-enhanced-dashboard) • [🔧 Installation](#-installation)

</div>

---

## 📋 Executive Summary

**NetworkMap** is a cutting-edge network monitoring and visualization platform featuring **AI-powered analytics**, **modern PatternFly UI design**, and **intelligent network insights**. Designed for IT administrators, network engineers, and DevOps teams who need comprehensive network intelligence with beautiful, professional interfaces.

### 🎯 Key Benefits

- **🧠 AI-Powered Analytics**: Generate comprehensive network analysis reports using Google Gemini and OpenAI
- **🎨 Modern UI Design**: Professional PatternFly 4 interface with responsive design and intuitive workflows
- **📊 Real-time Dashboard**: Dynamic statistics with live updates and colorful, informative visualizations
- **🤖 Distributed Monitoring**: Lightweight agents with automatic deployment and real-time status updates
- **🔍 Advanced Network Discovery**: Multi-method network scanning with enhanced topology mapping
- **📈 Intelligent Insights**: Smart suggestions and contextual guidance for better network management
- **🛠 Professional Tools**: Comprehensive host management, agent lifecycle, and network analytics
- **⚡ Performance Optimized**: Fast, responsive interface with efficient data loading and caching

---

## ✨ Features

### 🧠 **AI-Powered Analytics**
- **Smart Report Generation**: Comprehensive network analysis using advanced AI models
- **Multiple AI Providers**: Support for Google Gemini (2.5 Flash, 2.5 Pro, 1.5 Pro) and OpenAI ChatGPT
- **Intelligent Data Analysis**: Analyze complete network datasets, latest snapshots, or system logs
- **Contextual Suggestions**: Smart recommendations for network scans and data collection
- **Professional Report Format**: Well-structured, actionable reports with executive summaries
- **Real-time Processing**: Live report generation with progress tracking and error handling

### 🎨 **Modern PatternFly Interface**
- **Professional Design**: Enterprise-grade UI components with consistent styling
- **Responsive Layout**: Optimized for desktop, tablet, and mobile devices
- **Intuitive Navigation**: Clean sidebar navigation with organized sections
- **Enhanced Modals**: Interactive dialogs with proper form validation and user feedback
- **Accessible Design**: WCAG compliant with keyboard navigation and screen reader support
- **Visual Indicators**: Color-coded status indicators, progress bars, and interactive elements

### 📊 **Enhanced Dashboard**
- **Dynamic Statistics Cards**: Real-time data from API endpoints with automatic refresh
- **5-Column Layout**: Total Hosts, Network Connections, Active Agents, Open Ports, Recent Scans
- **Live Updates**: Statistics refresh every 30 seconds with loading states and error handling
- **Visual Appeal**: Colorful icons, hover effects, and professional styling
- **Consistent Data**: Same data sources as Statistics page ensuring accuracy
- **Quick Actions**: Direct access to network scans, tool installation, and network maps

### 📈 **Advanced Statistics Dashboard** *(NEW in v2.1.0)*
- **Real-time Network Analytics**: Comprehensive network traffic analysis with live data
- **Interactive Charts**: Chart.js powered visualizations with protocol breakdown and traffic patterns
- **Network Traffic Analysis**: 
  - Protocol breakdown (TCP, UDP, ICMP) with connection counts and percentages
  - Top destinations with connection volumes and port analysis
  - Top active hosts with traffic patterns and activity status
  - LAN vs External traffic analysis with bandwidth utilization
- **Agent Activity Monitoring**:
  - Real-time agent status with platform breakdown
  - Version distribution across monitored infrastructure
  - Scan activity metrics with type-based analysis
  - Heartbeat monitoring with connectivity status
- **Historical Analytics**:
  - Hourly connection activity trends with visual timelines
  - Daily agent scan activity with performance metrics
  - Time-based filtering (24h, 7d, 30d) for trend analysis
  - Historical data visualization with interactive charts
- **REST API Integration**: Three dedicated endpoints for real-time data
  - `/api/statistics/network` - Network traffic and topology statistics
  - `/api/statistics/agents` - Agent monitoring and activity metrics  
  - `/api/statistics/historical` - Time-based analytics and trend data
- **Auto-refresh Functionality**: 30-second refresh intervals with manual refresh options
- **Professional PatternFly Design**: Enterprise-grade cards, charts, and layout components

### 🖥 **Improved Web Interface**
- **Streamlined Sidebar**: Organized navigation with Main, Infrastructure, Visualization, AI Tooling, and Settings
- **Enhanced Host Management**: Improved edit buttons, removed clutter, better visual hierarchy
- **Smart Quick Actions**: Context-aware action buttons with intelligent suggestions
- **Professional Cards**: Clean card layouts with proper spacing and visual indicators
- **Loading States**: Smooth transitions and loading indicators for better UX
- **Error Handling**: Graceful error states with user-friendly messages

### 🤖 **Advanced Agent System** 
- **Lightweight Monitoring**: Minimal resource footprint with comprehensive data collection
- **Auto-deployment**: One-click SSH-based deployment with real-time progress tracking
- **Version Management**: Automatic versioning with build date tracking and update management
- **Real-time Communication**: Heartbeat monitoring with instant status updates
- **Enhanced Data Structure**: Comprehensive agent information with platform details
- **Bulk Operations**: Mass deployment, updates, and configuration management

### 🔍 **Network Discovery & Analysis**
- **Multi-method Discovery**: ARP scanning, ping sweeps, advanced port scanning
- **Intelligent Topology**: Automatic network mapping with relationship analysis
- **Performance Testing**: Bandwidth analysis, latency monitoring, connectivity validation
- **Security Assessment**: Vulnerability scanning, service detection, port analysis
- **Traffic Analysis**: Network flow monitoring and pattern recognition
- **Tool Installation**: Automated installation of network analysis utilities

### 📊 **Advanced Visualizations**
- **Interactive Network Maps**: D3.js powered topology with zoom, pan, and node manipulation
- **Enhanced Diagrams**: Professional network diagrams with device-specific icons
- **Real-time Updates**: Live visualization updates during network scans
- **Multiple View Modes**: Traditional diagrams, force-directed graphs, hierarchical layouts
- **Export Capabilities**: Save network diagrams and topology data
- **Responsive Design**: Optimized viewing across all device sizes

### 🛠 **Professional Management Tools**
- **Comprehensive Host Management**: Add, edit, organize hosts with enhanced forms
- **Agent Lifecycle Management**: Deploy, configure, update, monitor with version tracking
- **Centralized Configuration**: Unified configuration management across all agents
- **Advanced Analytics**: PostgreSQL-based data analytics with performance insights
- **Import/Export**: Backup and restore configurations with data validation
- **Cleanup Utilities**: Database maintenance tools and stale record removal

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.8+** with pip and virtual environment support
- **Ubuntu/Debian Server** (recommended for optimal performance)
- **PostgreSQL Database** (for production) or SQLite (for development)
- **SSH Access** to target hosts for agent deployment
- **Network Connectivity** between server and monitored infrastructure
- **Modern Web Browser** (Chrome, Firefox, Safari, Edge)

### 1. 🔧 Server Setup
```bash
# Clone the repository
git clone https://github.com/mightywomble/networkdiscovery.git
cd networkdiscovery

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize the database
python3 -c "from database_postgresql import Database; db = Database(); db.init_db()"

# Start the server
python3 app.py
```

### 2. 🌐 Access the Web Interface
Open your browser and navigate to:
```
http://your-server-ip:5150
```

### 3. 🏠 Configure Your Network
1. **Dashboard** → Overview of your network with live statistics
2. **Hosts** → Add hosts with IP addresses and SSH credentials
3. **Agents** → Deploy monitoring agents to your infrastructure
4. **Statistics** → View comprehensive network analytics and trends
5. **AI Configuration** → Set up Google Gemini or OpenAI API keys

### 4. 🤖 Generate AI Reports
1. **AI Reports** → Choose data type (Complete Dataset, Latest Snapshot, System Logs)
2. **Select AI Model** → Choose from Gemini 2.5 Flash, Gemini Pro, or ChatGPT
3. **Generate Report** → Get comprehensive network analysis with actionable insights
4. **Review Recommendations** → Follow AI suggestions for network optimization

### 5. 📊 Monitor Your Network
1. **Statistics** → View detailed network metrics, charts, and trends
2. **Network Maps** → Visualize topology and device relationships
3. **Agent Monitoring** → Track agent health and data collection
4. **Real-time Updates** → Monitor live network status and changes

---

## 🧠 AI-Powered Analytics

### 🎯 Overview
NetworkMap's AI analytics engine provides intelligent network insights using state-of-the-art language models. Generate comprehensive reports that identify issues, suggest optimizations, and provide actionable recommendations.

### 🤖 Supported AI Models

#### Google Gemini (Recommended)
- **Gemini 2.5 Flash** (Default) - Fast, efficient analysis
- **Gemini 2.5 Pro** - Enhanced reasoning and detailed insights  
- **Gemini 1.5 Pro** - Comprehensive analysis with deep context
- **Gemini 1.5 Flash** - Quick analysis for routine monitoring
- **Gemini Pro** (Legacy) - Backward compatibility support
- **Gemini Pro Vision** (Legacy) - Image and visual analysis

#### OpenAI ChatGPT
- **ChatGPT-4o** - Advanced reasoning and detailed analysis
- **ChatGPT-4** - Professional-grade network analysis
- **ChatGPT-3.5 Turbo** - Fast, cost-effective insights

### 📊 Data Analysis Types

#### 1. **Complete Network Dataset**
- **Scope**: All historical data, connections, hosts, and log files
- **Best For**: Comprehensive network audits, trend analysis, long-term planning
- **Analysis**: Network evolution, pattern recognition, capacity planning
- **Report Includes**: Historical trends, performance patterns, growth projections

#### 2. **Latest Data Snapshot**
- **Scope**: Most recent network scan results and current host status
- **Best For**: Current state analysis, immediate issue detection
- **Analysis**: Real-time network health, active connections, device status
- **Report Includes**: Current network topology, active issues, immediate recommendations
- **Smart Suggestions**: Automatic recommendations for fresh network scans when data is stale

#### 3. **Latest System Logs**
- **Scope**: Recent log files from all monitored hosts
- **Best For**: Troubleshooting, security analysis, error detection
- **Analysis**: Log pattern analysis, error correlation, security events
- **Report Includes**: Critical events, error patterns, security recommendations

### 🎨 Report Features

#### Professional Format
- **Executive Summary**: High-level overview for management
- **Technical Analysis**: Detailed findings for technical teams
- **Visual Formatting**: Well-structured HTML with proper styling
- **Actionable Insights**: Specific recommendations with implementation guidance
- **Risk Assessment**: Security vulnerabilities and priority rankings

#### Smart Contextual Suggestions
- **Data Freshness**: Intelligent recommendations for network scans based on data age
- **Optimization Opportunities**: AI-identified areas for improvement
- **Security Alerts**: Potential vulnerabilities and mitigation strategies
- **Performance Insights**: Network bottlenecks and optimization suggestions

### 🔧 AI Configuration

#### Setting Up Google Gemini
1. **Get API Key**: Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. **AI Configuration** → **Google Gemini** → Enter API key
3. **Test Connection** → Verify API connectivity
4. **Select Model** → Choose appropriate model for your needs
5. **Generate Reports** → Start creating intelligent network insights

#### Setting Up OpenAI ChatGPT
1. **Get API Key**: Visit [OpenAI Platform](https://platform.openai.com/api-keys)
2. **AI Configuration** → **OpenAI ChatGPT** → Enter API key
3. **Test Connection** → Verify API access and model availability
4. **Choose Model** → Select ChatGPT model based on requirements
5. **Generate Analysis** → Create detailed network reports

### 📈 Use Cases

#### Network Health Assessment
```
Generate comprehensive health reports identifying:
• Performance bottlenecks and optimization opportunities
• Security vulnerabilities and recommended mitigations  
• Configuration issues and best practice recommendations
• Capacity planning insights and growth projections
```

#### Security Analysis
```
Analyze network for security issues including:
• Open ports and potential attack vectors
• Unusual connection patterns and anomalies
• Service configurations and hardening opportunities
• Compliance gaps and remediation strategies
```

#### Troubleshooting Assistant
```
Intelligent analysis for problem resolution:
• Root cause analysis of network issues
• Correlation of logs and network data
• Step-by-step troubleshooting guides
• Performance optimization recommendations
```

---

## 📊 Enhanced Dashboard

### 🎨 Dynamic Statistics
The Dashboard features a modern, data-driven statistics bar with real-time updates:

#### 5-Column Live Statistics
1. **🖥 Total Hosts** - Complete host inventory with online status
2. **🌐 Network Connections** - Active connections with recent activity metrics  
3. **🤖 Active Agents** - Monitoring agent status with recent activity
4. **🚪 Open Ports** - Security assessment with host distribution
5. **🔍 Recent Scans** - Scanning activity with hourly and daily metrics

#### Features
- **Real-time Updates**: Statistics refresh every 30 seconds
- **API-Driven Data**: Same reliable data sources as Statistics page
- **Visual Excellence**: Colorful themed icons with hover animations
- **Responsive Design**: Adapts beautifully to all screen sizes
- **Loading States**: Professional loading indicators and error handling

### 🎯 Quick Actions
Streamlined action buttons for common network operations:
- **🔍 Start Network Scan**: Launch comprehensive network discovery
- **🛠 Install Ubuntu Tools**: Deploy network analysis utilities
- **📊 View Network Map**: Navigate to interactive topology visualization

### 💡 Smart Design Elements
- **Color-coded Cards**: Each statistic has a unique color theme
- **Professional Styling**: PatternFly components with enterprise appearance  
- **Intuitive Icons**: Font Awesome icons that clearly represent each metric
- **Hover Effects**: Subtle animations that enhance user interaction
- **Consistent Layout**: Grid system that maintains visual hierarchy

---

## 📈 Advanced Statistics Dashboard *(NEW in v2.1.0)*

### 🎯 Overview
The completely redesigned Statistics page provides comprehensive network intelligence with real-time data visualization, interactive charts, and professional PatternFly styling.

### 📊 **Network Traffic Analytics**

#### Protocol Analysis
- **Protocol Breakdown**: Visual pie charts showing TCP, UDP, ICMP distribution
- **Connection Metrics**: Total connections, unique hosts, and destination analysis
- **Traffic Patterns**: Visual representation of network communication flows
- **Port Usage**: Analysis of commonly used ports and services

#### Top Destinations & Hosts
- **Traffic Leaders**: Ranked tables of most active destinations and source hosts
- **Connection Counts**: Total connections with unique port and host metrics
- **Activity Status**: Real-time status indicators (online/offline)
- **Last Activity**: Timestamps showing recent network activity
- **Traffic Distribution**: Visual charts showing communication patterns

#### LAN vs External Analysis
- **Network Segmentation**: Clear breakdown of internal vs external traffic
- **Security Assessment**: Analysis of external connections and potential risks
- **Bandwidth Utilization**: Visual representation of traffic distribution
- **Connection Patterns**: Identification of normal vs anomalous traffic flows

### 🤖 **Agent Activity Monitoring**

#### Agent Overview
- **Total Agent Count**: Complete inventory of deployed monitoring agents
- **Active Status**: Real-time status with recent heartbeat tracking
- **Platform Distribution**: Breakdown by operating system and architecture
- **Version Management**: Agent version distribution and update status

#### Scan Activity Analysis
- **Scan Type Breakdown**: Analysis of different scan types (network, port, service)
- **Activity Metrics**: Scan frequency and completion rates
- **Agent Performance**: Individual agent productivity and health metrics
- **Historical Trends**: Scan activity patterns over time

### 📅 **Historical Analytics** *(NEW Feature)*

#### Time-based Analysis
- **Hourly Activity**: Connection patterns throughout the day
- **Daily Trends**: Long-term activity patterns and growth analysis
- **Custom Time Ranges**: Flexible time period selection (24h, 7d, 30d)
- **Activity Correlation**: Relationship between agent scans and network activity

#### Trend Visualization
- **Interactive Charts**: Chart.js powered time series visualizations
- **Activity Timelines**: Visual representation of network and agent activity
- **Peak Analysis**: Identification of high and low activity periods
- **Capacity Planning**: Historical data for network growth planning

### 🔄 **Real-time Features**

#### Auto-refresh Functionality
- **30-Second Updates**: Automatic data refresh for current information
- **Manual Refresh**: On-demand data updates with loading indicators
- **Error Handling**: Graceful degradation when API endpoints are unavailable
- **Loading States**: Professional loading animations and progress indicators

#### API Integration
- **RESTful Endpoints**: Clean, well-documented API for statistics data
- **JSON Response Format**: Structured data with timestamps and success indicators
- **Error Responses**: Comprehensive error handling with detailed messages
- **Performance Optimized**: Efficient database queries for fast response times

### 🎨 **Professional UI Design**

#### PatternFly Components
- **Enterprise Cards**: Professional card layouts with headers and actions
- **Data Tables**: Sortable, responsive tables with pagination support
- **Chart Integration**: Seamless Chart.js integration with PatternFly styling
- **Color Schemes**: Consistent color themes across all visualizations
- **Responsive Layout**: Mobile-optimized design with tablet and desktop support

#### Visual Excellence
- **Interactive Elements**: Hover effects, clickable charts, and dynamic content
- **Status Indicators**: Color-coded badges for quick status assessment
- **Typography**: Professional font choices with proper hierarchy
- **Spacing & Layout**: Optimal white space and visual flow
- **Accessibility**: Screen reader support and keyboard navigation

---

## 🔧 Installation

### 🖥 Production Server Setup

#### Option 1: Standard Installation
```bash
# Create production directory
sudo mkdir -p /opt/networkmap
sudo chown $USER:$USER /opt/networkmap

# Clone repository  
git clone https://github.com/mightywomble/networkdiscovery.git /opt/networkmap
cd /opt/networkmap

# Install system dependencies
sudo apt update && sudo apt install -y python3 python3-pip python3-venv nginx postgresql postgresql-contrib

# Create Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Setup PostgreSQL database
sudo -u postgres createuser networkmap
sudo -u postgres createdb networkmap -O networkmap
sudo -u postgres psql -c "ALTER USER networkmap PASSWORD 'secure_password';"

# Initialize database
python3 -c "from database_postgresql import Database; db = Database(); db.init_db()"

# Create systemd service
sudo cp scripts/networkmap.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable networkmap
sudo systemctl start networkmap
```

#### Option 2: Development Setup
```bash
# Clone for development
git clone https://github.com/mightywomble/networkdiscovery.git
cd networkdiscovery

# Create development environment
python3 -m venv dev-env
source dev-env/bin/activate
pip install -r requirements.txt

# Use SQLite for development
python3 -c "from database import Database; db = Database(); db.init_db()"

# Run in development mode
export FLASK_DEBUG=1
python3 app.py
```

### 🐳 Docker Deployment
```bash
# Build Docker image
docker build -t networkmap:latest .

# Run container with PostgreSQL
docker run -d \
  --name networkmap \
  -p 5150:5150 \
  -v /opt/networkmap/data:/app/data \
  -e DATABASE_URL="postgresql://user:pass@localhost/networkmap" \
  networkmap:latest
```

### ☁️ Cloud Deployment

#### AWS EC2
```bash
# Create EC2 instance (Ubuntu 20.04+)
# Configure security groups (port 5150, 22)
# Setup RDS PostgreSQL instance
# Follow standard installation steps
# Consider using Application Load Balancer for high availability
```

#### Google Cloud Platform
```bash
# Create Compute Engine instance
# Configure firewall rules
# Use Cloud SQL for PostgreSQL database
# Deploy with Cloud Run for serverless (advanced)
```

---

## 🤖 Agent Management

### 🚀 Enhanced Agent System

#### Automatic Deployment
```bash
# Web Interface (Recommended)
1. Hosts → Select hosts → Deploy Selected
2. Monitor real-time deployment progress
3. Verify agent registration and heartbeat

# Bulk Deployment
1. Agents → Bulk Operations → Deploy All
2. Configure deployment parameters
3. Monitor deployment status dashboard
```

#### Advanced Configuration
```json
{
    "server_url": "http://your-server:5150",
    "scan_interval": 300,
    "heartbeat_interval": 60,
    "log_collection_enabled": true,
    "scan_enabled": true,
    "test_suites": ["connectivity", "performance", "security"],
    "log_paths": ["/var/log", "/var/log/syslog", "/var/log/auth.log"],
    "resource_limits": {
        "max_cpu_percent": 10,
        "max_memory_mb": 100
    }
}
```

#### Version Management
- **Automatic Versioning**: Git hook-based version increment
- **Update Tracking**: Web interface for version monitoring
- **Bulk Updates**: Mass agent update capabilities
- **Compatibility**: Support for legacy and new agent formats
- **Health Monitoring**: Agent health dashboards with status indicators

---

## 🌐 Network Analysis

### 🔍 Advanced Discovery Methods

#### Multi-Protocol Scanning
```bash
# ARP Table Analysis
- Discovers devices via MAC address resolution
- Identifies network segments and VLANs
- Maps physical network topology

# ICMP Ping Sweeps  
- Fast host discovery across subnets
- Network reachability validation
- Response time analysis

# Port Scanning
- Service discovery and fingerprinting
- Security assessment and vulnerability detection
- Application mapping and inventory
```

#### Enhanced Topology Mapping
- **Relationship Analysis**: Device interconnection mapping
- **Network Segmentation**: VLAN and subnet identification
- **Path Discovery**: Network route analysis and optimization
- **Performance Metrics**: Latency, bandwidth, and throughput analysis

### 📊 Professional Visualizations

#### Interactive Network Maps
- **D3.js Power**: Modern, responsive network diagrams
- **Real-time Updates**: Live topology changes during scans
- **Multiple Layouts**: Force-directed, hierarchical, circular arrangements
- **Device Icons**: Professional icons for servers, switches, routers, workstations
- **Zoom & Pan**: Smooth navigation for large network topologies
- **Export Options**: PNG, SVG, JSON export capabilities

#### Enhanced Network Diagrams
- **Professional Styling**: Enterprise-grade visual design
- **Color Coding**: Status-based coloring for quick health assessment
- **Interactive Elements**: Click, hover, drag for detailed information
- **Responsive Design**: Optimized viewing on all devices
- **Custom Styling**: Configurable themes and layout options

---

## 📚 API Reference

### 🔗 Core API Endpoints

#### Dashboard & Statistics *(Enhanced in v2.1.0)*
```http
GET    /api/stats/overview              # Live dashboard statistics
GET    /api/statistics/network          # Comprehensive network traffic analytics
GET    /api/statistics/agents           # Agent activity and monitoring metrics
GET    /api/statistics/historical       # Historical data trends and analytics
GET    /api/stats/realtime              # Real-time metrics
GET    /api/stats/hosts                 # Host-specific statistics
GET    /api/stats/connections           # Network connection stats
```

#### AI Analytics
```http
GET    /api/ai_settings                 # AI configuration status
POST   /api/ai_settings                 # Update AI configuration
GET    /api/ai_settings/{provider}      # Provider-specific settings
POST   /api/ai_reports/generate         # Generate AI report
GET    /api/ai_reports/data_stats       # Data statistics for reports
```

#### Host & Agent Management
```http
GET    /api/hosts                       # List all hosts
POST   /api/hosts                       # Add new host
PUT    /api/hosts/{id}                  # Update host configuration
DELETE /api/hosts/{id}                  # Remove host

GET    /api/agents                      # List all agents
POST   /api/agents/deploy               # Deploy agent to hosts
PUT    /api/agents/{id}/config          # Update agent configuration
GET    /api/agents/{id}/status          # Get agent status
POST   /api/agents/{id}/scan            # Trigger agent scan
```

#### Network Operations
```http
POST   /api/network/scan                # Start network scan
GET    /api/network/scan/status         # Get scan progress
GET    /api/network/scan/results        # Get scan results
POST   /api/network/topology/build      # Build network topology
GET    /api/network/topology/data       # Get topology data
```

### 📖 API Usage Examples

#### Get Network Statistics *(NEW)*
```bash
curl -X GET http://localhost:5150/api/statistics/network \
  -H "Accept: application/json"

# Response includes:
# - Protocol breakdown (TCP, UDP, ICMP)
# - Top destinations with connection counts
# - Top active hosts with traffic analysis
# - LAN vs External traffic distribution
```

#### Get Agent Statistics *(NEW)*
```bash
curl -X GET http://localhost:5150/api/statistics/agents \
  -H "Accept: application/json"

# Response includes:
# - Agent overview (total, active, recent activity)
# - Platform breakdown (Linux, Windows, etc.)
# - Version distribution across agents
# - Scan activity metrics by type
```

#### Get Historical Analytics *(NEW)*
```bash
curl -X GET http://localhost:5150/api/statistics/historical?hours=24 \
  -H "Accept: application/json"

# Response includes:
# - Hourly connection activity trends
# - Daily agent scan activity
# - Time-based filtering support
# - Historical pattern analysis
```

#### Generate AI Report
```bash
curl -X POST http://localhost:5150/api/ai_reports/generate \
  -H "Content-Type: application/json" \
  -d '{
    "ai_model": "gemini-2.5-flash",
    "data_type": "latest_capture",
    "include_recommendations": true
  }'
```

#### Get Live Dashboard Statistics
```bash
curl -X GET http://localhost:5150/api/stats/overview \
  -H "Accept: application/json"
```

#### Deploy Agent
```bash
curl -X POST http://localhost:5150/api/agents/deploy \
  -H "Content-Type: application/json" \
  -d '{
    "host_ids": [1, 2, 3],
    "config": {
      "scan_interval": 300,
      "heartbeat_interval": 60
    }
  }'
```

---

## 🎨 Modern UI Design

### 🖌 PatternFly Integration

#### Professional Components
- **Enterprise Design System**: Red Hat's PatternFly 4 components
- **Consistent Styling**: Unified visual language across all interfaces
- **Accessibility**: WCAG 2.1 compliant with keyboard navigation
- **Responsive Layouts**: Mobile-first design with tablet and desktop optimization
- **Dark Mode Support**: Automatic theme detection and switching

#### Enhanced User Experience
```css
/* Modern design elements */
- Clean, minimalist interfaces with purposeful white space
- Color-coded status indicators for quick visual scanning
- Professional card layouts with subtle shadows and borders
- Smooth animations and transitions for enhanced interaction
- Interactive elements with hover states and visual feedback
```

#### Improved Navigation
- **Organized Sidebar**: Logical grouping of features and tools
- **Breadcrumb Navigation**: Clear page hierarchy and navigation context
- **Quick Actions**: Context-sensitive action buttons and shortcuts
- **Search Integration**: Global search capabilities across all data
- **Keyboard Shortcuts**: Power user keyboard navigation support

### 📱 Mobile Optimization

#### Responsive Design
- **Mobile-First**: Optimized for touch interfaces and small screens
- **Tablet Support**: Enhanced layouts for medium-sized devices  
- **Progressive Enhancement**: Advanced features for desktop users
- **Touch Gestures**: Native mobile gestures for map navigation
- **Offline Capability**: Basic functionality during connectivity issues

---

## ⚙️ Configuration

### 🔐 Security Configuration

#### Server Security
```bash
# Create dedicated user
sudo useradd -r -s /bin/false networkmap
sudo chown -R networkmap:networkmap /opt/networkmap

# Set proper permissions
chmod 750 /opt/networkmap
chmod 640 /opt/networkmap/config/*
chmod 600 /opt/networkmap/.env

# Configure log rotation
sudo logrotate -f /etc/logrotate.d/networkmap
```

#### API Key Management
```bash
# Store API keys securely
echo 'GEMINI_API_KEY=your-key' >> /opt/networkmap/.env
echo 'OPENAI_API_KEY=your-key' >> /opt/networkmap/.env
chmod 600 /opt/networkmap/.env

# Use environment variables
export $(cat /opt/networkmap/.env | xargs)
```

#### Database Security
```bash
# PostgreSQL Security (Production)
sudo -u postgres psql -c "ALTER USER networkmap PASSWORD 'secure_random_password';"
sudo -u postgres psql -c "GRANT CONNECT ON DATABASE networkmap TO networkmap;"
sudo -u postgres psql -c "GRANT USAGE ON SCHEMA public TO networkmap;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO networkmap;"

# Enable SSL connections
sudo vim /etc/postgresql/*/main/postgresql.conf
# ssl = on
# ssl_cert_file = 'server.crt'
# ssl_key_file = 'server.key'
```

### 🔐 Agent Security

#### SSH Key Authentication
```bash
# Generate SSH keys for agent deployment
ssh-keygen -t rsa -b 4096 -f /opt/networkmap/.ssh/networkmap_key

# Deploy public key to agents
ssh-copy-id -i /opt/networkmap/.ssh/networkmap_key.pub user@agent-host
```

#### Agent Configuration Security
- **Minimal Privileges**: Agents run with least required permissions
- **Encrypted Communication**: All data transmission uses HTTPS
- **Configuration Validation**: Server-side validation of all agent configs
- **Resource Limits**: CPU and memory constraints prevent resource exhaustion

---

## 🚨 Troubleshooting

### 🔧 Common Issues

#### AI Reports Not Working
```bash
# Check API key configuration
curl -X GET http://localhost:5150/api/ai_settings

# Test AI connectivity
curl -X POST http://localhost:5150/api/ai_settings/gemini/test \
  -H "Content-Type: application/json" \
  -d '{"api_key": "your-key"}'

# Check server logs
tail -f /opt/networkmap/logs/app.log | grep -i "ai\|error"
```

#### Statistics Dashboard Not Loading *(NEW Troubleshooting)*
```bash
# Test statistics API endpoints
curl -X GET http://localhost:5150/api/statistics/network
curl -X GET http://localhost:5150/api/statistics/agents
curl -X GET http://localhost:5150/api/statistics/historical?hours=24

# Check JavaScript console
# Open browser DevTools → Console tab
# Look for JavaScript errors or failed API calls

# Verify database connectivity
python3 -c "from database_postgresql import Database; db = Database(); print(db.get_network_statistics())"

# Check Flask service logs
journalctl -u networkmap --no-pager -n 20
```

#### Database Connection Issues *(PostgreSQL)*
```bash
# Test PostgreSQL connection
sudo -u postgres psql -c "\l"

# Check NetworkMap database
sudo -u postgres psql -d networkmap -c "\dt"

# Verify user permissions
sudo -u postgres psql -c "\du networkmap"

# Test Python database connection
python3 -c "from database_postgresql import Database; db = Database(); print(db.get_connection())"
```

#### Agent Deployment Issues  
```bash
# Test SSH connectivity
ssh -i /opt/networkmap/.ssh/networkmap_key user@target-host

# Check agent logs
tail -f /var/log/networkmap-agent.log

# Verify Python environment
ssh user@target-host "python3 --version && which python3"

# Test agent heartbeat
curl -X GET http://localhost:5150/api/agents | jq '.[] | select(.status == "online")'
```

#### Performance Issues
```bash
# Monitor system resources
htop
iostat 1
netstat -tuln | grep 5150

# Check database performance (PostgreSQL)
sudo -u postgres psql -d networkmap -c "SELECT * FROM pg_stat_activity;"

# Check query performance
sudo -u postgres psql -d networkmap -c "EXPLAIN ANALYZE SELECT * FROM network_connections LIMIT 100;"

# Review Flask performance
tail -f /opt/networkmap/logs/app.log | grep -E "INFO:werkzeug|ERROR"
```

### 📊 Monitoring & Maintenance

#### Health Checks
```bash
# Application health endpoint
curl -X GET http://localhost:5150/api/health

# Database health check
python3 -c "from database_postgresql import Database; db = Database(); print(db.health_check())"

# Statistics API health check
curl -X GET http://localhost:5150/api/statistics/network | jq '.success'

# Agent connectivity check
python3 -c "from agents import AgentManager; am = AgentManager(); am.check_all_agents()"
```

#### Regular Maintenance
```bash
# Daily maintenance script
#!/bin/bash
# Backup PostgreSQL database
sudo -u postgres pg_dump networkmap > /opt/networkmap/backups/$(date +%Y%m%d).sql

# Clean old logs
find /opt/networkmap/logs -name "*.log" -mtime +30 -delete

# Update agent versions
python3 /opt/networkmap/scripts/update_agents.py --check-all

# Generate system report
python3 /opt/networkmap/scripts/health_report.py

# Optimize database
sudo -u postgres psql -d networkmap -c "VACUUM ANALYZE;"
```

---

## 🎯 Advanced Features

### 📊 Analytics Dashboard

#### Network Intelligence
- **Trend Analysis**: Historical pattern recognition and forecasting
- **Anomaly Detection**: Automated identification of unusual network behavior  
- **Performance Baselines**: Establish normal operating parameters
- **Capacity Planning**: Predictive analysis for network growth
- **Security Monitoring**: Continuous threat detection and analysis

#### Reporting Engine
- **Scheduled Reports**: Automated report generation and distribution
- **Custom Templates**: Configurable report formats and content
- **Export Options**: PDF, HTML, JSON, CSV export capabilities
- **Email Integration**: Automated report delivery to stakeholders
- **Dashboard Widgets**: Customizable visual components for key metrics

### 🔮 Machine Learning Integration

#### Predictive Analytics
```python
# Example: Network anomaly detection
from ml_models import NetworkAnomalyDetector

detector = NetworkAnomalyDetector()
anomalies = detector.detect_anomalies(network_data)
recommendations = detector.get_recommendations(anomalies)
```

#### Intelligent Automation
- **Auto-scaling Recommendations**: Dynamic resource allocation suggestions
- **Predictive Maintenance**: Proactive identification of potential issues
- **Optimization Suggestions**: AI-driven network performance improvements
- **Security Intelligence**: Advanced threat detection using ML models

---

## 🤝 Contributing

### 🛠 Development Environment

#### Setup for Contributors
```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/your-username/networkdiscovery.git
cd networkdiscovery

# Create development branch
git checkout -b feature/your-feature-name

# Setup environment
python3 -m venv dev-env
source dev-env/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run tests
pytest tests/
```

#### Code Style
```bash
# Format code
black networkmap/
isort networkmap/

# Lint code  
pylint networkmap/
flake8 networkmap/

# Type checking
mypy networkmap/
```

### 📝 Contribution Guidelines

#### Pull Request Process
1. **Fork & Branch**: Create feature branch from main
2. **Develop**: Implement changes with tests
3. **Test**: Ensure all tests pass
4. **Document**: Update documentation and README
5. **Submit**: Create pull request with detailed description

#### Code Review Standards
- **Functionality**: Features work as intended
- **Testing**: Adequate test coverage (>80%)
- **Documentation**: Clear documentation and comments
- **Performance**: No significant performance degradation
- **Security**: No security vulnerabilities introduced

---

## 📈 Roadmap

### 🚀 Upcoming Features (v2.2.0)

#### Enhanced AI Capabilities
- [ ] **Multi-Provider Comparison**: Compare reports from different AI models
- [ ] **Custom AI Prompts**: User-defined analysis templates
- [ ] **AI-Powered Alerting**: Intelligent anomaly detection and notifications
- [ ] **Natural Language Queries**: Ask questions about your network in plain English

#### Advanced Analytics
- [ ] **Machine Learning Integration**: Predictive network analysis
- [ ] **Time Series Analysis**: Historical trend analysis with forecasting
- [ ] **Behavioral Analysis**: User and device behavior pattern recognition
- [ ] **Security Intelligence**: Advanced threat detection using AI

#### Enterprise Features
- [ ] **Multi-Tenancy**: Support for multiple organizations/networks
- [ ] **Role-Based Access Control**: Granular permission management
- [ ] **Single Sign-On**: SAML/OIDC integration
- [ ] **Audit Logging**: Comprehensive activity tracking and compliance

#### Statistics Enhancements *(Planned for v2.2.0)*
- [ ] **Custom Dashboard Widgets**: User-configurable statistics displays
- [ ] **Advanced Filtering**: Complex filter options for all statistics views
- [ ] **Data Export**: Export statistics data in multiple formats (CSV, JSON, PDF)
- [ ] **Alert Thresholds**: Configurable alerts based on statistical thresholds
- [ ] **Comparative Analysis**: Compare statistics across different time periods
- [ ] **Scheduled Reports**: Automated statistics reports via email
- [ ] **Real-time Alerts**: Push notifications for critical network events

### 🎯 Long-term Vision (v3.0+)

#### Cloud-Native Architecture
- [ ] **Kubernetes Deployment**: Scalable containerized deployment
- [ ] **Microservices**: Distributed architecture for high availability
- [ ] **Edge Computing**: Distributed processing at network edge
- [ ] **Global Load Balancing**: Multi-region deployment support

#### Advanced Integrations
- [ ] **API Ecosystem**: Extensive third-party integrations
- [ ] **Webhook Support**: Real-time event notifications
- [ ] **Custom Plugins**: Extensible architecture for custom features
- [ ] **Mobile Applications**: Native iOS and Android apps

---

## 📋 Version History

### 🆕 v2.1.0 (Current) - AI-Powered Analytics & Enhanced Statistics Platform
- ✨ **AI Report Generation**: Google Gemini and OpenAI integration
- 🎨 **PatternFly UI**: Complete interface redesign with modern components
- 📊 **Dynamic Dashboard**: Real-time statistics with live API data
- 📈 **Advanced Statistics Dashboard**: Comprehensive network analytics with interactive charts
- 🔗 **REST API Endpoints**: Three new statistics APIs for real-time data access
- 🗄️ **PostgreSQL Integration**: Enhanced database support with optimized queries  
- 📊 **Chart.js Visualizations**: Interactive charts for protocol breakdown and traffic analysis
- 🔄 **Auto-refresh Functionality**: Real-time updates with 30-second refresh intervals
- 💡 **Smart Suggestions**: Contextual recommendations for network scans
- 🎯 **Enhanced UX**: Streamlined navigation and improved workflows
- 🔧 **Better Agent Management**: Improved deployment and monitoring
- 🚀 **Performance Optimizations**: Faster loading and response times
- 🛠️ **Service Reliability**: Improved Flask service stability and error handling

### 📦 Previous Versions
- **v2.0.0**: Major UI overhaul with PatternFly integration
- **v1.6.4**: Agent versioning system and enhanced data structures  
- **v1.5.0**: Advanced network analysis and improved agent management
- **v1.4.0**: Enhanced visualization and reporting capabilities
- **v1.3.0**: Real-time monitoring and agent lifecycle management
- **v1.2.0**: Network topology visualization and mapping
- **v1.1.0**: Multi-host scanning and bulk operations
- **v1.0.0**: Initial release with basic network monitoring

---

## 📧 Support & Community

### 🔗 Links
- **🐛 Issues**: [GitHub Issues](https://github.com/mightywomble/networkdiscovery/issues)
- **📖 Documentation**: [Project Wiki](https://github.com/mightywomble/networkdiscovery/wiki)
- **💬 Discussions**: [GitHub Discussions](https://github.com/mightywomble/networkdiscovery/discussions)
- **🔄 Updates**: [Release Notes](https://github.com/mightywomble/networkdiscovery/releases)

### 🆘 Getting Help

#### Before Opening an Issue
1. **Check Documentation**: Review README and wiki
2. **Search Existing Issues**: Look for similar problems
3. **Check Logs**: Include relevant log files
4. **Test Environment**: Verify on clean installation

#### Providing Information
```markdown
**Environment:**
- OS: Ubuntu 20.04
- Python: 3.8.10
- NetworkMap Version: 2.1.0
- Database: PostgreSQL 13.x
- Browser: Chrome 96

**Issue Description:**
Brief description of the problem

**Steps to Reproduce:**
1. Step one
2. Step two
3. Step three

**Expected Behavior:**
What should happen

**Actual Behavior:**
What actually happens

**Logs:**
```
[Include relevant logs here]
```
```

### 🏆 Contributors

We thank all the contributors who have helped make NetworkMap better:

- **🧑‍💻 Core Maintainers**: [@mightywomble](https://github.com/mightywomble)
- **🎨 UI/UX Contributors**: Community designers and developers
- **🐛 Bug Reporters**: Users who help identify and resolve issues
- **📝 Documentation**: Contributors who improve docs and examples
- **🔧 Feature Contributors**: Developers adding new functionality

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 NetworkMap Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

<div align="center">

## 🎉 Ready to Transform Your Network Monitoring?

**NetworkMap v2.1.0** brings AI-powered intelligence to network management with a beautiful, modern interface that makes complex network analysis accessible to everyone.

[![Get Started](https://img.shields.io/badge/🚀_Get_Started-Quick_Start_Guide-blue?style=for-the-badge)](##-quick-start)
[![View Demo](https://img.shields.io/badge/👀_View_Demo-Live_Examples-green?style=for-the-badge)](#)
[![Join Community](https://img.shields.io/badge/💬_Join_Community-GitHub_Discussions-purple?style=for-the-badge)](https://github.com/mightywomble/networkdiscovery/discussions)

**Made with ❤️ for network administrators, DevOps engineers, and IT professionals worldwide**

[![GitHub stars](https://img.shields.io/github/stars/mightywomble/networkdiscovery?style=social)](https://github.com/mightywomble/networkdiscovery/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/mightywomble/networkdiscovery?style=social)](https://github.com/mightywomble/networkdiscovery/network/members)
[![GitHub watchers](https://img.shields.io/github/watchers/mightywomble/networkdiscovery?style=social)](https://github.com/mightywomble/networkdiscovery/watchers)

</div>
