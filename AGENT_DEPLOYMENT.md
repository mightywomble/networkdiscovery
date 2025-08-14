# NetworkMap Agent Deployment Guide

This guide explains how to deploy NetworkMap monitoring agents on remote hosts to enable distributed network monitoring and log collection.

## Overview

The NetworkMap agent system allows you to:
- Deploy lightweight monitoring agents on multiple hosts
- Collect network scan data from distributed locations
- Gather system logs from remote hosts
- Monitor agent health with real-time status updates
- Configure scan intervals and log collection remotely

## Prerequisites

### Server Requirements
- NetworkMap server running and accessible
- Python 3.6+ with Flask
- SQLite database with agent schema initialized

### Target Host Requirements
- Ubuntu/Debian Linux system
- Python 3.6 or later
- Root/sudo access for installation
- Network connectivity to NetworkMap server
- Sufficient disk space for logs and tools

## Deployment Methods

### Method 1: Web Interface (Recommended)

1. Open the NetworkMap web interface
2. Navigate to **Agents** page
3. Click **Deploy New Agent**
4. Follow the deployment instructions in the modal
5. Copy and run the provided commands on your target host

### Method 2: Deployment Script

#### Download and Run
```bash
# Download the deployment script
curl -O http://your-server:5150/static/deploy_agent.sh

# Make executable
chmod +x deploy_agent.sh

# Run with default settings
sudo ./deploy_agent.sh

# Or with custom server URL
sudo ./deploy_agent.sh --server-url http://your-server:5150
```

#### Local Installation
If you have the NetworkMap source code:
```bash
# From the NetworkMap directory
sudo ./deploy_agent.sh --server-url http://your-server:5150
```

### Method 3: Manual Installation

#### Step 1: Download Agent Script
```bash
curl -O http://your-server:5150/static/network_agent.py
chmod +x network_agent.py
```

#### Step 2: Install Dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-requests
sudo apt install -y nmap traceroute mtr-tiny iperf3 tcpdump
```

#### Step 3: Create User and Directories
```bash
sudo useradd --system networkmap-agent
sudo mkdir -p /opt/networkmap-agent /var/log/networkmap-agent /etc/networkmap-agent
sudo chown networkmap-agent:networkmap-agent /opt/networkmap-agent /var/log/networkmap-agent /etc/networkmap-agent
```

#### Step 4: Configure Passwordless Sudo
```bash
echo "networkmap-agent ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/networkmap-agent
sudo chmod 440 /etc/sudoers.d/networkmap-agent
```

#### Step 5: Create Configuration
```bash
sudo tee /etc/networkmap-agent/config.json << EOF
{
    "server_url": "http://your-server:5150",
    "scan_interval": 300,
    "heartbeat_interval": 60,
    "log_collection_enabled": true,
    "log_paths": ["/var/log/syslog", "/var/log/auth.log"],
    "scan_enabled": true
}
EOF
```

#### Step 6: Install as Service
```bash
sudo tee /etc/systemd/system/networkmap-agent.service << EOF
[Unit]
Description=NetworkMap Monitoring Agent
After=network.target

[Service]
Type=simple
User=networkmap-agent
ExecStart=/usr/bin/python3 /opt/networkmap-agent/network_agent.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable networkmap-agent
sudo systemctl start networkmap-agent
```

## Configuration Options

### Deployment Script Options
```bash
sudo ./deploy_agent.sh [OPTIONS]

Options:
  -s, --server-url URL     Server URL (default: http://localhost:5150)
  -u, --user USER          System user for agent (default: networkmap-agent)
  -i, --install-dir DIR    Installation directory (default: /opt/networkmap-agent)
  -l, --log-dir DIR        Log directory (default: /var/log/networkmap-agent)
  -c, --config-dir DIR     Config directory (default: /etc/networkmap-agent)
  -f, --force              Force installation (overwrite existing)
  --uninstall              Uninstall the agent
  --no-start               Don't start service after installation
  -h, --help               Show help message
```

### Agent Configuration
Edit `/etc/networkmap-agent/config.json`:
```json
{
    "server_url": "http://your-server:5150",
    "scan_interval": 300,           // Scan every 5 minutes
    "heartbeat_interval": 60,       // Heartbeat every minute
    "log_collection_enabled": true,
    "log_paths": [
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/kern.log"
    ],
    "scan_enabled": true,
    "log_level": "INFO"
}
```

After changing configuration:
```bash
sudo systemctl restart networkmap-agent
```

## Service Management

### Check Status
```bash
sudo systemctl status networkmap-agent
```

### View Logs
```bash
# Live logs
sudo journalctl -u networkmap-agent -f

# Recent logs
sudo journalctl -u networkmap-agent --since "1 hour ago"
```

### Start/Stop/Restart
```bash
sudo systemctl start networkmap-agent
sudo systemctl stop networkmap-agent
sudo systemctl restart networkmap-agent
```

### Enable/Disable
```bash
sudo systemctl enable networkmap-agent   # Start on boot
sudo systemctl disable networkmap-agent  # Don't start on boot
```

## Monitoring and Management

### Web Interface
1. Go to **Agents** page in NetworkMap web interface
2. View agent status, configuration, and logs
3. Configure agents remotely
4. Export agent data

### Command Line
```bash
# Check agent registration
curl http://your-server:5150/api/agents

# View agent logs
curl "http://your-server:5150/api/agent/logs?agent_id=AGENT_ID&hours=24"
```

## Troubleshooting

### Agent Not Registering
1. Check network connectivity to server
2. Verify server URL in configuration
3. Check agent logs: `sudo journalctl -u networkmap-agent`
4. Ensure server is accepting agent registrations

### Permission Issues
1. Verify passwordless sudo is configured
2. Check file permissions in installation directories
3. Ensure agent user exists and has proper access

### Service Not Starting
1. Check systemd service status
2. Verify Python dependencies are installed
3. Check configuration file syntax
4. Review system logs for errors

### Network Tools Missing
The deployment script automatically installs network monitoring tools. If some tools are missing:
```bash
sudo apt install -y nmap traceroute mtr-tiny iperf3 tcpdump iftop nethogs
```

## Uninstallation

### Using Deployment Script
```bash
sudo ./deploy_agent.sh --uninstall
```

### Manual Removal
```bash
# Stop and disable service
sudo systemctl stop networkmap-agent
sudo systemctl disable networkmap-agent

# Remove service file
sudo rm /etc/systemd/system/networkmap-agent.service
sudo systemctl daemon-reload

# Remove directories
sudo rm -rf /opt/networkmap-agent /var/log/networkmap-agent /etc/networkmap-agent

# Remove user
sudo userdel networkmap-agent

# Remove sudo configuration
sudo rm /etc/sudoers.d/networkmap-agent
```

## Security Considerations

1. **Passwordless Sudo**: The agent requires passwordless sudo to run network monitoring commands. This is configured specifically for the agent user.

2. **Network Access**: Ensure the NetworkMap server is only accessible from trusted networks.

3. **Log Sensitivity**: The agent may collect sensitive log data. Ensure proper access controls on the server.

4. **Service Security**: The systemd service runs with limited privileges where possible.

## Advanced Configuration

### Custom Log Sources
Add custom log files to monitor:
```json
{
    "log_paths": [
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/apache2/access.log",
        "/var/log/nginx/error.log"
    ]
}
```

### Scan Frequency
Adjust scan intervals based on requirements:
```json
{
    "scan_interval": 1800,      // 30 minutes for production
    "heartbeat_interval": 300   // 5 minutes for production
}
```

### Resource Limits
For resource-constrained environments, disable features:
```json
{
    "scan_enabled": false,           // Disable network scans
    "log_collection_enabled": false // Disable log collection
}
```

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review agent logs and server logs
3. Verify network connectivity and permissions
4. Check the NetworkMap documentation

The agent system provides comprehensive distributed monitoring capabilities while maintaining security and ease of deployment.
