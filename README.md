# Network Map

A comprehensive Flask-based web application for network monitoring, visualization, and analysis. This tool allows you to SSH into remote hosts, scan networks, monitor traffic, and visualize network topology in real-time.

## Features

- **SSH-based Host Management**: Add and manage remote hosts with passwordless SSH access
- **Network Scanning**: Port scanning, network discovery, and traffic analysis
- **Real-time Monitoring**: Live network traffic statistics and connection tracking
- **Interactive Visualization**: Web-based network topology graph with filtering and controls
- **Multi-network Support**: Handles home networks, Nord Mesh networks, and internet connections
- **Statistics & Analytics**: Historical data storage and network performance metrics

## Prerequisites

- Python 3.8+
- SSH access to target hosts with passwordless authentication (SSH keys)
- `nmap` installed (optional, for enhanced scanning)
- Network access to target hosts

## Installation

1. **Clone or navigate to the project directory:**
   ```bash
   cd /Users/david/code/networkmap
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

4. **Set up SSH keys** (if not already configured):
   ```bash
   ssh-keygen -t rsa -b 4096
   ssh-copy-id user@your-host-ip
   ```

## Usage

### Starting the Application

```bash
python3 app.py
```

The application will be available at: `http://localhost:5150`

### Adding Hosts

1. Navigate to the "Hosts" page
2. Fill in the host details:
   - **Name**: Friendly name for the host
   - **IP Address**: IPv4 address
   - **Username**: SSH username (default: root)
   - **SSH Port**: SSH port (default: 22)
   - **Description**: Optional description

### Network Scanning

- Click "Scan Now" in the navigation bar for immediate scanning
- View progress and status in the dashboard
- Scans include:
  - Host connectivity testing (ping + SSH)
  - Port scanning (common ports)
  - Network connection analysis
  - Traffic statistics collection
  - Local network discovery

### Network Visualization

1. Go to the "Network Map" page
2. Interactive features:
   - Click nodes to see host details
   - Click connections to see port/protocol info
   - Use filters to show/hide different types of hosts
   - Toggle physics simulation for dynamic layout
   - Zoom and pan for detailed exploration

## Database Schema

The application uses SQLite with the following main tables:

- **hosts**: Host configuration and status
- **network_connections**: Connection data between hosts
- **port_scans**: Open port information
- **traffic_stats**: Network traffic statistics
- **host_info**: System information from hosts

## Configuration

### Environment Variables

- `FLASK_SECRET_KEY`: Set for production use
- `DATABASE_PATH`: Custom database location (default: networkmap.db)

### SSH Configuration

Ensure your SSH config allows passwordless access:

```bash
# ~/.ssh/config
Host *
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
```

## Security Considerations

- **SSH Keys**: Use strong SSH keys and rotate regularly
- **Network Access**: Run on trusted networks only
- **Database**: Secure the SQLite database file
- **Web Interface**: Consider adding authentication for production use

## Troubleshooting

### Common Issues

1. **SSH Connection Failures**
   - Verify SSH keys are properly installed
   - Check network connectivity
   - Ensure SSH service is running on target hosts

2. **Port Scanning Issues**
   - Install `nmap` for enhanced scanning
   - Check firewall settings on both scanner and target
   - Verify user permissions for network operations

3. **Database Errors**
   - Check file permissions for networkmap.db
   - Ensure sufficient disk space
   - Restart application if database locks occur

### Debug Mode

Enable debug mode for development:

```python
app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
```

## API Endpoints

- `GET /api/network_data`: Network topology data
- `GET /api/host_stats/<id>`: Detailed host statistics
- `GET /api/traffic_stats`: Network traffic data
- `POST /scan_now`: Trigger immediate network scan
- `GET /scan_status`: Get current scan status

## Network Discovery

The application can discover and map:

- **Local Networks**: 192.168.x.x ranges
- **Corporate Networks**: 10.x.x.x ranges  
- **Private Networks**: 172.16-31.x.x ranges
- **Internet Connections**: Public IP addresses
- **Nord Mesh Networks**: When properly configured

## Traffic Monitoring

Real-time monitoring includes:

- Bytes in/out per host
- Active connection counts
- Port usage statistics
- Connection frequency tracking
- Historical data retention

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and test thoroughly
4. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues and questions:
- Check the troubleshooting section
- Review log files for error messages
- Ensure all prerequisites are met
- Verify network connectivity and SSH access
