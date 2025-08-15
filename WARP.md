# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Common Commands

### Setup

- **Clone or navigate to the project directory:**
  ```bash
  cd /Users/david/code/networkmap
  ```

- **Create and activate a virtual environment:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

- **Install dependencies:**
  ```bash
  pip3 install -r requirements.txt
  ```

### Running the Application

- **Start the application:**
  ```bash
  python3 app.py
  ```
  The application will be available at: `http://localhost:5150`

### Testing

- **Enable debug mode for development:**
  ```python
  app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
  ```

### Code Structure

- **High-Level Architecture:**
  The application is structured to support network monitoring and visualization through the following main components:
  - **SSH-based Host Management:** Manages remote hosts and supports passwordless SSH access.
  - **Network Scanning:** Includes port scanning, network discovery, and traffic analysis.
  - **Real-time Monitoring:** Provides live network statistics and connection tracking.
  - **Interactive Visualization:** Web-based topology graph for visual exploration.
  - **Database Schema:** Uses SQLite to store hosts, connections, ports, and traffic stats.

### Configuration

- **Environment Variables:**
  - `FLASK_SECRET_KEY`: Set for production use.
  - `DATABASE_PATH`: Custom database location (default: networkmap.db).

- **SSH Configuration:**
  ```bash
  # ~/.ssh/config
  Host *
      StrictHostKeyChecking no
      UserKnownHostsFile /dev/null
  ```

## Security Considerations

- **SSH Keys:** Use strong keys and rotate them regularly.
- **Network Access:** Run only on trusted networks.
- **Database Security:** Secure the SQLite database file.

## API Endpoints

- `GET /api/network_data`: Network topology data
- `GET /api/host_stats/<id>`: Detailed host statistics
- `GET /api/traffic_stats`: Network traffic data
- `POST /scan_now`: Trigger immediate network scan
- `GET /scan_status`: Get current scan status

## Additional Resources

For more detailed setup instructions and usage, refer to the `README.md`.
