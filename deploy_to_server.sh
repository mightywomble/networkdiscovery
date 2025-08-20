#!/bin/bash

# Deploy NetworkMap to remote server
set -e

echo "🚀 Deploying NetworkMap to remote server..."

# Find SSH key file
SSH_KEY=""
for keyfile in ~/.ssh/id_rsa ~/.ssh/id_ed25519 ~/.ssh/google_compute_engine; do
    if [ -f "$keyfile" ]; then
        SSH_KEY="$keyfile"
        break
    fi
done

if [ -z "$SSH_KEY" ]; then
    echo "❌ No SSH key found. Please set up SSH access to the server."
    exit 1
fi

# Server details
SERVER_USER="david"
SERVER_IP="100.83.62.51"
PROJECT_DIR="/home/david/live/networkapp"

echo "📡 Connecting to server $SERVER_IP..."

# Try to connect and deploy
ssh -i "$SSH_KEY" -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$SERVER_USER@$SERVER_IP" << 'EOF'
    echo "📥 Pulling latest code from repository..."
    cd /home/david/live/networkapp
    git pull origin main
    
    echo "🔧 Installing/updating dependencies..."
    pip3 install --user -r requirements.txt 2>/dev/null || echo "Requirements file not found, skipping..."
    
    echo "🗄️ Initializing database with new schema..."
    python3 -c "from database import Database; db = Database(); db.init_db(); print('✅ Database initialized')"
    
    echo "🔄 Restarting NetworkApp service..."
    sudo systemctl restart networkapp
    
    echo "📊 Checking service status..."
    sudo systemctl status networkapp --no-pager -l || echo "Service status check failed"
    
    echo "🎉 Deployment completed!"
EOF

if [ $? -eq 0 ]; then
    echo "✅ Successfully deployed to server!"
    echo "🌐 Application should be available at: http://$SERVER_IP:5150"
else
    echo "❌ Deployment failed. Please check the server manually."
    exit 1
fi
