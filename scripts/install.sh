#!/bin/bash

################################################################################
# AI Bouncer Agent Installer for Linux
# 
# This script installs the AI Bouncer agent on a Linux system.
# It sets up Python dependencies, generates a unique agent ID, and creates
# a systemd service for continuous operation.
#
# Usage:
#   curl -sSL https://your-domain/install.sh | bash
#   OR
#   bash install.sh
#
################################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/aibouncer-agent"
BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
SERVICE_NAME="aibouncer-agent"
PYTHON_VERSION="3.11"

################################################################################
# Functions
################################################################################

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use: sudo bash install.sh)"
        exit 1
    fi
}

check_os() {
    if [[ ! "$OSTYPE" == "linux"* ]]; then
        log_error "This script only supports Linux. Current OS: $OSTYPE"
        exit 1
    fi
    log_info "Linux system detected"
}

install_dependencies() {
    log_info "Installing system dependencies..."
    
    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        apt-get update
        apt-get install -y \
            python${PYTHON_VERSION} \
            python${PYTHON_VERSION}-pip \
            python${PYTHON_VERSION}-venv \
            git \
            curl \
            build-essential
    elif command -v yum &> /dev/null; then
        # RHEL/CentOS
        yum install -y \
            python${PYTHON_VERSION} \
            python${PYTHON_VERSION}-pip \
            git \
            curl \
            gcc \
            make
    elif command -v pacman &> /dev/null; then
        # Arch
        pacman -Syu --noconfirm \
            python \
            python-pip \
            git \
            curl \
            base-devel
    else
        log_error "Unsupported package manager. Please install Python 3.11 and pip manually."
        exit 1
    fi
    
    log_info "Dependencies installed successfully"
}

create_agent_directory() {
    log_info "Creating agent directory at $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    log_info "Directory created"
}

clone_or_update_repo() {
    log_info "Setting up agent code..."
    
    if [ -d ".git" ]; then
        log_info "Repository already exists, pulling latest changes..."
        git pull origin main
    else
        log_info "Cloning repository..."
        # TODO: Replace with your actual repo URL
        git clone https://github.com/your-org/kernal_ai_bouncer.git .
    fi
    
    log_info "Repository ready"
}

setup_python_env() {
    log_info "Setting up Python virtual environment..."
    
    python${PYTHON_VERSION} -m venv venv
    source venv/bin/activate
    
    # Upgrade pip, setuptools, wheel
    pip install --upgrade pip setuptools wheel
    
    # Install backend dependencies
    if [ -f "backend/requirements.txt" ]; then
        pip install -r backend/requirements.txt
    else
        log_warn "backend/requirements.txt not found"
    fi
    
    log_info "Python environment ready"
}

generate_agent_id() {
    log_info "Generating unique agent ID..."
    
    # Generate UUID v4
    AGENT_ID=$(python3 -c "import uuid; print(str(uuid.uuid4()))")
    log_info "Agent ID: $AGENT_ID"
}

create_env_file() {
    log_info "Creating .env file..."
    
    cat > "$INSTALL_DIR/.env" << EOF
# AI Bouncer Agent Configuration
AGENT_ID=$AGENT_ID
BACKEND_URL=$BACKEND_URL
API_HOST=0.0.0.0
API_PORT=8000
API_LOG_LEVEL=info
DB_PATH=data/events.db
EVENT_CACHE_SIZE=1000
VITE_API_URL=$BACKEND_URL
EOF
    
    chmod 600 "$INSTALL_DIR/.env"
    log_info ".env file created (mode 600)"
}

create_systemd_service() {
    log_info "Creating systemd service..."
    
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=AI Bouncer Security Agent
Documentation=https://github.com/your-org/kernal_ai_bouncer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=aibouncer
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$INSTALL_DIR/venv/bin/python -m backend.agent.main
Restart=always
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    
    chmod 644 "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    log_info "Systemd service created: /etc/systemd/system/${SERVICE_NAME}.service"
}

create_agent_user() {
    log_info "Creating aibouncer user..."
    
    if ! id "aibouncer" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" aibouncer
        log_info "User 'aibouncer' created"
    else
        log_warn "User 'aibouncer' already exists"
    fi
    
    # Set ownership
    chown -R aibouncer:aibouncer "$INSTALL_DIR"
    log_info "Ownership set to aibouncer:aibouncer"
}

start_service() {
    log_info "Starting agent service..."
    
    systemctl start "$SERVICE_NAME"
    systemctl enable "$SERVICE_NAME"
    
    # Wait a moment for service to start
    sleep 2
    
    # Check status
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_info "Service is running!"
        systemctl status "$SERVICE_NAME" --no-pager
    else
        log_error "Service failed to start. Check logs with: journalctl -u $SERVICE_NAME -n 50"
        exit 1
    fi
}

print_summary() {
    cat << EOF

${GREEN}========================================
Installation Complete!
========================================${NC}

Agent ID:           $AGENT_ID
Install Directory:  $INSTALL_DIR
Backend URL:        $BACKEND_URL
Service Name:       $SERVICE_NAME

${GREEN}Useful Commands:${NC}
  View logs:        journalctl -u $SERVICE_NAME -f
  Check status:     systemctl status $SERVICE_NAME
  Stop agent:       sudo systemctl stop $SERVICE_NAME
  Start agent:      sudo systemctl start $SERVICE_NAME
  Restart agent:    sudo systemctl restart $SERVICE_NAME
  Remove service:   sudo systemctl disable $SERVICE_NAME && sudo systemctl stop $SERVICE_NAME

${GREEN}Next Steps:${NC}
  1. Verify logs: journalctl -u $SERVICE_NAME -n 20
  2. Check backend connectivity: curl -H "X-Agent-Id: $AGENT_ID" $BACKEND_URL/stats
  3. Monitor events: curl $BACKEND_URL/events?agent_id=$AGENT_ID

For detailed documentation, see: $INSTALL_DIR/docs/ARCHITECTURE.md

EOF
}

print_env_warning() {
    cat << EOF

${YELLOW}========================================
Environment Configuration
========================================${NC}

To connect to a different backend, edit: $INSTALL_DIR/.env
Then restart the service:

  sudo systemctl restart $SERVICE_NAME

Current backend: $BACKEND_URL

EOF
}

################################################################################
# Main Installation Flow
################################################################################

main() {
    echo "=========================================="
    echo "AI Bouncer Agent Installer"
    echo "=========================================="
    echo ""
    
    check_root
    check_os
    
    log_info "Backend URL: $BACKEND_URL"
    log_info "Install directory: $INSTALL_DIR"
    echo ""
    
    install_dependencies
    create_agent_directory
    clone_or_update_repo
    setup_python_env
    generate_agent_id
    create_env_file
    create_agent_user
    create_systemd_service
    start_service
    
    echo ""
    print_summary
    print_env_warning
}

# Run main function
main
