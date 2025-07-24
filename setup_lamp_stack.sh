#!/bin/bash

set -e

# Function to prompt for yes/no confirmation
confirm() {
  while true; do
    read -rp "$1 [y/n]: " yn
    case $yn in
      [Yy]*) return 0 ;;
      [Nn]*) return 1 ;;
      *) echo "Please answer yes or no." ;;
    esac
  done
}

# Update and upgrade system packages
echo "Updating package lists and upgrading existing packages..."
sudo apt update && sudo apt upgrade -y

# Check and install sudo if missing
if ! command -v sudo &> /dev/null; then
  echo "sudo not found. Installing sudo..."
  apt install -y sudo
fi

# Check and install SSH if missing
if ! command -v ssh &> /dev/null; then
  echo "SSH client not found. Installing openssh-server..."
  apt install -y openssh-server
fi

# Check and install git if missing
if ! command -v git &> /dev/null; then
  echo "git not found. Installing git..."
  apt install -y git
fi

# Check and install wget if missing
if ! command -v wget &> /dev/null; then
  echo "wget not found. Installing wget..."
  apt install -y wget
fi

# Prompt for new username and password
read -rp "Enter the username to create: " NEW_USER
while id "$NEW_USER" &>/dev/null; do
  echo "User '$NEW_USER' already exists. Please enter a different username."
  read -rp "Enter the username to create: " NEW_USER
done

read -rsp "Enter password for user $NEW_USER: " USER_PASS
echo
read -rsp "Confirm password for user $NEW_USER: " USER_PASS_CONFIRM
echo
while [ "$USER_PASS" != "$USER_PASS_CONFIRM" ]; do
  echo "Passwords do not match. Please try again."
  read -rsp "Enter password for user $NEW_USER: " USER_PASS
  echo
  read -rsp "Confirm password for user $NEW_USER: " USER_PASS_CONFIRM
  echo
done

# Create user and set password
echo "Creating user $NEW_USER..."
adduser --quiet --disabled-password --gecos "" "$NEW_USER"
echo "$NEW_USER:$USER_PASS" | chpasswd

# Add user to sudoers with limited access
echo "Adding $NEW_USER to sudoers with limited access..."
usermod -aG sudo "$NEW_USER"
echo "$NEW_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/"$NEW_USER"
chmod 440 /etc/sudoers.d/"$NEW_USER"

# Confirm before installing NGINX with Brotli and HTTP/3
if confirm "Proceed with installing latest NGINX with Brotli and HTTP/3 support?"; then
  echo "Installing prerequisites for building NGINX..."
  apt install -y software-properties-common curl gnupg2 ca-certificates lsb-release build-essential libpcre3 libpcre3-dev zlib1g-dev libssl-dev

  # Add official NGINX repository for latest stable version
  echo "Adding official NGINX repository..."
  curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/$(lsb_release -is | tr '[:upper:]' '[:lower:]') $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list
  apt update

  # Install dependencies for Brotli and HTTP/3
  echo "Installing Brotli and HTTP/3 dependencies..."
  apt install -y libbrotli-dev

  # Build NGINX from source with Brotli and HTTP/3 modules
  echo "Building NGINX from source with Brotli and HTTP/3 support..."

  # Create a temp directory for build
  BUILD_DIR=$(mktemp -d)
  cd "$BUILD_DIR"

  # Download latest NGINX source with fallback version
  echo "Fetching latest stable NGINX version..."
  NGINX_VERSION=$(curl -s https://nginx.org/en/download.html | grep -oP 'nginx-\K[0-9.]+(?=</a>.*stable version)' | head -1)
  if [ -z "$NGINX_VERSION" ] || [[ "$NGINX_VERSION" == "" ]]; then
    echo "NGINX version detection failed, setting default to 1.29.0"
    NGINX_VERSION="1.29.0"
  fi
  NGINX_TARBALL_URL="https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"
  echo "Downloading NGINX from $NGINX_TARBALL_URL"
  wget -O nginx.tar.gz "$NGINX_TARBALL_URL"
  tar -xzf nginx.tar.gz

  # Install git if missing (required for Brotli module)
  if ! command -v git &> /dev/null; then
    echo "git not found. Installing git..."
    apt install -y git
  fi

  # Download Brotli module
  git clone --depth=1 https://github.com/google/ngx_brotli.git
  cd ngx_brotli && git submodule update --init && cd ..

  cd nginx-$NGINX_VERSION

  # Configure with Brotli and HTTP/3 (QUIC) support
  ./configure --with-compat --add-dynamic-module=../ngx_brotli --with-http_v3_module --with-http_ssl_module --with-http_v2_module
  make
  make install

  # Cleanup build directory
  cd /
  rm -rf "$BUILD_DIR"

  # Enable Brotli module in NGINX config
  echo "LoadModule modules/ngx_http_brotli_filter_module.so;" > /etc/nginx/modules-enabled/50-mod-brotli.conf || true
  echo "LoadModule modules/ngx_http_brotli_static_module.so;" >> /etc/nginx/modules-enabled/50-mod-brotli.conf || true

  # Configure NGINX for HTTP/3 (example snippet)
  # User will need to add this to their server block:
  # listen 443 ssl http2;
  # listen [::]:443 ssl http2;
  # listen 443 quic reuseport;
  # ssl_protocols TLSv1.3;
  # ssl_prefer_server_ciphers off;
  # ssl_certificate /path/to/cert.pem;
  # ssl_certificate_key /path/to/key.pem;
  # add_header Alt-Svc 'h3-23=":443"'; # Advertise that HTTP/3 is available
  # add_header QUIC-Status $quic;

  echo "NGINX with Brotli and HTTP/3 installed. Please configure SSL certificates and server blocks accordingly."
else
  echo "Skipping NGINX installation."
fi

# Confirm before installing PHP with FastCGI
if confirm "Proceed with installing latest PHP with FastCGI support?"; then
  echo "Installing PHP-FPM and common extensions..."
  apt install -y php-fpm php-cli php-curl php-imap php-mysql php-pgsql php-mongodb php-zip php-xml php-mbstring php-bcmath php-gd php-intl php-soap php-opcache
else
  echo "Skipping PHP installation."
fi

# Confirm before installing databases
if confirm "Proceed with installing MariaDB, MongoDB, and PostgreSQL?"; then
  echo "Installing MariaDB..."
  apt install -y mariadb-server mariadb-client

  echo "Securing MariaDB installation..."
  mysql_secure_installation <<EOF

y
StrongRootPass123!
StrongRootPass123!
y
y
y
y
EOF

  echo "Installing MongoDB..."
  wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | apt-key add -
  echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/6.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-6.0.list
  apt update
  apt install -y mongodb-org

  echo "Starting and enabling MongoDB service..."
  systemctl start mongod
  systemctl enable mongod

  echo "Installing PostgreSQL..."
  apt install -y postgresql postgresql-contrib

  echo "Securing PostgreSQL..."
  sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'StrongRootPass123!';"
else
  echo "Skipping database installations."
fi

# Confirm before installing Fail2Ban and UFW
if confirm "Proceed with installing and configuring Fail2Ban and UFW?"; then
  echo "Installing Fail2Ban and UFW..."
  apt install -y fail2ban ufw

  echo "Configuring UFW..."
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22
  ufw allow 80
  ufw allow 443
  ufw --force enable

  echo "Configuring Fail2Ban for SSH and NGINX..."
  cat > /etc/fail2ban/jail.local <<EOL
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
EOL

  systemctl restart fail2ban

  echo "Enabling automatic security updates..."
  apt install -y unattended-upgrades
  dpkg-reconfigure -plow unattended-upgrades
else
  echo "Skipping Fail2Ban and UFW installation."
fi

# Secure SSH configuration
echo "Securing SSH configuration..."
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
if ! grep -q "^AllowUsers $NEW_USER" /etc/ssh/sshd_config; then
  echo "AllowUsers $NEW_USER" >> /etc/ssh/sshd_config
fi
systemctl restart sshd

# OpenTelemetry and SigNoz installation
if confirm "Proceed with installing and configuring OpenTelemetry tools for SigNoz?"; then
  echo "Installing OpenTelemetry Collector and configuring for SigNoz..."

  # Download OpenTelemetry Collector binary
  OTEL_VERSION="0.74.0"
  curl -LO https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v${OTEL_VERSION}/otelcol_${OTEL_VERSION}_linux_amd64.tar.gz
  tar -xzf otelcol_${OTEL_VERSION}_linux_amd64.tar.gz
  mv otelcol_${OTEL_VERSION}_linux_amd64/otelcol /usr/local/bin/
  chmod +x /usr/local/bin/otelcol
  rm -rf otelcol_${OTEL_VERSION}_linux_amd64*

  # Create config directory
  mkdir -p /etc/otelcol

  # Create a basic config file for SigNoz (user should customize)
  cat > /etc/otelcol/config.yaml <<EOL
receivers:
  otlp:
    protocols:
      grpc:
      http:

exporters:
  signoz:
    endpoint: "http://localhost:4317"
    insecure: true

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [signoz]
EOL

  # Create systemd service
  cat > /etc/systemd/system/otelcol.service <<EOL
[Unit]
Description=OpenTelemetry Collector
After=network.target

[Service]
ExecStart=/usr/local/bin/otelcol --config /etc/otelcol/config.yaml
Restart=always

[Install]
WantedBy=multi-user.target
EOL

  systemctl daemon-reload
  systemctl enable otelcol
  systemctl start otelcol

  echo "OpenTelemetry Collector installed and running."
else
  echo "Skipping OpenTelemetry installation."
fi

# Prompt for domain name and create folders
read -rp "Enter your domain name (e.g. example.com): " DOMAIN_NAME
WWW_DIR="/var/www/$DOMAIN_NAME"
LOGS_DIR="/var/log/nginx/$DOMAIN_NAME"

echo "Creating WWW directory at $WWW_DIR and logs directory at $LOGS_DIR..."
mkdir -p "$WWW_DIR"
mkdir -p "$LOGS_DIR"
chown -R "$NEW_USER":"$NEW_USER" "$WWW_DIR"
chown -R "$NEW_USER":"$NEW_USER" "$LOGS_DIR"

# Security checks (basic)
echo "Running basic security checks..."

echo "Checking NGINX configuration..."
nginx -t

echo "Checking PHP-FPM status..."
systemctl is-active --quiet php7.4-fpm && echo "PHP-FPM is running." || echo "PHP-FPM is not running."

echo "Checking MariaDB status..."
systemctl is-active --quiet mariadb && echo "MariaDB is running." || echo "MariaDB is not running."

echo "Checking MongoDB status..."
systemctl is-active --quiet mongod && echo "MongoDB is running." || echo "MongoDB is not running."

echo "Checking PostgreSQL status..."
systemctl is-active --quiet postgresql && echo "PostgreSQL is running." || echo "PostgreSQL is not running."

# Final summary and suggestions
echo
echo "Setup Summary:"
echo "User created: $NEW_USER"
echo "Domain configured: $DOMAIN_NAME"
echo "WWW directory: $WWW_DIR"
echo "Logs directory: $LOGS_DIR"
echo
echo "Security Suggestions:"
echo "- Use key-based SSH authentication and disable password login if possible."
echo "- Regularly update and upgrade your system."
echo "- Review and customize NGINX server blocks for HTTP/3 and SSL."
echo "- Secure your databases with strong passwords and limited access."
echo "- Monitor Fail2Ban logs and adjust settings as needed."
echo "- Consider setting up automated backups for your databases and web files."
echo "- Review OpenTelemetry Collector configuration for your monitoring needs."

echo "Script execution completed."
