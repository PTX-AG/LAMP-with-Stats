# LAMP Stack Setup Script

This Bash script automates the installation and configuration of a secure LAMP stack environment on Ubuntu and Debian systems. It includes:

- System update and upgrade
- User creation with sudo access
- Installation of latest NGINX with Brotli and HTTP/3 support
- Installation of PHP with FastCGI and common extensions
- Installation and securing of MariaDB, MongoDB, and PostgreSQL
- Installation and configuration of Fail2Ban and UFW for security
- SSH hardening (disable root login, restrict users)
- Installation and configuration of OpenTelemetry Collector for SigNoz monitoring
- Domain setup with WWW and logs directories
- Basic security checks and suggestions

## Usage

Run the script with root privileges:

```bash
sudo bash setup_lamp_stack.sh
```

The script will prompt for necessary inputs and confirmations at key steps.

## Notes

- SSL certificates and NGINX server blocks for HTTP/3 need to be configured manually.
- Passwords used in the script should be changed to secure values.
- Review and customize OpenTelemetry Collector configuration as needed.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
