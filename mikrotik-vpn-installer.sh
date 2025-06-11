# Create additional utility scripts for management
create_management_utility_scripts() {
    # Performance monitoring script
    cat << 'EOF' > "$SCRIPT_DIR/monitor-performance.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                Performance Monitoring Dashboard               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

# Function to format bytes
format_bytes() {
    local bytes=$1
    if [[ $bytes -ge 1073741824 ]]; then
        echo "$(awk "BEGIN {printf \"%.2f\", $bytes/1073741824}") GB"
    elif [[ $bytes -ge 1048576 ]]; then
        echo "$(awk "BEGIN {printf \"%.2f\", $bytes/1048576}") MB"
    else
        echo "$(awk "BEGIN {printf \"%.2f\", $bytes/1024}") KB"
    fi
}

while true; do
    clear
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                Performance Monitoring Dashboard               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo "Time: $(date)"
    echo

    # CPU Usage
    echo "CPU Performance"
    echo "═════════════"
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    echo "Usage: $cpu_usage%"
    echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
    echo

    # Memory Usage
    echo "Memory Usage"
    echo "══════════"
    free -h | grep -E "Mem:|Swap:"
    echo

    # Disk Usage
    echo "Disk Usage"
    echo "════════"
    df -h / | grep -v Filesystem
    echo

    # Docker Container Stats
    echo "Container Resource Usage"
    echo "═════════════════════"
    docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" | grep mikrotik
    echo

    # Network Traffic
    echo "Network Traffic (last 5 seconds)"
    echo "═════════════════════════════"
    
    # Get initial network stats
    rx1=$(cat /sys/class/net/eth0/statistics/rx_bytes 2>/dev/null || cat /sys/class/net/ens33/statistics/rx_bytes 2>/dev/null || echo 0)
    tx1=$(cat /sys/class/net/eth0/statistics/tx_bytes 2>/dev/null || cat /sys/class/net/ens33/statistics/tx_bytes 2>/dev/null || echo 0)
    
    sleep 5
    
    # Get final network stats
    rx2=$(cat /sys/class/net/eth0/statistics/rx_bytes 2>/dev/null || cat /sys/class/net/ens33/statistics/rx_bytes 2>/dev/null || echo 0)
    tx2=$(cat /sys/class/net/eth0/statistics/tx_bytes 2>/dev/null || cat /sys/class/net/ens33/statistics/tx_bytes 2>/dev/null || echo 0)
    
    # Calculate rates
    rx_rate=$((($rx2 - $rx1) / 5))
    tx_rate=$((($tx2 - $tx1) / 5))
    
    echo "Download: $(format_bytes $rx_rate)/s"
    echo "Upload: $(format_bytes $tx_rate)/s"
    echo

    # Active Connections
    echo "Active Connections"
    echo "════════════════"
    echo "Total connections: $(netstat -an | grep ESTABLISHED | wc -l)"
    echo "MongoDB connections: $(netstat -an | grep :27017 | grep ESTABLISHED | wc -l)"
    echo "Redis connections: $(netstat -an | grep :6379 | grep ESTABLISHED | wc -l)"
    echo "VPN connections: $(docker exec mikrotik-openvpn cat /var/log/openvpn-status.log 2>/dev/null | grep -c CLIENT_LIST || echo 0)"
    echo

    echo "Press Ctrl+C to exit, refreshing in 10 seconds..."
    sleep 5
done
EOF

    # Database maintenance script
    cat << 'EOF' > "$SCRIPT_DIR/maintain-database.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                  Database Maintenance Utility                 ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

echo "1. Compact MongoDB database"
echo "2. Clean old session data"
echo "3. Optimize MongoDB indexes"
echo "4. Clean Redis expired keys"
echo "5. Database statistics report"
echo "6. Exit"
echo

read -p "Select option (1-6): " choice

case $choice in
    1)
        echo
        echo "Compacting MongoDB database..."
        docker exec mikrotik-mongodb mongosh \
            -u admin -p "$MONGO_ROOT_PASSWORD" \
            --authenticationDatabase admin \
            --eval "
            db = db.getSiblingDB('mikrotik_vpn');
            db.runCommand({ compact: 'devices' });
            db.runCommand({ compact: 'users' });
            db.runCommand({ compact: 'vouchers' });
            db.runCommand({ compact: 'sessions' });
            db.runCommand({ compact: 'logs' });
            print('Database compaction completed');
            "
        ;;
        
    2)
        echo
        echo "Cleaning old session data..."
        read -p "Delete sessions older than (days, default 30): " days
        days=${days:-30}
        
        docker exec mikrotik-mongodb mongosh \
            -u admin -p "$MONGO_ROOT_PASSWORD" \
            --authenticationDatabase admin \
            --eval "
            db = db.getSiblingDB('mikrotik_vpn');
            var cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - $days);
            var result = db.sessions.deleteMany({ start_time: { \$lt: cutoffDate } });
            print('Deleted ' + result.deletedCount + ' old sessions');
            
            result = db.logs.deleteMany({ timestamp: { \$lt: cutoffDate } });
            print('Deleted ' + result.deletedCount + ' old log entries');
            "
        ;;
        
    3)
        echo
        echo "Optimizing MongoDB indexes..."
        docker exec mikrotik-mongodb mongosh \
            -u admin -p "$MONGO_ROOT_PASSWORD" \
            --authenticationDatabase admin \
            --eval "
            db = db.getSiblingDB('mikrotik_vpn');
            
            print('Rebuilding indexes...');
            db.devices.reIndex();
            db.users.reIndex();
            db.vouchers.reIndex();
            db.sessions.reIndex();
            db.logs.reIndex();
            
            print('Index optimization completed');
            "
        ;;
        
    4)
        echo
        echo "Cleaning Redis expired keys..."
        docker exec mikrotik-redis redis-cli --pass "$REDIS_PASSWORD" <<< "
        DBSIZE
        SCRIPT FLUSH
        MEMORY PURGE
        DBSIZE
        "
        echo "Redis cleanup completed"
        ;;
        
    5)
        echo
        echo "Database Statistics Report"
        echo "═════════════════════════"
        
        # MongoDB stats
        docker exec mikrotik-mongodb mongosh \
            -u admin -p "$MONGO_ROOT_PASSWORD" \
            --authenticationDatabase admin \
            --eval "
            db = db.getSiblingDB('mikrotik_vpn');
            var stats = db.stats();
            
            print('MongoDB Statistics:');
            print('─────────────────');
            print('Database size: ' + (stats.dataSize / 1024 / 1024).toFixed(2) + ' MB');
            print('Storage size: ' + (stats.storageSize / 1024 / 1024).toFixed(2) + ' MB');
            print('Index size: ' + (stats.indexSize / 1024 / 1024).toFixed(2) + ' MB');
            print('Collections: ' + stats.collections);
            print('Indexes: ' + stats.indexes);
            print('');
            
            print('Collection statistics:');
            db.getCollectionNames().forEach(function(col) {
                var colStats = db[col].stats();
                var count = db[col].countDocuments();
                print('  ' + col + ':');
                print('    Documents: ' + count);
                print('    Size: ' + (colStats.size / 1024).toFixed(2) + ' KB');
                print('    Avg doc size: ' + (count > 0 ? (colStats.avgObjSize / 1024).toFixed(2) : 0) + ' KB');
            });
            "
            
        echo
        echo "Redis Statistics:"
        echo "────────────────"
        docker exec mikrotik-redis redis-cli --pass "$REDIS_PASSWORD" INFO memory | grep -E "used_memory_human:|used_memory_peak_human:|used_memory_dataset:"
        ;;
        
    6)
        exit 0
        ;;
        
    *)
        echo "Invalid option"
        ;;
esac
EOF

    # VPN user management script
    cat << 'EOF' > "$SCRIPT_DIR/manage-vpn-users.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    VPN User Management                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

show_menu() {
    echo "1. List all VPN users"
    echo "2. Create new VPN user"
    echo "3. Revoke VPN user"
    echo "4. Show user details"
    echo "5. Export user config"
    echo "6. Bulk create users"
    echo "7. Exit"
    echo
}

list_vpn_users() {
    echo "Configured VPN Users:"
    echo "═══════════════════"
    
    if docker exec mikrotik-openvpn test -d /etc/openvpn/easy-rsa/pki/issued 2>/dev/null; then
        docker exec mikrotik-openvpn ls -1 /etc/openvpn/easy-rsa/pki/issued/ | grep -v server.crt | sed 's/.crt$//'
    else
        echo "No PKI found. Initialize OpenVPN first."
    fi
}

create_vpn_user() {
    read -p "Enter username: " username
    
    if [[ ! $username =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "Invalid username. Use only letters, numbers, hyphens, and underscores."
        return
    fi
    
    # Check if user already exists
    if docker exec mikrotik-openvpn test -f /etc/openvpn/easy-rsa/pki/issued/$username.crt 2>/dev/null; then
        echo "User $username already exists!"
        return
    fi
    
    echo "Creating VPN user: $username"
    $SCRIPT_DIR/create-vpn-client.sh <<< "$username"
}

revoke_vpn_user() {
    read -p "Enter username to revoke: " username
    
    if ! docker exec mikrotik-openvpn test -f /etc/openvpn/easy-rsa/pki/issued/$username.crt 2>/dev/null; then
        echo "User $username not found!"
        return
    fi
    
    read -p "Are you sure you want to revoke $username? (yes/no): " confirm
    if [[ $confirm != "yes" ]]; then
        echo "Revocation cancelled"
        return
    fi
    
    docker exec mikrotik-openvpn bash -c "
        cd /etc/openvpn/easy-rsa
        ./easyrsa --batch revoke $username
        ./easyrsa gen-crl
        cp pki/crl.pem /etc/openvpn/
    "
    
    # Remove client config
    rm -f /opt/mikrotik-vpn/clients/$username.ovpn
    
    echo "User $username has been revoked"
}

show_user_details() {
    read -p "Enter username: " username
    
    if ! docker exec mikrotik-openvpn test -f /etc/openvpn/easy-rsa/pki/issued/$username.crt 2>/dev/null; then
        echo "User $username not found!"
        return
    fi
    
    echo
    echo "User Details: $username"
    echo "═══════════════════════"
    
    # Certificate details
    docker exec mikrotik-openvpn openssl x509 -in /etc/openvpn/easy-rsa/pki/issued/$username.crt -noout -subject -dates
    
    # Check if config exists
    if [[ -f /opt/mikrotik-vpn/clients/$username.ovpn ]]; then
        echo "Config file: /opt/mikrotik-vpn/clients/$username.ovpn"
        echo "File size: $(ls -lh /opt/mikrotik-vpn/clients/$username.ovpn | awk '{print $5}')"
    else
        echo "Config file: Not found"
    fi
    
    # Check if currently connected
    if docker exec mikrotik-openvpn grep -q "^$username," /var/log/openvpn-status.log 2>/dev/null; then
        echo "Status: Connected"
        docker exec mikrotik-openvpn grep "^$username," /var/log/openvpn-status.log | awk -F',' '{print "  IP: "$3"\n  Connected since: "$8}'
    else
        echo "Status: Not connected"
    fi
}

export_user_config() {
    read -p "Enter username: " username
    
    if [[ ! -f /opt/mikrotik-vpn/clients/$username.ovpn ]]; then
        echo "Config file not found for user: $username"
        return
    fi
    
    read -p "Export to directory (default: /tmp): " export_dir
    export_dir=${export_dir:-/tmp}
    
    if [[ ! -d $export_dir ]]; then
        echo "Directory not found: $export_dir"
        return
    fi
    
    cp /opt/mikrotik-vpn/clients/$username.ovpn $export_dir/
    echo "Config exported to: $export_dir/$username.ovpn"
}

bulk_create_users() {
    echo "Bulk User Creation"
    echo "════════════════"
    echo "Enter usernames (one per line, empty line to finish):"
    
    users=()
    while true; do
        read -p "> " username
        [[ -z "$username" ]] && break
        
        if [[ ! $username =~ ^[a-zA-Z0-9_-]+$ ]]; then
            echo "Invalid username: $username (skipping)"
            continue
        fi
        
        users+=("$username")
    done
    
    if [[ ${#users[@]} -eq 0 ]]; then
        echo "No users to create"
        return
    fi
    
    echo
    echo "Creating ${#users[@]} users..."
    
    for username in "${users[@]}"; do
        echo -n "Creating $username... "
        if docker exec mikrotik-openvpn test -f /etc/openvpn/easy-rsa/pki/issued/$username.crt 2>/dev/null; then
            echo "already exists (skipping)"
        else
            $SCRIPT_DIR/create-vpn-client.sh <<< "$username" >/dev/null 2>&1
            echo "done"
        fi
    done
    
    echo
    echo "Bulk creation completed!"
}

# Main menu loop
while true; do
    echo
    show_menu
    read -p "Select option (1-7): " choice
    
    case $choice in
        1) list_vpn_users ;;
        2) create_vpn_user ;;
        3) revoke_vpn_user ;;
        4) show_user_details ;;
        5) export_user_config ;;
        6) bulk_create_users ;;
        7) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
    
    echo
    read -p "Press Enter to continue..."
done
EOF

    # Container management script
    cat << 'EOF' > "$SCRIPT_DIR/manage-containers.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                   Container Management                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

show_menu() {
    echo "1. Show container status"
    echo "2. Restart specific container"
    echo "3. View container logs"
    echo "4. Execute command in container"
    echo "5. Update container images"
    echo "6. Clean unused resources"
    echo "7. Container resource limits"
    echo "8. Exit"
    echo
}

show_container_status() {
    echo "Container Status"
    echo "═══════════════"
    docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Size}}" | grep mikrotik
    
    echo
    echo "Container Health"
    echo "═══════════════"
    for container in $(docker ps --format "{{.Names}}" | grep mikrotik); do
        health=$(docker inspect --format='{{.State.Health.Status}}' $container 2>/dev/null || echo "none")
        echo "$container: $health"
    done
}

restart_container() {
    echo "Available containers:"
    docker ps -a --format "{{.Names}}" | grep mikrotik | nl
    
    read -p "Select container number: " num
    container=$(docker ps -a --format "{{.Names}}" | grep mikrotik | sed -n "${num}p")
    
    if [[ -z "$container" ]]; then
        echo "Invalid selection"
        return
    fi
    
    echo "Restarting $container..."
    docker restart $container
    
    # Wait for health check
    echo -n "Waiting for container to be healthy"
    for i in {1..30}; do
        if docker ps | grep -q $container; then
            echo -n "."
            sleep 1
        else
            echo " Failed!"
            return
        fi
    done
    echo " OK!"
}

view_container_logs() {
    echo "Available containers:"
    docker ps -a --format "{{.Names}}" | grep mikrotik | nl
    
    read -p "Select container number: " num
    container=$(docker ps -a --format "{{.Names}}" | grep mikrotik | sed -n "${num}p")
    
    if [[ -z "$container" ]]; then
        echo "Invalid selection"
        return
    fi
    
    read -p "Number of lines to show (default 100): " lines
    lines=${lines:-100}
    
    echo
    echo "Logs for $container (last $lines lines):"
    echo "════════════════════════════════════════"
    docker logs --tail $lines $container
}

execute_in_container() {
    echo "Available containers:"
    docker ps --format "{{.Names}}" | grep mikrotik | nl
    
    read -p "Select container number: " num
    container=$(docker ps --format "{{.Names}}" | grep mikrotik | sed -n "${num}p")
    
    if [[ -z "$container" ]]; then
        echo "Invalid selection"
        return
    fi
    
    read -p "Enter command to execute: " command
    
    echo
    echo "Executing in $container: $command"
    echo "═══════════════════════════════"
    docker exec -it $container $command
}

update_container_images() {
    echo "Updating container images..."
    echo "══════════════════════════"
    
    cd /opt/mikrotik-vpn || exit 1
    
    # Pull latest images
    docker compose pull
    
    echo
    read -p "Restart containers with new images? (y/n): " restart
    
    if [[ $restart == "y" ]]; then
        docker compose up -d
        echo "Containers restarted with updated images"
    else
        echo "Images updated. Restart manually when ready."
    fi
}

clean_unused_resources() {
    echo "Docker Resource Usage"
    echo "═══════════════════"
    docker system df
    
    echo
    echo "This will remove:"
    echo "• Stopped containers"
    echo "• Unused networks"
    echo "• Dangling images"
    echo "• Build cache"
    echo
    
    read -p "Continue with cleanup? (y/n): " confirm
    
    if [[ $confirm == "y" ]]; then
        docker system prune -af --volumes
        echo "Cleanup completed!"
        
        echo
        echo "New usage:"
        docker system df
    fi
}

container_resource_limits() {
    echo "Container Resource Limits"
    echo "═══════════════════════"
    
    for container in $(docker ps --format "{{.Names}}" | grep mikrotik); do
        echo
        echo "$container:"
        echo "─────────"
        
        # Get limits
        mem_limit=$(docker inspect $container --format='{{.HostConfig.Memory}}')
        cpu_quota=$(docker inspect $container --format='{{.HostConfig.CpuQuota}}')
        cpu_period=$(docker inspect $container --format='{{.HostConfig.CpuPeriod}}')
        
        if [[ $mem_limit -eq 0 ]]; then
            echo "  Memory: Unlimited"
        else
            echo "  Memory: $((mem_limit / 1024 / 1024)) MB"
        fi
        
        if [[ $cpu_quota -eq 0 ]]; then
            echo "  CPU: Unlimited"
        else
            cpu_limit=$(awk "BEGIN {printf \"%.2f\", $cpu_quota/$cpu_period}")
            echo "  CPU: $cpu_limit cores"
        fi
        
        # Current usage
        stats=$(docker stats --no-stream --format "{{.MemUsage}}\t{{.CPUPerc}}" $container)
        echo "  Current usage: $stats"
    done
}

# Main menu loop
while true; do
    echo
    show_menu
    read -p "Select option (1-8): " choice
    
    case $choice in
        1) show_container_status ;;
        2) restart_container ;;
        3) view_container_logs ;;
        4) execute_in_container ;;
        5) update_container_images ;;
        6) clean_unused_resources ;;
        7) container_resource_limits ;;
        8) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
    
    echo
    read -p "Press Enter to continue..."
done
EOF

    # Alerting configuration script
    cat << 'EOF' > "$SCRIPT_DIR/configure-alerts.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                   Alert Configuration                         ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

# Check if Alertmanager config exists
ALERT_CONFIG="/opt/mikrotik-vpn/monitoring/alertmanager/alertmanager.yml"

if [[ ! -f "$ALERT_CONFIG" ]]; then
    echo "Creating default Alertmanager configuration..."
    mkdir -p /opt/mikrotik-vpn/monitoring/alertmanager
    
    cat << 'ALERTCONFIG' > "$ALERT_CONFIG"
global:
  resolve_timeout: 5m
  smtp_from: 'alerts@mikrotik-vpn.local'
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_auth_username: ''
  smtp_auth_password: ''

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'default'
  routes:
    - match:
        severity: critical
      receiver: 'critical'
      continue: true

receivers:
  - name: 'default'
    email_configs:
      - to: ''
        headers:
          Subject: 'MikroTik VPN Alert: {{ .GroupLabels.alertname }}'

  - name: 'critical'
    email_configs:
      - to: ''
        headers:
          Subject: 'CRITICAL - MikroTik VPN: {{ .GroupLabels.alertname }}'
    webhook_configs:
      - url: 'http://app:3000/api/alerts'
        send_resolved: true

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'instance']
ALERTCONFIG
fi

echo "Current Alert Configuration"
echo "═════════════════════════"

# Read current config
smtp_host=$(grep smtp_smarthost "$ALERT_CONFIG" | awk -F"'" '{print $2}')
smtp_user=$(grep smtp_auth_username "$ALERT_CONFIG" | awk -F"'" '{print $2}')
email_to=$(grep -A2 "name: 'default'" "$ALERT_CONFIG" | grep "to:" | awk -F"'" '{print $2}')

echo "SMTP Host: ${smtp_host:-Not configured}"
echo "SMTP User: ${smtp_user:-Not configured}"
echo "Alert Email: ${email_to:-Not configured}"
echo

echo "1. Configure email alerts"
echo "2. Configure webhook alerts"
echo "3. Test alert configuration"
echo "4. View current alerts"
echo "5. Silence alerts"
echo "6. Exit"
echo

read -p "Select option (1-6): " choice

case $choice in
    1)
        echo
        echo "Email Alert Configuration"
        echo "───────────────────────"
        
        read -p "SMTP Server (e.g., smtp.gmail.com:587): " smtp_server
        read -p "SMTP Username: " smtp_username
        read -s -p "SMTP Password: " smtp_password
        echo
        read -p "Alert recipient email: " alert_email
        
        # Update configuration
        sed -i "s|smtp_smarthost:.*|smtp_smarthost: '$smtp_server'|" "$ALERT_CONFIG"
        sed -i "s|smtp_auth_username:.*|smtp_auth_username: '$smtp_username'|" "$ALERT_CONFIG"
        sed -i "s|smtp_auth_password:.*|smtp_auth_password: '$smtp_password'|" "$ALERT_CONFIG"
        sed -i "s|smtp_from:.*|smtp_from: '$smtp_username'|" "$ALERT_CONFIG"
        
        # Update receiver email
        sed -i "/name: 'default'/,/- name:/ s|to:.*|to: '$alert_email'|" "$ALERT_CONFIG"
        sed -i "/name: 'critical'/,/webhook_configs:/ s|to:.*|to: '$alert_email'|" "$ALERT_CONFIG"
        
        # Restart Alertmanager
        docker restart mikrotik-alertmanager 2>/dev/null || echo "Alertmanager not running"
        
        echo "Email alerts configured!"
        ;;
        
    2)
        echo
        echo "Webhook Alert Configuration"
        echo "─────────────────────────"
        
        read -p "Webhook URL: " webhook_url
        
        # Update webhook in config
        sed -i "s|url:.*|url: '$webhook_url'|" "$ALERT_CONFIG"
        
        # Restart Alertmanager
        docker restart mikrotik-alertmanager 2>/dev/null || echo "Alertmanager not running"
        
        echo "Webhook configured!"
        ;;
        
    3)
        echo
        echo "Sending test alert..."
        
        # Create test alert
        curl -XPOST http://localhost:9093/api/v1/alerts -H "Content-Type: application/json" -d '[
          {
            "labels": {
              "alertname": "TestAlert",
              "severity": "info",
              "instance": "test"
            },
            "annotations": {
              "summary": "This is a test alert",
              "description": "Testing MikroTik VPN alerting system"
            },
            "generatorURL": "http://localhost:9090/"
          }
        ]' 2>/dev/null
        
        echo "Test alert sent! Check your email/webhook endpoint."
        ;;
        
    4)
        echo
        echo "Current Active Alerts"
        echo "═══════════════════"
        
        alerts=$(curl -s http://localhost:9093/api/v1/alerts | jq -r '.[] | "\(.labels.alertname) - \(.labels.severity) - \(.status.state)"' 2>/dev/null)
        
        if [[ -z "$alerts" ]]; then
            echo "No active alerts"
        else
            echo "$alerts"
        fi
        ;;
        
    5)
        echo
        echo "Silence Alerts"
        echo "════════════"
        
        read -p "Duration in hours (default 2): " duration
        duration=${duration:-2}
        
        read -p "Comment: " comment
        
        # Create silence
        end_time=$(date -u -d "+${duration} hours" +"%Y-%m-%dT%H:%M:%S")
        
        curl -XPOST http://localhost:9093/api/v1/silences -H "Content-Type: application/json" -d "{
          \"matchers\": [
            {
              \"name\": \"alertname\",
              \"value\": \".*\",
              \"isRegex\": true
            }
          ],
          \"startsAt\": \"$(date -u +"%Y-%m-%dT%H:%M:%S")\",
          \"endsAt\": \"${end_time}\",
          \"createdBy\": \"admin\",
          \"comment\": \"${comment}\"
        }" 2>/dev/null
        
        echo "All alerts silenced for $duration hours"
        ;;
        
    6)
        exit 0
        ;;
        
    *)
        echo "Invalid option"
        ;;
esac
EOF

    chmod +x "$SCRIPT_DIR"/*.sh
}

# Create deployment helper scripts
create_deployment_scripts() {
    # Pre-deployment checklist script
    cat << 'EOF' > "$SCRIPT_DIR/pre-deployment-check.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                Pre-Deployment Checklist                       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

CHECKS_PASSED=0
CHECKS_FAILED=0

# Function to perform check
check() {
    local description=$1
    local command=$2
    
    echo -n "• $description... "
    
    if eval "$command" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
        return 1
    fi
}

echo "System Requirements"
echo "═════════════════"

check "Operating System (Ubuntu)" "[[ -f /etc/os-release ]] && grep -q Ubuntu /etc/os-release"
check "CPU cores (minimum 2)" "[[ $(nproc) -ge 2 ]]"
check "Memory (minimum 4GB)" "[[ $(free -m | awk '/^Mem:/{print $2}') -ge 4096 ]]"
check "Disk space (minimum 20GB)" "[[ $(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//') -ge 20 ]]"

echo
echo "Docker Environment"
echo "════════════════"

check "Docker installed" "command -v docker"
check "Docker running" "docker ps"
check "Docker Compose installed" "docker compose version"
check "Docker network exists" "docker network ls | grep -q mikrotik-vpn-net"

echo
echo "Services Status"
echo "═════════════"

check "MongoDB running" "docker ps | grep -q mikrotik-mongodb"
check "Redis running" "docker ps | grep -q mikrotik-redis"
check "Application running" "docker ps | grep -q mikrotik-app"
check "Nginx running" "docker ps | grep -q mikrotik-nginx"
check "OpenVPN running" "docker ps | grep -q mikrotik-openvpn"

echo
echo "Configuration Files"
echo "═════════════════"

check "Environment file exists" "[[ -f /opt/mikrotik-vpn/.env ]]"
check "Setup config exists" "[[ -f /opt/mikrotik-vpn/configs/setup.env ]]"
check "Docker Compose file exists" "[[ -f /opt/mikrotik-vpn/docker-compose.yml ]]"
check "SSL certificate exists" "[[ -f /opt/mikrotik-vpn/nginx/ssl/fullchain.pem ]]"

echo
echo "Network Connectivity"
echo "═════════════════"

check "Internet connectivity" "ping -c 1 8.8.8.8"
check "DNS resolution" "nslookup google.com"
check "HTTP port available" "! lsof -i :9080"
check "HTTPS port available" "! lsof -i :9443"
check "VPN port available" "! lsof -i :1194"

echo
echo "Security"
echo "══════"

check "Firewall configured" "command -v ufw && ufw status | grep -q active"
check "Fail2ban installed" "command -v fail2ban-client"
check "SSL certificate valid" "openssl x509 -checkend 86400 -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem"
check "Secure file permissions" "[[ $(stat -c %a /opt/mikrotik-vpn/configs/setup.env) == 600 ]]"#!/bin/bash
# =============================================================================
# MikroTik VPN Management System - Complete Installation Script
# Version: 5.0 - Fixed and Tested Edition
# Description: Enhanced installation with proper syntax and compatibility
# Compatible with: Ubuntu 22.04/24.04 LTS, WSL, Container environments
# =============================================================================

set -euo pipefail

# =============================================================================
# GLOBAL VARIABLES AND CONFIGURATION
# =============================================================================

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# System directories
SYSTEM_DIR="/opt/mikrotik-vpn"
LOG_DIR="/var/log/mikrotik-vpn"
BACKUP_DIR="/opt/mikrotik-vpn/backups"
SCRIPT_DIR="/opt/mikrotik-vpn/scripts"
CONFIG_DIR="/opt/mikrotik-vpn/configs"

# Log file
LOG_FILE="$LOG_DIR/installation.log"

# Temporary directory
TEMP_DIR="/tmp/mikrotik-vpn-install-$$"

# System resources
TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
MONGODB_CACHE_SIZE=$((TOTAL_MEM / 4 / 1024))
REDIS_MAX_MEM=$((TOTAL_MEM / 4))

# Environment detection flags
IS_WSL=false
IS_CONTAINER=false
NO_SYSTEMD=false

# =============================================================================
# INITIALIZATION
# =============================================================================

# Create necessary directories
mkdir -p "$LOG_DIR" "$TEMP_DIR"

# Logging functions
log() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${GREEN}${message}${NC}" | tee -a "$LOG_FILE"
}

log_error() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1"
    echo -e "${RED}${message}${NC}" | tee -a "$LOG_FILE"
}

log_warning() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1"
    echo -e "${YELLOW}${message}${NC}" | tee -a "$LOG_FILE"
}

log_info() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1"
    echo -e "${BLUE}${message}${NC}" | tee -a "$LOG_FILE"
}

# Error handler
error_handler() {
    local line_number=$1
    log_error "Script failed at line $line_number"
    log_error "Last command: $BASH_COMMAND"
    cleanup_on_error
    exit 1
}

trap 'error_handler $LINENO' ERR

# Cleanup on error
cleanup_on_error() {
    log_warning "Cleaning up after error..."
    cd /
    rm -rf "$TEMP_DIR" 2>/dev/null || true
    
    # If Docker was started manually, clean it up
    if [[ -f /var/run/docker-manual.pid ]]; then
        local docker_pid=$(cat /var/run/docker-manual.pid)
        kill $docker_pid 2>/dev/null || true
        rm -f /var/run/docker-manual.pid
    fi
}

# Check root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect environment
detect_environment() {
    log "Detecting environment..."
    
    # Check if in WSL
    if grep -qi microsoft /proc/version 2>/dev/null; then
        IS_WSL=true
        log_warning "WSL environment detected"
    fi
    
    # Check if in container
    if [[ -f /.dockerenv ]]; then
        IS_CONTAINER=true
        log_warning "Container environment detected"
    fi
    
    # Check systemd
    if ! systemctl is-system-running &>/dev/null; then
        NO_SYSTEMD=true
        log_warning "systemd is not running or not available"
    fi
    
    # Export flags
    export IS_WSL
    export IS_CONTAINER
    export NO_SYSTEMD
}

# Enhanced Docker fix for all environments
fix_docker_universal() {
    log "Applying universal Docker fixes..."
    
    # Stop any existing Docker processes
    pkill -f dockerd 2>/dev/null || true
    pkill -f containerd 2>/dev/null || true
    sleep 2
    
    # Clean up Docker artifacts
    rm -rf /var/run/docker.sock 2>/dev/null || true
    rm -rf /var/run/docker.pid 2>/dev/null || true
    rm -rf /var/run/docker/ 2>/dev/null || true
    rm -rf /var/lib/docker/network/files/local-kv.db 2>/dev/null || true
    
    # Ensure Docker directories exist
    mkdir -p /etc/docker
    mkdir -p /var/lib/docker
    
    # Create optimized Docker daemon configuration
    cat << 'EOF' > /etc/docker/daemon.json
{
  "storage-driver": "overlay2",
  "storage-opts": [
    "overlay2.override_kernel_check=true"
  ],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  },
  "dns": ["8.8.8.8", "8.8.4.4"],
  "live-restore": true,
  "userland-proxy": false,
  "ip-forward": true,
  "iptables": true,
  "ipv6": false,
  "bip": "172.17.0.1/16",
  "exec-opts": ["native.cgroupdriver=cgroupfs"],
  "cgroup-parent": ""
}
EOF

    # Load necessary kernel modules
    log "Loading kernel modules..."
    local modules="ip_tables iptable_filter iptable_nat nf_nat nf_conntrack br_netfilter overlay"
    for module in $modules; do
        if ! lsmod | grep -q "^$module"; then
            modprobe $module 2>/dev/null || log_info "Module $module not available (not critical)"
        fi
    done
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    
    # Fix iptables for Docker
    if command -v update-alternatives &> /dev/null; then
        if [[ -f /usr/sbin/iptables-legacy ]]; then
            update-alternatives --set iptables /usr/sbin/iptables-legacy 2>/dev/null || true
            update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy 2>/dev/null || true
        fi
    fi
}

# Start Docker based on environment
start_docker_smart() {
    log "Starting Docker service..."
    
    # Method 1: Try systemd if available
    if [[ "$NO_SYSTEMD" != "true" ]]; then
        log_info "Attempting to start Docker with systemd..."
        if systemctl start docker 2>/dev/null; then
            log "Docker started successfully with systemd"
            systemctl enable docker 2>/dev/null || true
            return 0
        fi
    fi
    
    # Method 2: Try service command
    if command -v service &> /dev/null; then
        log_info "Attempting to start Docker with service command..."
        if service docker start 2>/dev/null; then
            log "Docker started successfully with service command"
            return 0
        fi
    fi
    
    # Method 3: Start Docker manually
    log_info "Starting Docker manually..."
    
    # Start containerd first if available
    if command -v containerd &> /dev/null; then
        containerd > /var/log/containerd.log 2>&1 &
        sleep 2
    fi
    
    # Determine Docker daemon startup command
    local docker_cmd="dockerd"
    
    # Add special options for WSL/Container environments
    if [[ "$IS_WSL" == "true" ]] || [[ "$IS_CONTAINER" == "true" ]]; then
        docker_cmd="dockerd --iptables=false"
    fi
    
    # Start Docker daemon
    $docker_cmd > /var/log/docker-manual.log 2>&1 &
    local docker_pid=$!
    echo $docker_pid > /var/run/docker-manual.pid
    
    # Wait for Docker to start
    local count=0
    while [[ $count -lt 30 ]]; do
        if docker version &>/dev/null; then
            log "Docker daemon started successfully (PID: $docker_pid)"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    
    # If failed, show error
    log_error "Docker failed to start after 30 seconds"
    cat /var/log/docker-manual.log | tail -20 >> "$LOG_FILE"
    return 1
}

# Create or check docker network
create_docker_network() {
    if ! docker network ls --format '{{.Name}}' | grep -q "^mikrotik-vpn-net$"; then
        log "Creating Docker network..."
        docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16
    else
        log "Docker network already exists"
    fi
}

# Print header
print_header() {
    clear
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║        MikroTik VPN Management System - Installation v5.0                 ║
║                                                                           ║
║                 Universal Environment Fix & Installation                  ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    echo
}

# =============================================================================
# PHASE 0: SYSTEM DETECTION AND PREPARATION
# =============================================================================

phase0_system_detection() {
    log "==================================================================="
    log "PHASE 0: SYSTEM DETECTION AND PREPARATION"
    log "==================================================================="
    
    # Detect environment first
    detect_environment
    
    # Detect OS
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        log_error "Cannot detect OS version"
        exit 1
    fi
    
    log "Detected OS: $OS $VER"
    log "Environment flags:"
    log "  WSL: $IS_WSL"
    log "  Container: $IS_CONTAINER"
    log "  No systemd: $NO_SYSTEMD"
    
    # Check Ubuntu version
    if [[ ! "$OS" =~ "Ubuntu" ]] || [[ ! "$VER" =~ ^(22.04|24.04)$ ]]; then
        log_warning "This script is optimized for Ubuntu 22.04 or 24.04 LTS"
        log_warning "Proceeding anyway, but some features may not work correctly"
    fi
    
    # Check system resources
    CPU_CORES=$(nproc)
    TOTAL_DISK=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    
    log "System Resources:"
    log "  CPU Cores: $CPU_CORES"
    log "  Total Memory: ${TOTAL_MEM}MB"
    log "  Available Disk: ${TOTAL_DISK}GB"
    log "  MongoDB Cache Size: ${MONGODB_CACHE_SIZE}GB"
    log "  Redis Max Memory: ${REDIS_MAX_MEM}MB"
    
    # Check minimum requirements
    if [[ $TOTAL_MEM -lt 2048 ]]; then
        log_warning "System has less than 2GB RAM. Performance may be affected."
    fi
    
    if [[ $TOTAL_DISK -lt 20 ]]; then
        log_error "Insufficient disk space. At least 20GB required."
        exit 1
    fi
    
    # Check if system is already installed
    if [[ -d "$SYSTEM_DIR" ]]; then
        log_warning "Existing installation detected at $SYSTEM_DIR"
        echo
        echo "What would you like to do?"
        echo "1. Complete fresh installation (remove existing)"
        echo "2. Fix/repair existing installation"
        echo "3. Exit"
        echo
        read -p "Enter choice (1-3): " install_choice
        
        case $install_choice in
            1)
                log "Backing up existing configuration..."
                backup_existing_installation
                log "Removing existing installation..."
                stop_all_services
                rm -rf "$SYSTEM_DIR"
                ;;
            2)
                log "Proceeding with repair mode..."
                REPAIR_MODE=true
                ;;
            3)
                log "Installation cancelled by user"
                exit 0
                ;;
            *)
                log_error "Invalid choice"
                exit 1
                ;;
        esac
    fi
    
    log "Phase 0 completed successfully!"
}

# Backup existing installation
backup_existing_installation() {
    local backup_name="backup-$(date +%Y%m%d_%H%M%S)"
    local backup_path="/root/mikrotik-vpn-backups/$backup_name"
    
    mkdir -p "$backup_path"
    
    if [[ -f "$CONFIG_DIR/setup.env" ]]; then
        cp -r "$CONFIG_DIR" "$backup_path/" 2>/dev/null || true
        log "Configuration backed up to: $backup_path"
    fi
    
    # Backup MongoDB data if running
    if docker ps | grep -q mikrotik-mongodb; then
        log "Backing up MongoDB data..."
        docker exec mikrotik-mongodb mongodump --archive=/tmp/backup.gz --gzip 2>/dev/null || true
        docker cp mikrotik-mongodb:/tmp/backup.gz "$backup_path/mongodb-backup.gz" 2>/dev/null || true
    fi
}

# Stop all services
stop_all_services() {
    log "Stopping all existing services..."
    
    # Stop systemd service if exists
    if [[ "$NO_SYSTEMD" != "true" ]]; then
        systemctl stop mikrotik-vpn 2>/dev/null || true
        systemctl disable mikrotik-vpn 2>/dev/null || true
    fi
    
    # Stop Docker containers
    if command -v docker &> /dev/null && docker ps &>/dev/null; then
        cd "$SYSTEM_DIR" 2>/dev/null || true
        docker compose down 2>/dev/null || true
        docker ps -a | grep mikrotik | awk '{print $1}' | xargs -r docker rm -f 2>/dev/null || true
    fi
}

# =============================================================================
# PHASE 1: USER CONFIGURATION
# =============================================================================

phase1_configuration() {
    log "==================================================================="
    log "PHASE 1: SYSTEM CONFIGURATION"
    log "==================================================================="
    
    # Check for existing configuration
    if [[ -f "$CONFIG_DIR/setup.env" ]] && [[ "${REPAIR_MODE:-false}" == "true" ]]; then
        log "Loading existing configuration..."
        source "$CONFIG_DIR/setup.env"
        
        echo
        echo "Current Configuration:"
        echo "━━━━━━━━━━━━━━━━━━━━━"
        echo "Domain: $DOMAIN_NAME"
        echo "Admin Email: $ADMIN_EMAIL"
        echo "SSH Port: $SSH_PORT"
        echo "VPN Network: $VPN_NETWORK"
        echo
        
        read -p "Keep this configuration? (y/n): " keep_config
        if [[ $keep_config =~ ^[Yy]$ ]]; then
            log "Using existing configuration"
            return
        fi
    fi
    
    # Get new configuration
    echo
    echo "System Configuration"
    echo "━━━━━━━━━━━━━━━━━━"
    
    # Domain name
    while true; do
        read -p "Enter domain name (e.g., vpn.company.com): " DOMAIN_NAME
        if [[ $DOMAIN_NAME =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            echo "Invalid domain format. Please try again."
        fi
    done
    
    # Admin email
    while true; do
        read -p "Enter admin email address: " ADMIN_EMAIL
        if [[ $ADMIN_EMAIL =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            echo "Invalid email format. Please try again."
        fi
    done
    
    # SSH port
    read -p "Enter SSH port (default 22): " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}
    
    # Other configurations
    TIMEZONE="Asia/Bangkok"
    VPN_NETWORK="10.8.0.0/24"
    
    # Generate secure passwords (avoiding special characters that cause issues)
    log "Generating secure passwords..."
    MONGO_ROOT_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    MONGO_APP_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    REDIS_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    JWT_SECRET=$(openssl rand -base64 32 | tr -d "=+/")
    SESSION_SECRET=$(openssl rand -base64 32 | tr -d "=+/")
    API_KEY=$(openssl rand -base64 32 | tr -d "=+/")
    L2TP_PSK=$(openssl rand -base64 32 | tr -d "=+/")
    GRAFANA_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    
    # Save configuration
    save_configuration
    
    # Display summary
    echo
    echo "Configuration Summary"
    echo "━━━━━━━━━━━━━━━━━━━"
    echo "Domain: $DOMAIN_NAME"
    echo "Admin Email: $ADMIN_EMAIL"
    echo "SSH Port: $SSH_PORT"
    echo "Timezone: $TIMEZONE"
    echo "VPN Network: $VPN_NETWORK"
    echo
    
    read -p "Proceed with installation? (y/n): " proceed
    if [[ ! $proceed =~ ^[Yy]$ ]]; then
        log "Installation cancelled by user"
        exit 0
    fi
    
    log "Phase 1 completed successfully!"
}

# Save configuration
save_configuration() {
    mkdir -p "$CONFIG_DIR"
    
    cat << EOF > "$CONFIG_DIR/setup.env"
# MikroTik VPN System Configuration
# Generated: $(date)

# Basic Configuration
export DOMAIN_NAME="$DOMAIN_NAME"
export ADMIN_EMAIL="$ADMIN_EMAIL"
export SSH_PORT="$SSH_PORT"
export TIMEZONE="$TIMEZONE"
export VPN_NETWORK="$VPN_NETWORK"

# Database Passwords
export MONGO_ROOT_PASSWORD="$MONGO_ROOT_PASSWORD"
export MONGO_APP_PASSWORD="$MONGO_APP_PASSWORD"
export REDIS_PASSWORD="$REDIS_PASSWORD"

# Application Secrets
export JWT_SECRET="$JWT_SECRET"
export SESSION_SECRET="$SESSION_SECRET"
export API_KEY="$API_KEY"

# VPN Configuration
export L2TP_PSK="$L2TP_PSK"

# Monitoring
export GRAFANA_PASSWORD="$GRAFANA_PASSWORD"

# System Paths
export SYSTEM_DIR="$SYSTEM_DIR"
export LOG_DIR="$LOG_DIR"
export BACKUP_DIR="$BACKUP_DIR"
export SCRIPT_DIR="$SCRIPT_DIR"
export CONFIG_DIR="$CONFIG_DIR"

# Resource Limits
export MONGODB_CACHE_SIZE="$MONGODB_CACHE_SIZE"
export REDIS_MAX_MEM="$REDIS_MAX_MEM"

# Environment Flags
export IS_WSL="$IS_WSL"
export IS_CONTAINER="$IS_CONTAINER"
export NO_SYSTEMD="$NO_SYSTEMD"
EOF
    
    chmod 600 "$CONFIG_DIR/setup.env"
    
    # Create Docker Compose .env file
    mkdir -p "$SYSTEM_DIR"
    cat << EOF > "$SYSTEM_DIR/.env"
# Docker Compose Environment Variables
MONGO_ROOT_PASSWORD=$MONGO_ROOT_PASSWORD
MONGO_APP_PASSWORD=$MONGO_APP_PASSWORD
REDIS_PASSWORD=$REDIS_PASSWORD
L2TP_PSK=$L2TP_PSK
DOMAIN_NAME=$DOMAIN_NAME
ADMIN_EMAIL=$ADMIN_EMAIL
GRAFANA_PASSWORD=$GRAFANA_PASSWORD
JWT_SECRET=$JWT_SECRET
SESSION_SECRET=$SESSION_SECRET
API_KEY=$API_KEY
MONGODB_CACHE_SIZE=$MONGODB_CACHE_SIZE
REDIS_MAX_MEM=$REDIS_MAX_MEM
EOF
    
    chmod 600 "$SYSTEM_DIR/.env"
}

# =============================================================================
# PHASE 2: SYSTEM PREPARATION
# =============================================================================

phase2_system_preparation() {
    log "==================================================================="
    log "PHASE 2: SYSTEM PREPARATION"
    log "==================================================================="
    
    # Update system
    log "Updating system packages..."
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    
    # Set timezone
    log "Setting timezone to $TIMEZONE..."
    timedatectl set-timezone "$TIMEZONE" 2>/dev/null || \
        ln -sf /usr/share/zoneinfo/$TIMEZONE /etc/localtime
    
    # Install essential packages
    log "Installing essential packages..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl \
        wget \
        vim \
        nano \
        htop \
        iotop \
        iftop \
        net-tools \
        dnsutils \
        iputils-ping \
        traceroute \
        tcpdump \
        mtr \
        nmap \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        ufw \
        fail2ban \
        unzip \
        zip \
        git \
        build-essential \
        python3-pip \
        python3-venv \
        tree \
        jq \
        certbot \
        python3-certbot-nginx \
        mailutils \
        cron \
        logrotate \
        rsync \
        screen \
        tmux \
        aide \
        clamav \
        clamav-daemon \
        rkhunter \
        openssl \
        openssh-server \
        openvpn \
        easy-rsa \
        whois \
        dirmngr \
        gpg-agent \
        iptables \
        kmod
    
    # Create system user
    log "Creating system user..."
    if ! id -u mikrotik-vpn &>/dev/null; then
        useradd -r -m -s /bin/bash -d /home/mikrotik-vpn mikrotik-vpn
        usermod -aG sudo mikrotik-vpn
    fi
    
    # Apply system optimizations
    log "Applying system optimizations..."
    apply_system_optimizations
    
    log "Phase 2 completed successfully!"
}

# Apply system optimizations
apply_system_optimizations() {
    log "Applying system optimizations..."
    
    # System limits
    cat << 'EOF' > /etc/security/limits.d/99-mikrotik-vpn.conf
# MikroTik VPN System Limits
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
root soft nofile 65536
root hard nofile 65536
root soft nproc 32768
root hard nproc 32768
mikrotik-vpn soft nofile 65536
mikrotik-vpn hard nofile 65536
mikrotik-vpn soft nproc 32768
mikrotik-vpn hard nproc 32768
EOF

    # Kernel parameters
    cat << 'EOF' > /etc/sysctl.d/99-mikrotik-vpn.conf
# Network Performance Tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000

# VPN Settings
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.forwarding = 1

# Security Hardening
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
EOF

    # Apply settings
    sysctl -p /etc/sysctl.d/99-mikrotik-vpn.conf 2>/dev/null || {
        log_warning "Some sysctl settings could not be applied"
        # Apply essential settings
        sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
        sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true
    }
}

# =============================================================================
# PHASE 3: DOCKER INSTALLATION WITH FIXES
# =============================================================================

phase3_docker_installation() {
    log "==================================================================="
    log "PHASE 3: DOCKER INSTALLATION WITH ENVIRONMENT FIXES"
    log "==================================================================="
    
    # Check if Docker is already installed
    if command -v docker &> /dev/null; then
        log "Docker is already installed"
        docker --version
        
        # Check if Docker is running
        if docker ps &>/dev/null; then
            log "Docker is already running"
            create_docker_network
            log "Phase 3 completed successfully!"
            return 0
        else
            log "Docker is installed but not running"
            log "Applying fixes..."
        fi
    else
        log "Installing Docker..."
        
        # Remove old packages
        apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
        
        # Add Docker GPG key
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg
        
        # Add Docker repository
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
          $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Update and install
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            docker-ce \
            docker-ce-cli \
            containerd.io \
            docker-buildx-plugin \
            docker-compose-plugin
    fi
    
    # Apply universal Docker fixes
    fix_docker_universal
    
    # Start Docker based on environment
    if ! start_docker_smart; then
        log_error "Failed to start Docker"
        exit 1
    fi
    
    # Add users to docker group
    usermod -aG docker mikrotik-vpn 2>/dev/null || true
    if [[ -n "${SUDO_USER:-}" ]]; then
        usermod -aG docker "$SUDO_USER" 2>/dev/null || true
    fi
    
    # Verify Docker is working
    log "Verifying Docker installation..."
    if ! docker run --rm hello-world &>/dev/null; then
        log_error "Docker test failed"
        exit 1
    fi
    
    log "Docker is working correctly"
    
    # Create Docker network
    create_docker_network
    
    # Show versions
    docker --version
    docker compose version
    
    log "Phase 3 completed successfully!"
}

# =============================================================================
# PHASE 4: DIRECTORY STRUCTURE
# =============================================================================

phase4_directory_structure() {
    log "==================================================================="
    log "PHASE 4: CREATING DIRECTORY STRUCTURE"
    log "==================================================================="
    
    # Create all necessary directories with a single command
    local dirs="
        $SYSTEM_DIR
        $CONFIG_DIR
        $SCRIPT_DIR
        $BACKUP_DIR/daily
        $BACKUP_DIR/weekly
        $BACKUP_DIR/monthly
        $LOG_DIR
        $SYSTEM_DIR/app/src
        $SYSTEM_DIR/app/routes
        $SYSTEM_DIR/app/models
        $SYSTEM_DIR/app/controllers
        $SYSTEM_DIR/app/middleware
        $SYSTEM_DIR/app/utils
        $SYSTEM_DIR/app/public
        $SYSTEM_DIR/app/views
        $SYSTEM_DIR/app/config
        $SYSTEM_DIR/mongodb/data
        $SYSTEM_DIR/mongodb/logs
        $SYSTEM_DIR/mongodb/backups
        $SYSTEM_DIR/redis/data
        $SYSTEM_DIR/redis/logs
        $SYSTEM_DIR/nginx/conf.d
        $SYSTEM_DIR/nginx/ssl
        $SYSTEM_DIR/nginx/html
        $SYSTEM_DIR/nginx/logs
        $SYSTEM_DIR/openvpn/server
        $SYSTEM_DIR/openvpn/client-configs
        $SYSTEM_DIR/openvpn/easy-rsa
        $SYSTEM_DIR/openvpn/ccd
        $SYSTEM_DIR/l2tp
        $SYSTEM_DIR/monitoring/prometheus/rules
        $SYSTEM_DIR/monitoring/grafana/provisioning/datasources
        $SYSTEM_DIR/monitoring/grafana/provisioning/dashboards
        $SYSTEM_DIR/monitoring/grafana/provisioning/notifiers
        $SYSTEM_DIR/monitoring/grafana/dashboards
        $SYSTEM_DIR/monitoring/alertmanager
        $SYSTEM_DIR/clients
        $SYSTEM_DIR/data
        $SYSTEM_DIR/ssl
    "
    
    for dir in $dirs; do
        mkdir -p "$dir"
        log "Created directory: $dir"
    done
    
    # Set ownership and permissions
    chown -R mikrotik-vpn:mikrotik-vpn "$SYSTEM_DIR"
    chown -R mikrotik-vpn:mikrotik-vpn "$LOG_DIR"
    chmod -R 755 "$SYSTEM_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 700 "$SYSTEM_DIR/ssl"
    
    log "Phase 4 completed successfully!"
}

# =============================================================================
# PHASE 5: NODE.JS APPLICATION WITH MINIMAL SETUP
# =============================================================================

phase5_nodejs_application() {
    log "==================================================================="
    log "PHASE 5: SETTING UP NODE.JS APPLICATION (MINIMAL)"
    log "==================================================================="
    
    # Install Node.js if not already installed
    if ! command -v node &> /dev/null; then
        log "Installing Node.js 20 LTS..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs
    fi
    
    # Create minimal package.json
    cat << 'EOF' > "$SYSTEM_DIR/app/package.json"
{
  "name": "mikrotik-vpn-app",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^7.5.0",
    "redis": "^4.6.8",
    "dotenv": "^16.3.1",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "winston": "^3.10.0"
  }
}
EOF

    # Create minimal working server
    cat << 'EOF' > "$SYSTEM_DIR/app/server.js"
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const redis = require('redis');
const cors = require('cors');
const helmet = require('helmet');
const winston = require('winston');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Configure logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.simple()
        }),
        new winston.transports.File({ 
            filename: '/var/log/mikrotik-vpn/app.log',
            maxsize: 10485760,
            maxFiles: 5
        })
    ]
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Global variables for connections
let redisClient = null;
let mongoConnected = false;

// Health check endpoint
app.get('/health', async (req, res) => {
    const health = {
        status: 'OK',
        timestamp: new Date().toISOString(),
        services: {
            mongodb: mongoConnected ? 'connected' : 'disconnected',
            redis: redisClient && redisClient.isOpen ? 'connected' : 'disconnected'
        }
    };
    res.json(health);
});

// Basic API endpoint
app.get('/api', (req, res) => {
    res.json({
        message: 'MikroTik VPN API',
        version: '1.0.0',
        status: 'operational'
    });
});

// Metrics endpoint
app.get('/metrics', (req, res) => {
    const metrics = [
        '# HELP app_up Application status',
        '# TYPE app_up gauge',
        'app_up 1',
        '',
        '# HELP app_mongodb_connected MongoDB connection status',
        '# TYPE app_mongodb_connected gauge',
        `app_mongodb_connected ${mongoConnected ? 1 : 0}`,
        '',
        '# HELP app_redis_connected Redis connection status',
        '# TYPE app_redis_connected gauge',
        `app_redis_connected ${redisClient && redisClient.isOpen ? 1 : 0}`
    ];
    res.set('Content-Type', 'text/plain');
    res.send(metrics.join('\n'));
});

// MongoDB connection with retry
async function connectMongoDB() {
    try {
        const mongoUri = `mongodb://mikrotik_app:${process.env.MONGO_APP_PASSWORD}@mongodb:27017/mikrotik_vpn?authSource=mikrotik_vpn&authMechanism=SCRAM-SHA-256`;
        
        await mongoose.connect(mongoUri, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000,
            directConnection: true
        });
        
        mongoConnected = true;
        logger.info('MongoDB connected successfully');
    } catch (error) {
        mongoConnected = false;
        logger.error('MongoDB connection failed:', error.message);
        setTimeout(connectMongoDB, 5000);
    }
}

// Redis connection with retry
async function connectRedis() {
    try {
        redisClient = redis.createClient({
            socket: {
                host: 'redis',
                port: 6379
            },
            password: process.env.REDIS_PASSWORD
        });
        
        redisClient.on('error', err => logger.error('Redis error:', err));
        redisClient.on('connect', () => logger.info('Redis connected'));
        
        await redisClient.connect();
    } catch (error) {
        logger.error('Redis connection failed:', error.message);
        setTimeout(connectRedis, 5000);
    }
}

// Start server
async function startServer() {
    // Start connections
    connectMongoDB();
    connectRedis();
    
    // Start Express server
    app.listen(PORT, '0.0.0.0', () => {
        logger.info(`Server running on port ${PORT}`);
        console.log(`
╔═══════════════════════════════════════════════════════════════╗
║          MikroTik VPN Management System                       ║
║          Server running at: http://0.0.0.0:${PORT}            ║
╚═══════════════════════════════════════════════════════════════╝
        `);
    });
}

// Handle shutdown
process.on('SIGTERM', async () => {
    logger.info('SIGTERM received, shutting down...');
    if (redisClient) await redisClient.quit();
    await mongoose.connection.close();
    process.exit(0);
});

// Start the server
startServer();
EOF

    # Create .env file
    cat << EOF > "$SYSTEM_DIR/app/.env"
NODE_ENV=production
PORT=3000
MONGO_APP_PASSWORD=$MONGO_APP_PASSWORD
REDIS_PASSWORD=$REDIS_PASSWORD
EOF

    # Create Dockerfile
    cat << 'EOF' > "$SYSTEM_DIR/app/Dockerfile"
FROM node:20-alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
EOF

    # Set permissions
    chown -R mikrotik-vpn:mikrotik-vpn "$SYSTEM_DIR/app"
    
    log "Phase 5 completed successfully!"
}

# =============================================================================
# PHASE 6: CONFIGURATION FILES WITH FIXES
# =============================================================================

phase6_configuration_files() {
    log "==================================================================="
    log "PHASE 6: CREATING CONFIGURATION FILES WITH FIXES"
    log "==================================================================="
    
    # MongoDB initialization script with proper authentication
    cat << EOF > "$SYSTEM_DIR/mongodb/mongo-init.js"
// MongoDB Initialization Script
print('Starting MongoDB initialization...');

// Switch to admin database
db = db.getSiblingDB('admin');

// Create admin user if not exists
try {
    db.createUser({
        user: 'admin',
        pwd: '$MONGO_ROOT_PASSWORD',
        roles: ['root']
    });
    print('Admin user created');
} catch (e) {
    print('Admin user already exists');
}

// Switch to application database
db = db.getSiblingDB('mikrotik_vpn');

// Drop existing user if exists
try {
    db.dropUser('mikrotik_app');
} catch (e) {
    // User doesn't exist, continue
}

// Create application user with correct password
db.createUser({
    user: 'mikrotik_app',
    pwd: '$MONGO_APP_PASSWORD',
    roles: [
        {
            role: 'readWrite',
            db: 'mikrotik_vpn'
        }
    ]
});
print('Application user created');

// Create collections
db.createCollection('organizations');
db.createCollection('devices');
db.createCollection('users');
db.createCollection('vouchers');
db.createCollection('sessions');
db.createCollection('logs');

// Create indexes
db.devices.createIndex({ serialNumber: 1 }, { unique: true });
db.devices.createIndex({ macAddress: 1 }, { unique: true });
db.users.createIndex({ username: 1 }, { unique: true });
db.users.createIndex({ email: 1 }, { unique: true });
db.vouchers.createIndex({ code: 1 }, { unique: true });

print('MongoDB initialization completed successfully');
EOF

    # Redis configuration
    cat << EOF > "$SYSTEM_DIR/redis/redis.conf"
# Redis Configuration
bind 0.0.0.0
protected-mode yes
port 6379
tcp-backlog 511
timeout 0
tcp-keepalive 300

# General
daemonize no
loglevel notice
logfile ""
databases 16

# Snapshotting
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /data

# Security
requirepass $REDIS_PASSWORD

# Limits
maxclients 10000
maxmemory ${REDIS_MAX_MEM}mb
maxmemory-policy allkeys-lru

# Append only mode
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec
EOF

    # Nginx configuration
    create_nginx_configs_fixed
    
    # OpenVPN configuration
    create_openvpn_configs_fixed
    
    # Prometheus configuration
    create_prometheus_configs_fixed
    
    # Grafana configuration
    create_grafana_configs_fixed
    
    log "Phase 6 completed successfully!"
}

# Create Nginx configurations with fixes
create_nginx_configs_fixed() {
    # Main nginx.conf
    cat << 'EOF' > "$SYSTEM_DIR/nginx/nginx.conf"
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # Security
    server_tokens off;
    
    # Gzip
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss;
    
    # Include site configurations
    include /etc/nginx/conf.d/*.conf;
}
EOF

    # Site configuration
    cat << EOF > "$SYSTEM_DIR/nginx/conf.d/default.conf"
upstream app_backend {
    server app:3000;
}

server {
    listen 80;
    listen [::]:80;
    server_name _;
    
    location / {
        proxy_pass http://app_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
    
    location /health {
        access_log off;
        proxy_pass http://app_backend/health;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name _;
    
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    location / {
        proxy_pass http://app_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

    # Create self-signed certificate
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SYSTEM_DIR/nginx/ssl/privkey.pem" \
        -out "$SYSTEM_DIR/nginx/ssl/fullchain.pem" \
        -subj "/C=TH/ST=Bangkok/L=Bangkok/O=MikroTik VPN/CN=$DOMAIN_NAME" \
        2>/dev/null
}

# Create OpenVPN configurations
create_openvpn_configs_fixed() {
    # Server configuration
    cat << EOF > "$SYSTEM_DIR/openvpn/server/server.conf"
port 1194
proto udp
dev tun

ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key /etc/openvpn/easy-rsa/pki/private/server.key
dh /etc/openvpn/easy-rsa/pki/dh.pem
tls-auth /etc/openvpn/easy-rsa/ta.key 0

server ${VPN_NETWORK%.0/24} 255.255.255.0
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

client-to-client
keepalive 10 120
cipher AES-256-GCM
auth SHA512
comp-lzo

user nobody
group nogroup
persist-key
persist-tun

status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3

max-clients 1000
EOF

    # Easy-RSA vars
    cat << EOF > "$SYSTEM_DIR/openvpn/easy-rsa/vars"
set_var EASYRSA_REQ_COUNTRY    "TH"
set_var EASYRSA_REQ_PROVINCE   "Bangkok"
set_var EASYRSA_REQ_CITY       "Bangkok"
set_var EASYRSA_REQ_ORG        "MikroTik VPN"
set_var EASYRSA_REQ_EMAIL      "$ADMIN_EMAIL"
set_var EASYRSA_REQ_OU         "VPN"
set_var EASYRSA_ALGO           "rsa"
set_var EASYRSA_KEY_SIZE       2048
EOF

    # PKI initialization script
    cat << 'EOF' > "$SYSTEM_DIR/openvpn/init-pki.sh"
#!/bin/bash
cd /etc/openvpn

if [[ ! -d "easy-rsa" ]]; then
    wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.0/EasyRSA-3.1.0.tgz
    tar xzf EasyRSA-3.1.0.tgz
    mv EasyRSA-3.1.0/* easy-rsa/
    rm -rf EasyRSA-3.1.0*
fi

cd easy-rsa
cp /etc/openvpn/easy-rsa/vars ./vars

./easyrsa init-pki
./easyrsa --batch build-ca nopass
./easyrsa --batch gen-req server nopass
./easyrsa --batch sign-req server server
./easyrsa gen-dh
openvpn --genkey secret ta.key

echo "PKI initialization completed!"
EOF

    chmod +x "$SYSTEM_DIR/openvpn/init-pki.sh"
}

# Create Prometheus configurations
create_prometheus_configs_fixed() {
    cat << 'EOF' > "$SYSTEM_DIR/monitoring/prometheus/prometheus.yml"
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'docker'
    static_configs:
      - targets: ['cadvisor:8080']

  - job_name: 'mongodb'
    static_configs:
      - targets: ['mongodb-exporter:9216']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-exporter:9113']

  - job_name: 'mikrotik-app'
    static_configs:
      - targets: ['app:3000']
    metrics_path: '/metrics'
EOF
}

# Create Grafana configurations
create_grafana_configs_fixed() {
    # Datasource
    cat << 'EOF' > "$SYSTEM_DIR/monitoring/grafana/provisioning/datasources/prometheus.yml"
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF

    # Dashboard provisioning
    cat << 'EOF' > "$SYSTEM_DIR/monitoring/grafana/provisioning/dashboards/dashboard.yml"
apiVersion: 1

providers:
  - name: 'MikroTik VPN Dashboards'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
EOF
}

# =============================================================================
# PHASE 7: DOCKER COMPOSE WITH FIXES
# =============================================================================

phase7_docker_compose() {
    log "==================================================================="
    log "PHASE 7: CREATING DOCKER COMPOSE CONFIGURATION WITH FIXES"
    log "==================================================================="
    
    cat << 'EOF' > "$SYSTEM_DIR/docker-compose.yml"
services:
  # ===========================================
  # Database Services
  # ===========================================
  mongodb:
    image: mongo:7.0
    container_name: mikrotik-mongodb
    restart: unless-stopped
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=${MONGO_ROOT_PASSWORD}
      - MONGO_INITDB_DATABASE=mikrotik_vpn
    volumes:
      - ./mongodb/data:/data/db
      - ./mongodb/logs:/var/log/mongodb
      - ./mongodb/mongo-init.js:/docker-entrypoint-initdb.d/mongo-init.js:ro
    ports:
      - "127.0.0.1:27017:27017"
    command: mongod --auth --bind_ip_all --wiredTigerCacheSizeGB ${MONGODB_CACHE_SIZE}
    networks:
      - mikrotik-vpn-net
    healthcheck:
      test: |
        mongosh --eval "db.adminCommand('ping')" -u admin -p ${MONGO_ROOT_PASSWORD} --authenticationDatabase admin --quiet
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 40s

  redis:
    image: redis:7-alpine
    container_name: mikrotik-redis
    restart: unless-stopped
    command: redis-server /usr/local/etc/redis/redis.conf
    volumes:
      - ./redis/data:/data
      - ./redis/redis.conf:/usr/local/etc/redis/redis.conf:ro
    ports:
      - "127.0.0.1:6379:6379"
    networks:
      - mikrotik-vpn-net
    healthcheck:
      test: ["CMD", "redis-cli", "--pass", "${REDIS_PASSWORD}", "ping"]
      interval: 30s
      timeout: 10s
      retries: 5

  # ===========================================
  # Application Service
  # ===========================================
  app:
    build: 
      context: ./app
      dockerfile: Dockerfile
    container_name: mikrotik-app
    restart: unless-stopped
    environment:
      - NODE_ENV=production
      - PORT=3000
      - MONGO_APP_PASSWORD=${MONGO_APP_PASSWORD}
      - REDIS_PASSWORD=${REDIS_PASSWORD}
    ports:
      - "127.0.0.1:3000:3000"
    volumes:
      - ./app:/usr/src/app
      - /usr/src/app/node_modules
      - ./logs:/var/log/mikrotik-vpn
    networks:
      - mikrotik-vpn-net
    depends_on:
      mongodb:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # ===========================================
  # Web Server
  # ===========================================
  nginx:
    image: nginx:alpine
    container_name: mikrotik-nginx
    restart: unless-stopped
    ports:
      - "9080:80"
      - "9443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/conf.d:/etc/nginx/conf.d:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./logs/nginx:/var/log/nginx
    networks:
      - mikrotik-vpn-net
    depends_on:
      app:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # ===========================================
  # VPN Services
  # ===========================================
  openvpn:
    build:
      context: ./openvpn
      dockerfile: Dockerfile
    container_name: mikrotik-openvpn
    cap_add:
      - NET_ADMIN
    ports:
      - "1194:1194/udp"
    volumes:
      - ./openvpn:/etc/openvpn
      - ./logs:/var/log
    restart: unless-stopped
    networks:
      - mikrotik-vpn-net
    devices:
      - /dev/net/tun
    sysctls:
      - net.ipv4.ip_forward=1
    environment:
      - OVPN_SERVER=${VPN_NETWORK}

  # ===========================================
  # Monitoring Stack (Optional)
  # ===========================================
  prometheus:
    image: prom/prometheus:latest
    container_name: mikrotik-prometheus
    restart: unless-stopped
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.enable-lifecycle'
    volumes:
      - ./monitoring/prometheus:/etc/prometheus
      - prometheus_data:/prometheus
    ports:
      - "127.0.0.1:9090:9090"
    networks:
      - mikrotik-vpn-net

  grafana:
    image: grafana/grafana:latest
    container_name: mikrotik-grafana
    restart: unless-stopped
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning:ro
    ports:
      - "127.0.0.1:3001:3000"
    networks:
      - mikrotik-vpn-net

  # ===========================================
  # Exporters for Monitoring
  # ===========================================
  node-exporter:
    image: prom/node-exporter:latest
    container_name: mikrotik-node-exporter
    restart: unless-stopped
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($|/)'
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    ports:
      - "127.0.0.1:9100:9100"
    networks:
      - mikrotik-vpn-net

  mongodb-exporter:
    image: percona/mongodb_exporter:0.40
    container_name: mikrotik-mongodb-exporter
    restart: unless-stopped
    command:
      - '--mongodb.uri=mongodb://admin:${MONGO_ROOT_PASSWORD}@mongodb:27017/admin?ssl=false&directConnection=true'
      - '--collect-all'
    ports:
      - "127.0.0.1:9216:9216"
    networks:
      - mikrotik-vpn-net
    depends_on:
      - mongodb

  redis-exporter:
    image: oliver006/redis_exporter:latest
    container_name: mikrotik-redis-exporter
    restart: unless-stopped
    environment:
      - REDIS_ADDR=redis:6379
      - REDIS_PASSWORD=${REDIS_PASSWORD}
    ports:
      - "127.0.0.1:9121:9121"
    networks:
      - mikrotik-vpn-net
    depends_on:
      - redis

  # ===========================================
  # Management Tools
  # ===========================================
  mongo-express:
    image: mongo-express:latest
    container_name: mikrotik-mongo-express
    restart: unless-stopped
    environment:
      - ME_CONFIG_MONGODB_ADMINUSERNAME=admin
      - ME_CONFIG_MONGODB_ADMINPASSWORD=${MONGO_ROOT_PASSWORD}
      - ME_CONFIG_MONGODB_SERVER=mongodb
      - ME_CONFIG_MONGODB_PORT=27017
      - ME_CONFIG_BASICAUTH_USERNAME=admin
      - ME_CONFIG_BASICAUTH_PASSWORD=${MONGO_ROOT_PASSWORD}
    ports:
      - "127.0.0.1:8081:8081"
    networks:
      - mikrotik-vpn-net
    depends_on:
      - mongodb

  redis-commander:
    image: rediscommander/redis-commander:latest
    container_name: mikrotik-redis-commander
    restart: unless-stopped
    environment:
      - REDIS_HOSTS=local:redis:6379:0:${REDIS_PASSWORD}
      - HTTP_USER=admin
      - HTTP_PASSWORD=${REDIS_PASSWORD}
    ports:
      - "127.0.0.1:8082:8081"
    networks:
      - mikrotik-vpn-net
    depends_on:
      - redis

# ===========================================
# Volumes
# ===========================================
volumes:
  prometheus_data:
    driver: local
  grafana_data:
    driver: local

# ===========================================
# Networks
# ===========================================
networks:
  mikrotik-vpn-net:
    external: true
EOF

    # Create OpenVPN Dockerfile
    cat << 'EOF' > "$SYSTEM_DIR/openvpn/Dockerfile"
FROM alpine:latest

RUN apk add --no-cache \
    openvpn \
    easy-rsa \
    bash \
    iptables \
    curl

COPY --chown=root:root . /etc/openvpn/

RUN mkdir -p /etc/openvpn/ccd \
    && mkdir -p /var/log \
    && chmod +x /etc/openvpn/init-pki.sh

EXPOSE 1194/udp

CMD ["openvpn", "--config", "/etc/openvpn/server/server.conf"]
EOF

    log "Phase 7 completed successfully!"
}

# =============================================================================
# PHASE 8: MANAGEMENT SCRIPTS
# =============================================================================

phase8_management_scripts() {
    log "==================================================================="
    log "PHASE 8: CREATING MANAGEMENT SCRIPTS"
    log "==================================================================="
    
    # Main management script
    create_main_management_script_fixed
    
    # Service control scripts
    create_service_scripts_fixed
    
    # Health check script
    create_health_check_script_fixed
    
    # Backup scripts
    create_backup_scripts_fixed
    
    # VPN management scripts
    create_vpn_scripts_fixed
    
    # Set permissions
    chmod +x "$SCRIPT_DIR"/*.sh
    
    log "Phase 8 completed successfully!"
}

# Create main management script with environment fixes
create_main_management_script_fixed() {
    cat << 'EOF' > "$SYSTEM_DIR/mikrotik-vpn"
#!/bin/bash
# MikroTik VPN System Management Interface

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SYSTEM_DIR="/opt/mikrotik-vpn"
SCRIPT_DIR="/opt/mikrotik-vpn/scripts"

# Load environment
if [[ -f "$SYSTEM_DIR/configs/setup.env" ]]; then
    source "$SYSTEM_DIR/configs/setup.env"
fi

# Print colored output
print_colored() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Show header
show_header() {
    clear
    print_colored "$CYAN" "╔═══════════════════════════════════════════════════════════════╗"
    print_colored "$CYAN" "║          MikroTik VPN Management System v5.0                  ║"
    print_colored "$CYAN" "╚═══════════════════════════════════════════════════════════════╝"
    echo
}

# Show status
show_status() {
    show_header
    print_colored "$BLUE" "System Status"
    print_colored "$BLUE" "═════════════"
    echo
    
    # Check Docker first
    if ! docker ps &>/dev/null; then
        print_colored "$RED" "✗ Docker is not running!"
        echo
        echo "Attempting to start Docker..."
        $SCRIPT_DIR/start-docker.sh
        echo
    fi
    
    # Check services
    local services="mongodb redis app nginx openvpn prometheus grafana"
    for service in $services; do
        if docker ps --format "{{.Names}}" | grep -q "mikrotik-$service"; then
            print_colored "$GREEN" "✓ $service is running"
        else
            print_colored "$RED" "✗ $service is not running"
        fi
    done
    
    echo
    print_colored "$BLUE" "System Information"
    print_colored "$BLUE" "═════════════════"
    echo "Domain: $DOMAIN_NAME"
    echo "VPN Network: $VPN_NETWORK"
    echo "Environment: $([ "$NO_SYSTEMD" = "true" ] && echo "No systemd" || echo "Standard")"
    echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
    echo
}

# Quick actions menu
quick_actions_menu() {
    show_header
    print_colored "$PURPLE" "Quick Actions"
    print_colored "$PURPLE" "════════════"
    echo
    echo "1. View logs (all services)"
    echo "2. Restart application"
    echo "3. Check health status"
    echo "4. Create VPN client"
    echo "5. Backup system"
    echo "6. Back to main menu"
    echo
    read -p "Select option (1-6): " choice
    
    case $choice in
        1) cd /opt/mikrotik-vpn && docker compose logs -f --tail=100 ;;
        2) docker restart mikrotik-app && echo "Application restarted" && sleep 2 ;;
        3) $SCRIPT_DIR/health-check.sh; read -p "Press Enter to continue..." ;;
        4) $SCRIPT_DIR/create-vpn-client.sh ;;
        5) $SCRIPT_DIR/backup-system.sh; read -p "Press Enter to continue..." ;;
        6) main_menu ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; quick_actions_menu ;;
    esac
}

# Main menu
main_menu() {
    show_header
    print_colored "$PURPLE" "Main Menu"
    print_colored "$PURPLE" "═════════"
    echo
    echo "1. System Status"
    echo "2. Quick Actions"
    echo "3. Service Management"
    echo "4. View Logs"
    echo "5. Access URLs"
    echo "6. Exit"
    echo
    read -p "Select option (1-6): " choice
    
    case $choice in
        1) show_status; read -p "Press Enter to continue..."; main_menu ;;
        2) quick_actions_menu; main_menu ;;
        3) $SCRIPT_DIR/service-manager.sh; main_menu ;;
        4) cd /opt/mikrotik-vpn && docker compose logs -f --tail=100 ;;
        5) 
            echo
            print_colored "$BLUE" "Access URLs:"
            echo "Main: http://localhost:9080 or https://localhost:9443"
            echo "MongoDB: http://localhost:8081"
            echo "Redis: http://localhost:8082"
            echo "Prometheus: http://localhost:9090"
            echo "Grafana: http://localhost:3001"
            read -p "Press Enter to continue..."
            main_menu
            ;;
        6) exit 0 ;;
        *) print_colored "$RED" "Invalid option"; sleep 2; main_menu ;;
    esac
}

# Handle command line arguments
case "${1:-}" in
    status)
        show_status
        ;;
    start)
        $SCRIPT_DIR/start-services.sh
        ;;
    stop)
        $SCRIPT_DIR/stop-services.sh
        ;;
    restart)
        $SCRIPT_DIR/restart-services.sh
        ;;
    health)
        $SCRIPT_DIR/health-check.sh
        ;;
    backup)
        $SCRIPT_DIR/backup-system.sh
        ;;
    logs)
        cd /opt/mikrotik-vpn && docker compose logs -f --tail=100
        ;;
    *)
        main_menu
        ;;
esac
EOF

    chmod +x "$SYSTEM_DIR/mikrotik-vpn"
    ln -sf "$SYSTEM_DIR/mikrotik-vpn" /usr/local/bin/mikrotik-vpn
}

# Create service control scripts with Docker fixes
create_service_scripts_fixed() {
    # Start Docker script
    cat << 'EOF' > "$SCRIPT_DIR/start-docker.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "Starting Docker..."

# Check if already running
if docker ps &>/dev/null; then
    echo "Docker is already running"
    exit 0
fi

# Try systemd first
if [[ "$NO_SYSTEMD" != "true" ]]; then
    if systemctl start docker 2>/dev/null; then
        echo "Docker started with systemd"
        exit 0
    fi
fi

# Try service command
if service docker start 2>/dev/null; then
    echo "Docker started with service command"
    exit 0
fi

# Start manually
echo "Starting Docker manually..."
dockerd > /var/log/docker-manual.log 2>&1 &
echo $! > /var/run/docker-manual.pid

# Wait for Docker
count=0
while [[ $count -lt 30 ]]; do
    if docker ps &>/dev/null; then
        echo "Docker started successfully"
        exit 0
    fi
    sleep 1
    count=$((count + 1))
done

echo "Failed to start Docker"
exit 1
EOF

    # Start services
    cat << 'EOF' > "$SCRIPT_DIR/start-services.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "Starting MikroTik VPN services..."

# Ensure Docker is running
$SCRIPT_DIR/start-docker.sh || exit 1

cd /opt/mikrotik-vpn || exit 1

# Create network if not exists
docker network ls --format '{{.Name}}' | grep -q "^mikrotik-vpn-net$" || \
    docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16

# Start services in order
echo "Starting MongoDB and Redis..."
docker compose up -d mongodb redis
sleep 15

echo "Starting application..."
docker compose up -d app
sleep 10

echo "Starting all remaining services..."
docker compose up -d

echo "All services started!"
docker compose ps
EOF

    # Stop services
    cat << 'EOF' > "$SCRIPT_DIR/stop-services.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "Stopping MikroTik VPN services..."
cd /opt/mikrotik-vpn || exit 1
docker compose down

# If Docker was started manually, stop it
if [[ -f /var/run/docker-manual.pid ]]; then
    echo "Stopping manually started Docker..."
    kill $(cat /var/run/docker-manual.pid) 2>/dev/null || true
    rm -f /var/run/docker-manual.pid
fi

echo "All services stopped!"
EOF

    # Restart services
    cat << 'EOF' > "$SCRIPT_DIR/restart-services.sh"
#!/bin/bash
$SCRIPT_DIR/stop-services.sh
sleep 5
$SCRIPT_DIR/start-services.sh
EOF

    # Service manager
    cat << 'EOF' > "$SCRIPT_DIR/service-manager.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

show_menu() {
    clear
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                Service Management                             ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo
    echo "1. Start all services"
    echo "2. Stop all services"
    echo "3. Restart all services"
    echo "4. Start specific service"
    echo "5. Stop specific service"
    echo "6. Restart specific service"
    echo "7. View service logs"
    echo "8. Back to main menu"
    echo
}

manage_specific_service() {
    local action=$1
    echo "Select service:"
    echo "1. MongoDB"
    echo "2. Redis"
    echo "3. Application"
    echo "4. Nginx"
    echo "5. OpenVPN"
    echo "6. All monitoring services"
    echo
    read -p "Enter choice: " service_choice
    
    case $service_choice in
        1) service="mongodb" ;;
        2) service="redis" ;;
        3) service="app" ;;
        4) service="nginx" ;;
        5) service="openvpn" ;;
        6) service="prometheus grafana node-exporter" ;;
        *) echo "Invalid choice"; return ;;
    esac
    
    cd /opt/mikrotik-vpn || exit 1
    
    case $action in
        "start") docker compose up -d $service ;;
        "stop") docker compose stop $service ;;
        "restart") docker compose restart $service ;;
    esac
    
    echo "$action $service completed"
    sleep 2
}

while true; do
    show_menu
    read -p "Select option (1-8): " choice
    
    case $choice in
        1) $SCRIPT_DIR/start-services.sh; read -p "Press Enter to continue..." ;;
        2) $SCRIPT_DIR/stop-services.sh; read -p "Press Enter to continue..." ;;
        3) $SCRIPT_DIR/restart-services.sh; read -p "Press Enter to continue..." ;;
        4) manage_specific_service "start" ;;
        5) manage_specific_service "stop" ;;
        6) manage_specific_service "restart" ;;
        7) cd /opt/mikrotik-vpn && docker compose logs -f --tail=100 ;;
        8) break ;;
        *) echo "Invalid option"; sleep 2 ;;
    esac
done
EOF

    chmod +x "$SCRIPT_DIR"/*.sh
}

# Create health check script
create_health_check_script_fixed() {
    cat << 'EOF' > "$SCRIPT_DIR/health-check.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== MikroTik VPN System Health Check ==="
echo "Timestamp: $(date)"
echo

# Check Docker first
if ! docker ps &>/dev/null; then
    echo -e "${RED}✗${NC} Docker is not running!"
    exit 1
fi

# Function to check service
check_service() {
    local service=$1
    local container="mikrotik-$service"
    
    if docker ps --format "{{.Names}}" | grep -q "^${container}$"; then
        # Get container health status
        health=$(docker inspect --format='{{.State.Health.Status}}' $container 2>/dev/null || echo "none")
        
        if [[ "$health" == "healthy" ]] || [[ "$health" == "none" ]]; then
            echo -e "${GREEN}✓${NC} $service is running"
            
            # Additional checks
            case $service in
                "mongodb")
                    if docker exec $container mongosh --eval "db.adminCommand('ping')" -u admin -p "$MONGO_ROOT_PASSWORD" --authenticationDatabase admin --quiet &>/dev/null; then
                        echo -e "  ${GREEN}✓${NC} MongoDB responding to queries"
                    else
                        echo -e "  ${RED}✗${NC} MongoDB not responding"
                    fi
                    ;;
                "redis")
                    if docker exec $container redis-cli --pass "$REDIS_PASSWORD" ping 2>/dev/null | grep -q "PONG"; then
                        echo -e "  ${GREEN}✓${NC} Redis responding to queries"
                    else
                        echo -e "  ${RED}✗${NC} Redis not responding"
                    fi
                    ;;
                "app")
                    if curl -s http://localhost:3000/health | grep -q "OK"; then
                        echo -e "  ${GREEN}✓${NC} Application API healthy"
                    else
                        echo -e "  ${RED}✗${NC} Application API not responding"
                    fi
                    ;;
                "nginx")
                    if curl -s http://localhost:9080/health >/dev/null; then
                        echo -e "  ${GREEN}✓${NC} Nginx proxy working"
                    else
                        echo -e "  ${RED}✗${NC} Nginx proxy not responding"
                    fi
                    ;;
            esac
        else
            echo -e "${YELLOW}⚠${NC} $service is unhealthy (status: $health)"
        fi
    else
        echo -e "${RED}✗${NC} $service is not running"
    fi
}

# Check all services
echo "Checking services..."
services="mongodb redis app nginx openvpn"
for service in $services; do
    check_service "$service"
done

echo
echo "Checking system resources..."

# Disk usage
disk_usage=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [[ $disk_usage -lt 80 ]]; then
    echo -e "${GREEN}✓${NC} Disk usage: $disk_usage%"
else
    echo -e "${YELLOW}⚠${NC} Disk usage: $disk_usage% (high)"
fi

# Memory usage
mem_total=$(free -m | awk '/^Mem:/{print $2}')
mem_used=$(free -m | awk '/^Mem:/{print $3}')
mem_percent=$((mem_used * 100 / mem_total))
if [[ $mem_percent -lt 80 ]]; then
    echo -e "${GREEN}✓${NC} Memory usage: $mem_percent% ($mem_used MB / $mem_total MB)"
else
    echo -e "${YELLOW}⚠${NC} Memory usage: $mem_percent% (high)"
fi

# Load average
load_avg=$(uptime | awk -F'load average:' '{print $2}')
echo -e "${GREEN}✓${NC} Load average:$load_avg"

echo
echo "Health check completed!"
EOF
}

# Create backup scripts
create_backup_scripts_fixed() {
    cat << 'EOF' > "$SCRIPT_DIR/backup-system.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

BACKUP_DIR="/opt/mikrotik-vpn/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="mikrotik-vpn-backup-$DATE"
BACKUP_PATH="$BACKUP_DIR/$BACKUP_NAME"

echo "Creating system backup..."
mkdir -p "$BACKUP_PATH"

# Check if services are running
if ! docker ps | grep -q mikrotik-mongodb; then
    echo "MongoDB is not running. Starting services..."
    $SCRIPT_DIR/start-services.sh
    sleep 10
fi

# Backup databases
echo "Backing up MongoDB..."
docker exec mikrotik-mongodb mongodump \
    --uri="mongodb://admin:$MONGO_ROOT_PASSWORD@localhost:27017/admin" \
    --archive="/tmp/mongodb-backup.gz" \
    --gzip

docker cp mikrotik-mongodb:/tmp/mongodb-backup.gz "$BACKUP_PATH/"
docker exec mikrotik-mongodb rm /tmp/mongodb-backup.gz

echo "Backing up Redis..."
docker exec mikrotik-redis redis-cli --pass "$REDIS_PASSWORD" BGSAVE
sleep 5
docker cp mikrotik-redis:/data/dump.rdb "$BACKUP_PATH/redis-dump.rdb"

# Backup configurations
echo "Backing up configurations..."
tar -czf "$BACKUP_PATH/configs.tar.gz" \
    /opt/mikrotik-vpn/configs \
    /opt/mikrotik-vpn/nginx \
    /opt/mikrotik-vpn/app/.env \
    /opt/mikrotik-vpn/docker-compose.yml \
    /opt/mikrotik-vpn/.env \
    2>/dev/null

# Create backup info
cat << INFO > "$BACKUP_PATH/backup-info.txt"
Backup Information
==================
Date: $(date)
System: MikroTik VPN Management System
Version: 5.0
Domain: $DOMAIN_NAME

Contents:
- MongoDB database
- Redis database
- System configurations
INFO

# Compress backup
echo "Compressing backup..."
cd "$BACKUP_DIR"
tar -czf "$BACKUP_NAME.tar.gz" "$BACKUP_NAME"
rm -rf "$BACKUP_NAME"

# Clean old backups (keep last 7)
ls -t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | tail -n +8 | xargs -r rm

echo "Backup completed: $BACKUP_DIR/$BACKUP_NAME.tar.gz"
echo "Size: $(du -h "$BACKUP_DIR/$BACKUP_NAME.tar.gz" | cut -f1)"
EOF
}

# Create VPN management scripts
create_vpn_scripts_fixed() {
    cat << 'EOF' > "$SCRIPT_DIR/create-vpn-client.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

read -p "Enter client name (alphanumeric, no spaces): " CLIENT_NAME

# Validate input
if [[ ! $CLIENT_NAME =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Invalid client name. Use only letters, numbers, hyphens, and underscores."
    exit 1
fi

echo "Creating VPN client: $CLIENT_NAME"

# Check if OpenVPN is running
if ! docker ps | grep -q mikrotik-openvpn; then
    echo "OpenVPN is not running. Starting it..."
    cd /opt/mikrotik-vpn && docker compose up -d openvpn
    sleep 10
fi

# Check if PKI is initialized
if ! docker exec mikrotik-openvpn test -f /etc/openvpn/easy-rsa/pki/ca.crt 2>/dev/null; then
    echo "Initializing OpenVPN PKI..."
    docker exec mikrotik-openvpn /etc/openvpn/init-pki.sh
fi

# Generate client certificate
docker exec mikrotik-openvpn bash -c "
cd /etc/openvpn/easy-rsa
./easyrsa --batch gen-req $CLIENT_NAME nopass
./easyrsa --batch sign-req client $CLIENT_NAME
"

# Create client configuration
mkdir -p /opt/mikrotik-vpn/clients

cat << OVPN > "/opt/mikrotik-vpn/clients/$CLIENT_NAME.ovpn"
client
dev tun
proto udp
remote $DOMAIN_NAME 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA512
comp-lzo
verb 3

<ca>
$(docker exec mikrotik-openvpn cat /etc/openvpn/easy-rsa/pki/ca.crt)
</ca>

<cert>
$(docker exec mikrotik-openvpn cat /etc/openvpn/easy-rsa/pki/issued/$CLIENT_NAME.crt | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p')
</cert>

<key>
$(docker exec mikrotik-openvpn cat /etc/openvpn/easy-rsa/pki/private/$CLIENT_NAME.key)
</key>

<tls-auth>
$(docker exec mikrotik-openvpn cat /etc/openvpn/easy-rsa/ta.key)
</tls-auth>
key-direction 1
OVPN

echo "VPN client configuration created: /opt/mikrotik-vpn/clients/$CLIENT_NAME.ovpn"
echo
echo "To use this configuration:"
echo "1. Copy the .ovpn file to your device"
echo "2. Import it into your OpenVPN client"
echo "3. Connect using the imported profile"
EOF

    chmod +x "$SCRIPT_DIR"/*.sh
}

# =============================================================================
# PHASE 9: SECURITY CONFIGURATION (ADAPTIVE)
# =============================================================================

phase9_security_configuration() {
    log "==================================================================="
    log "PHASE 9: SECURITY CONFIGURATION (ADAPTIVE)"
    log "==================================================================="
    
    # Configure firewall if available
    if command -v ufw &> /dev/null && [[ "$IS_CONTAINER" != "true" ]]; then
        setup_firewall_fixed
    else
        log_warning "Firewall configuration skipped (not available in this environment)"
    fi
    
    # Configure Fail2ban if systemd is available
    if [[ "$NO_SYSTEMD" != "true" ]] && command -v fail2ban-client &> /dev/null; then
        setup_fail2ban_fixed
    else
        log_warning "Fail2ban configuration skipped (requires systemd)"
    fi
    
    # SSH hardening
    if [[ -d /etc/ssh ]] && [[ "$IS_CONTAINER" != "true" ]]; then
        harden_ssh_fixed
    else
        log_warning "SSH hardening skipped (not applicable in this environment)"
    fi
    
    log "Phase 9 completed successfully!"
}

# Setup firewall with checks
setup_firewall_fixed() {
    log "Configuring UFW firewall..."
    
    # Check if UFW is already configured
    if ufw status | grep -q "Status: active"; then
        log "Firewall is already active, updating rules..."
    fi
    
    # Reset firewall
    ufw --force disable
    echo "y" | ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow "$SSH_PORT/tcp" comment 'SSH'
    
    # Allow web traffic
    ufw allow 9080/tcp comment 'HTTP'
    ufw allow 9443/tcp comment 'HTTPS'
    
    # Allow VPN
    ufw allow 1194/udp comment 'OpenVPN'
    
    # Allow Docker network
    ufw allow from 172.20.0.0/16 comment 'Docker network'
    
    # Enable firewall
    echo "y" | ufw enable
    
    log "Firewall configured successfully"
}

# Setup Fail2ban
setup_fail2ban_fixed() {
    log "Configuring Fail2ban..."
    
    # Create jail configuration
    cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = $ADMIN_EMAIL
sender = fail2ban@$DOMAIN_NAME
action = %(action_mwl)s

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF

    # Restart Fail2ban
    systemctl restart fail2ban
    systemctl enable fail2ban
    
    log "Fail2ban configured successfully"
}

# SSH hardening
harden_ssh_fixed() {
    log "Hardening SSH configuration..."
    
    # Only proceed if SSH config directory exists
    if [[ ! -d /etc/ssh/sshd_config.d ]]; then
        mkdir -p /etc/ssh/sshd_config.d
    fi
    
    # Create SSH hardening config
    cat << EOF > /etc/ssh/sshd_config.d/99-mikrotik-vpn.conf
# MikroTik VPN SSH Hardening
Port $SSH_PORT
Protocol 2
LoginGraceTime 30
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 5
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

    # Test configuration
    if sshd -t 2>/dev/null; then
        # Restart SSH if systemd is available
        if [[ "$NO_SYSTEMD" != "true" ]]; then
            systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
        fi
        log "SSH hardening completed"
    else
        log_warning "SSH configuration test failed, reverting"
        rm -f /etc/ssh/sshd_config.d/99-mikrotik-vpn.conf
    fi
}

# =============================================================================
# PHASE 10: FINAL SETUP AND VERIFICATION
# =============================================================================

phase10_final_setup() {
    log "==================================================================="
    log "PHASE 10: FINAL SETUP AND VERIFICATION"
    log "==================================================================="
    
    # Load configuration
    if [[ -f "$CONFIG_DIR/setup.env" ]]; then
        source "$CONFIG_DIR/setup.env"
    fi
    
    # Create systemd service or init script
    create_system_service
    
    # Set final permissions
    set_final_permissions_fixed
    
    # Initialize OpenVPN
    initialize_openvpn_fixed
    
    # Start all services
    start_all_services_fixed
    
    # Wait for services to stabilize
    log "Waiting for services to stabilize..."
    sleep 30
    
    # Run final health check
    run_final_health_check_fixed
    
    # Create completion report
    create_completion_report_fixed
    
    log "Phase 10 completed successfully!"
}

# Create system service based on environment
create_system_service() {
    if [[ "$NO_SYSTEMD" != "true" ]]; then
        # Create systemd service
        cat << EOF > /etc/systemd/system/mikrotik-vpn.service
[Unit]
Description=MikroTik VPN Management System
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/mikrotik-vpn
ExecStart=/opt/mikrotik-vpn/scripts/start-services.sh
ExecStop=/opt/mikrotik-vpn/scripts/stop-services.sh
TimeoutStartSec=300
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable mikrotik-vpn.service
        log "Systemd service created and enabled"
    else
        log_warning "Systemd not available, service auto-start not configured"
        log_info "Use 'mikrotik-vpn start' to start services manually"
    fi
}

# Set final permissions
set_final_permissions_fixed() {
    chown -R mikrotik-vpn:mikrotik-vpn "$SYSTEM_DIR" 2>/dev/null || true
    chown -R mikrotik-vpn:mikrotik-vpn "$LOG_DIR" 2>/dev/null || true
    chmod -R 755 "$SYSTEM_DIR"
    chmod 700 "$CONFIG_DIR"
    chmod 600 "$CONFIG_DIR"/* 2>/dev/null || true
    chmod 700 "$SYSTEM_DIR/ssl" 2>/dev/null || true
    chmod 755 "$SCRIPT_DIR"/*.sh 2>/dev/null || true
    
    log "Permissions set successfully"
}

# Initialize OpenVPN with proper checks
initialize_openvpn_fixed() {
    log "Initializing OpenVPN PKI..."
    
    # Ensure Docker is running
    if ! docker ps &>/dev/null; then
        log_warning "Docker not running, skipping OpenVPN initialization"
        return
    fi
    
    cd "$SYSTEM_DIR" || return
    
    # Start OpenVPN container
    docker compose up -d openvpn 2>/dev/null || true
    sleep 10
    
    # Initialize PKI if container is running
    if docker ps | grep -q mikrotik-openvpn; then
        if ! docker exec mikrotik-openvpn test -f /etc/openvpn/easy-rsa/pki/ca.crt 2>/dev/null; then
            docker exec mikrotik-openvpn /etc/openvpn/init-pki.sh || \
                log_warning "OpenVPN PKI initialization failed"
        else
            log "OpenVPN PKI already initialized"
        fi
    else
        log_warning "OpenVPN container not running"
    fi
}

# Start all services with proper environment handling
start_all_services_fixed() {
    log "Starting all services..."
    
    # Use the start script which handles Docker startup
    "$SCRIPT_DIR/start-services.sh"
}

# Run final health check
run_final_health_check_fixed() {
    log "Running final health check..."
    "$SCRIPT_DIR/health-check.sh" | tee -a "$LOG_FILE"
}

# Create completion report
create_completion_report_fixed() {
    local report_file="$SYSTEM_DIR/INSTALLATION_REPORT.txt"
    
    cat << EOF > "$report_file"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║                 MikroTik VPN Management System v5.0                           ║
║                                                                               ║
║                     INSTALLATION COMPLETED SUCCESSFULLY!                       ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Installation Date: $(date)
System Version: 5.0
Domain: $DOMAIN_NAME
Admin Email: $ADMIN_EMAIL
Environment: $([ "$NO_SYSTEMD" = "true" ] && echo "No systemd" || echo "Standard")

═══════════════════════════════════════════════════════════════════════════════
ACCESS INFORMATION
═══════════════════════════════════════════════════════════════════════════════

Web Interfaces:
  Main Application:     http://localhost:9080
  Secure Access:        https://localhost:9443
  MongoDB Express:      http://localhost:8081 (admin / $MONGO_ROOT_PASSWORD)
  Redis Commander:      http://localhost:8082 (admin / $REDIS_PASSWORD)
  Prometheus:           http://localhost:9090
  Grafana:              http://localhost:3001 (admin / $GRAFANA_PASSWORD)

API Endpoints:
  Health Check:         http://localhost:9080/health
  API Info:             http://localhost:9080/api
  Metrics:              http://localhost:9080/metrics

VPN Access:
  OpenVPN Port:         1194/udp
  Configuration:        /opt/mikrotik-vpn/clients/

SSH Access:
  Port:                 $SSH_PORT
  Users:                mikrotik-vpn, ${SUDO_USER:-current user}

═══════════════════════════════════════════════════════════════════════════════
MANAGEMENT COMMANDS
═══════════════════════════════════════════════════════════════════════════════

System Management:
  mikrotik-vpn                    - Open management interface
  mikrotik-vpn status             - Check system status
  mikrotik-vpn start              - Start all services
  mikrotik-vpn stop               - Stop all services
  mikrotik-vpn restart            - Restart all services
  mikrotik-vpn health             - Run health check

Quick Commands:
  cd /opt/mikrotik-vpn && docker compose ps        - Show containers
  cd /opt/mikrotik-vpn && docker compose logs -f   - View logs
  docker exec -it mikrotik-mongodb mongosh         - Access MongoDB
  docker exec -it mikrotik-redis redis-cli         - Access Redis

═══════════════════════════════════════════════════════════════════════════════
IMPORTANT NOTES
═══════════════════════════════════════════════════════════════════════════════

1. SSL Certificate:
   - Currently using self-signed certificate
   - To install Let's Encrypt certificate, ensure ports 80/443 are accessible
   - Update domain DNS to point to this server

2. Firewall:
   - Ports 9080 (HTTP) and 9443 (HTTPS) are used for web access
   - Port 1194/udp is used for OpenVPN
   - Ensure these ports are open in your network firewall

3. Docker:
   $(if [[ "$NO_SYSTEMD" == "true" ]]; then
       echo "- Docker must be started manually (no systemd detected)"
       echo "- Use: mikrotik-vpn start"
   else
       echo "- Docker is managed by systemd"
       echo "- Will start automatically on boot"
   fi)

4. Backups:
   - Run regular backups: mikrotik-vpn backup
   - Backup location: /opt/mikrotik-vpn/backups/

5. Monitoring:
   - Access Grafana for system metrics
   - Default dashboards are pre-configured

═══════════════════════════════════════════════════════════════════════════════
NEXT STEPS
═══════════════════════════════════════════════════════════════════════════════

1. Access the web interface:
   - Open http://localhost:9080 in your browser
   - Or https://localhost:9443 for secure access

2. Create your first VPN client:
   - Run: /opt/mikrotik-vpn/scripts/create-vpn-client.sh
   - Or use: mikrotik-vpn (then select VPN management)

3. Configure your domain:
   - Update DNS to point to this server
   - Install proper SSL certificate

4. Review security settings:
   - Change default passwords if needed
   - Configure firewall rules
   - Set up regular backups

═══════════════════════════════════════════════════════════════════════════════
TROUBLESHOOTING
═══════════════════════════════════════════════════════════════════════════════

If services don't start:
1. Check Docker: docker ps
2. View logs: cd /opt/mikrotik-vpn && docker compose logs
3. Run health check: mikrotik-vpn health
4. Restart Docker: mikrotik-vpn restart

For support, save this installation report and the logs in:
- Installation log: $LOG_FILE
- Service logs: /opt/mikrotik-vpn/logs/

Installation ID: $(uuidgen 2>/dev/null || echo "$(date +%s)-$")

═══════════════════════════════════════════════════════════════════════════════
EOF

    # Display report
    cat "$report_file"
    
    # Save credentials separately
    cat << EOF > "$CONFIG_DIR/credentials.txt"
MikroTik VPN System Credentials
Generated: $(date)
=====================================

MongoDB:
  Root: admin / $MONGO_ROOT_PASSWORD
  App: mikrotik_app / $MONGO_APP_PASSWORD

Redis:
  Password: $REDIS_PASSWORD

Grafana:
  Admin: admin / $GRAFANA_PASSWORD

API Key: $API_KEY

IMPORTANT: Keep this file secure!
EOF
    
    chmod 600 "$CONFIG_DIR/credentials.txt"
}

# =============================================================================
# CLEANUP AND ERROR HANDLING
# =============================================================================

cleanup() {
    log "Performing cleanup..."
    rm -rf "$TEMP_DIR"
    
    # Clean up manual Docker if needed
    if [[ -f /var/run/docker-manual.pid ]] && [[ "${CLEANUP_DOCKER:-true}" == "true" ]]; then
        kill $(cat /var/run/docker-manual.pid) 2>/dev/null || true
        rm -f /var/run/docker-manual.pid
    fi
}

trap cleanup EXIT

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Initialize
    print_header
    check_root
    
    # Run installation phases
    phase0_system_detection
    phase1_configuration
    phase2_system_preparation
    phase3_docker_installation
    phase4_directory_structure
    phase5_nodejs_application
    phase6_configuration_files
    phase7_docker_compose
    phase8_management_scripts
    phase9_security_configuration
    phase10_final_setup
    
    # Success
    log "=================================================================="
    log "MikroTik VPN Management System installation completed successfully!"
    log "=================================================================="
    log ""
    log "To manage the system, run: mikrotik-vpn"
    log ""
    
    # Don't cleanup Docker on successful completion
    CLEANUP_DOCKER=false
    
    return 0
}

# Create additional utility scripts
create_utility_scripts_fixed() {
    # Update system script
    cat << 'EOF' > "$SCRIPT_DIR/update-system.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== System Update ==="
echo

# Check if Docker is running
if ! docker ps &>/dev/null; then
    echo "Docker is not running. Starting Docker..."
    $SCRIPT_DIR/start-docker.sh || exit 1
fi

echo "Pulling latest Docker images..."
cd /opt/mikrotik-vpn || exit 1
docker compose pull

echo
echo "Rebuilding application..."
docker compose build app

echo
echo "Restarting services with new images..."
docker compose up -d

echo
echo "Cleaning up old images..."
docker image prune -f

echo
echo "Update completed!"
docker compose ps
EOF

    # Show configuration script
    cat << 'EOF' > "$SCRIPT_DIR/show-config.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== System Configuration ==="
echo

echo "Basic Information:"
echo "  Domain: $DOMAIN_NAME"
echo "  Admin Email: $ADMIN_EMAIL"
echo "  VPN Network: $VPN_NETWORK"
echo "  SSH Port: $SSH_PORT"
echo "  Environment: $([ "$NO_SYSTEMD" = "true" ] && echo "No systemd" || echo "Standard")"
echo

echo "Service URLs:"
echo "  Main: http://localhost:9080"
echo "  Secure: https://localhost:9443"
echo "  MongoDB: http://localhost:8081"
echo "  Redis: http://localhost:8082"
echo "  Prometheus: http://localhost:9090"
echo "  Grafana: http://localhost:3001"
echo

echo "Database Credentials:"
echo "  MongoDB Root: admin / [Protected]"
echo "  MongoDB App: mikrotik_app / [Protected]"
echo "  Redis: [Protected]"
echo "  Grafana: admin / [Protected]"
echo

echo "Configuration Files:"
echo "  Environment: $CONFIG_DIR/setup.env"
echo "  Credentials: $CONFIG_DIR/credentials.txt"
echo "  Docker Compose: $SYSTEM_DIR/docker-compose.yml"
echo "  Nginx: $SYSTEM_DIR/nginx/conf.d/"
echo "  Application: $SYSTEM_DIR/app/.env"
echo

echo "To view credentials, check: $CONFIG_DIR/credentials.txt"
EOF

    # List VPN clients script
    cat << 'EOF' > "$SCRIPT_DIR/list-vpn-clients.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== VPN Clients ==="
echo

if [[ -d "/opt/mikrotik-vpn/clients" ]]; then
    clients=$(ls -1 /opt/mikrotik-vpn/clients/*.ovpn 2>/dev/null | wc -l)
    
    if [[ $clients -gt 0 ]]; then
        echo "Configured clients ($clients total):"
        echo "─────────────────────────────"
        ls -1 /opt/mikrotik-vpn/clients/*.ovpn | while read file; do
            client_name=$(basename "$file" .ovpn)
            file_size=$(ls -lh "$file" | awk '{print $5}')
            file_date=$(ls -l "$file" | awk '{print $6" "$7" "$8}')
            echo "• $client_name (Created: $file_date, Size: $file_size)"
        done
    else
        echo "No client configurations found."
    fi
else
    echo "Clients directory not found."
fi

echo
echo "=== Currently Connected Clients ==="
if docker ps | grep -q mikrotik-openvpn; then
    if docker exec mikrotik-openvpn test -f /var/log/openvpn-status.log 2>/dev/null; then
        connected=$(docker exec mikrotik-openvpn grep -c "CLIENT_LIST" /var/log/openvpn-status.log 2>/dev/null || echo "0")
        if [[ $connected -gt 0 ]]; then
            echo "Connected clients ($connected):"
            echo "───────────────────────────"
            docker exec mikrotik-openvpn cat /var/log/openvpn-status.log | grep "CLIENT_LIST" | awk -F',' '{print "• "$2" - IP: "$3" - Connected since: "$8}'
        else
            echo "No clients currently connected."
        fi
    else
        echo "OpenVPN status log not available."
    fi
else
    echo "OpenVPN container is not running."
fi
EOF

    # Export configuration script
    cat << 'EOF' > "$SCRIPT_DIR/export-config.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

EXPORT_DIR="/tmp/mikrotik-vpn-export-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EXPORT_DIR"

echo "Exporting configuration..."

# Create info file
cat << INFO > "$EXPORT_DIR/README.txt"
MikroTik VPN System Configuration Export
========================================
Date: $(date)
Domain: $DOMAIN_NAME
Version: 5.0

This export contains configuration files with sensitive data removed.
To import on another system, place files in appropriate locations and update credentials.
INFO

# Copy configuration files
cp -r /opt/mikrotik-vpn/configs "$EXPORT_DIR/"
cp /opt/mikrotik-vpn/docker-compose.yml "$EXPORT_DIR/"
cp /opt/mikrotik-vpn/.env "$EXPORT_DIR/"

# Copy scripts
mkdir -p "$EXPORT_DIR/scripts"
cp -r /opt/mikrotik-vpn/scripts/*.sh "$EXPORT_DIR/scripts/"

# Copy nginx configs
mkdir -p "$EXPORT_DIR/nginx"
cp -r /opt/mikrotik-vpn/nginx/conf.d "$EXPORT_DIR/nginx/"

# Remove sensitive data
find "$EXPORT_DIR" -type f -name "*.env" -o -name "setup.env" | while read file; do
    sed -i 's/MONGO_ROOT_PASSWORD=.*/MONGO_ROOT_PASSWORD=<REDACTED>/' "$file"
    sed -i 's/MONGO_APP_PASSWORD=.*/MONGO_APP_PASSWORD=<REDACTED>/' "$file"
    sed -i 's/REDIS_PASSWORD=.*/REDIS_PASSWORD=<REDACTED>/' "$file"
    sed -i 's/JWT_SECRET=.*/JWT_SECRET=<REDACTED>/' "$file"
    sed -i 's/SESSION_SECRET=.*/SESSION_SECRET=<REDACTED>/' "$file"
    sed -i 's/API_KEY=.*/API_KEY=<REDACTED>/' "$file"
    sed -i 's/GRAFANA_PASSWORD=.*/GRAFANA_PASSWORD=<REDACTED>/' "$file"
    sed -i 's/L2TP_PSK=.*/L2TP_PSK=<REDACTED>/' "$file"
done

# Remove credentials file
rm -f "$EXPORT_DIR/configs/credentials.txt"

# Create archive
cd /tmp
tar -czf "$EXPORT_DIR.tar.gz" "$(basename $EXPORT_DIR)"
rm -rf "$EXPORT_DIR"

echo "Configuration exported to: $EXPORT_DIR.tar.gz"
echo "Size: $(du -h $EXPORT_DIR.tar.gz | cut -f1)"
EOF

    # View logs script
    cat << 'EOF' > "$SCRIPT_DIR/view-logs.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

show_menu() {
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                    Log Viewer                                 ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo
    echo "Select service to view logs:"
    echo "1. All services (combined)"
    echo "2. Application"
    echo "3. MongoDB"
    echo "4. Redis"
    echo "5. Nginx"
    echo "6. OpenVPN"
    echo "7. Prometheus"
    echo "8. Grafana"
    echo "9. Installation log"
    echo "0. Exit"
    echo
}

cd /opt/mikrotik-vpn || exit 1

while true; do
    show_menu
    read -p "Enter choice (0-9): " choice
    
    case $choice in
        1) docker compose logs -f --tail=100 ;;
        2) docker compose logs -f --tail=100 app ;;
        3) docker compose logs -f --tail=100 mongodb ;;
        4) docker compose logs -f --tail=100 redis ;;
        5) docker compose logs -f --tail=100 nginx ;;
        6) docker compose logs -f --tail=100 openvpn ;;
        7) docker compose logs -f --tail=100 prometheus ;;
        8) docker compose logs -f --tail=100 grafana ;;
        9) less +G /var/log/mikrotik-vpn/installation.log ;;
        0) exit 0 ;;
        *) echo "Invalid choice"; sleep 2 ;;
    esac
done
EOF

    # Reset password script
    cat << 'EOF' > "$SCRIPT_DIR/reset-password.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                  Password Reset Utility                       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

echo "Select password to reset:"
echo "1. MongoDB admin password"
echo "2. Redis password"
echo "3. Grafana admin password"
echo "4. Application user password"
echo "5. Exit"
echo

read -p "Enter choice (1-5): " choice

case $choice in
    1)
        echo
        echo "This will reset the MongoDB admin password."
        read -p "Continue? (y/n): " confirm
        
        if [[ $confirm != "y" ]]; then
            echo "Cancelled."
            exit 0
        fi
        
        # Generate new password
        NEW_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
        
        echo "New MongoDB admin password: $NEW_PASSWORD"
        echo
        
        # Update MongoDB password
        echo "Updating MongoDB password..."
        docker exec mikrotik-mongodb mongosh --eval "
        use admin
        db.changeUserPassword('admin', '$NEW_PASSWORD')
        " -u admin -p "$MONGO_ROOT_PASSWORD" --authenticationDatabase admin
        
        if [[ $? -eq 0 ]]; then
            # Update configuration files
            sed -i "s/MONGO_ROOT_PASSWORD=.*/MONGO_ROOT_PASSWORD=$NEW_PASSWORD/" /opt/mikrotik-vpn/configs/setup.env
            sed -i "s/MONGO_ROOT_PASSWORD=.*/MONGO_ROOT_PASSWORD=$NEW_PASSWORD/" /opt/mikrotik-vpn/.env
            
            # Update credentials file
            sed -i "s/MongoDB Root: .*/MongoDB Root: $NEW_PASSWORD/" /opt/mikrotik-vpn/configs/credentials.txt
            
            echo "Password updated successfully. Please restart services."
        else
            echo "Failed to update password."
        fi
        ;;
        
    2)
        echo
        echo "Redis password reset requires service restart."
        read -p "Continue? (y/n): " confirm
        
        if [[ $confirm != "y" ]]; then
            echo "Cancelled."
            exit 0
        fi
        
        # Generate new password
        NEW_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
        
        echo "New Redis password: $NEW_PASSWORD"
        
        # Update configuration
        sed -i "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=$NEW_PASSWORD/" /opt/mikrotik-vpn/configs/setup.env
        sed -i "s/REDIS_PASSWORD=.*/REDIS_PASSWORD=$NEW_PASSWORD/" /opt/mikrotik-vpn/.env
        sed -i "s/requirepass .*/requirepass $NEW_PASSWORD/" /opt/mikrotik-vpn/redis/redis.conf
        
        # Update credentials file
        sed -i "s/Redis: .*/Redis: $NEW_PASSWORD/" /opt/mikrotik-vpn/configs/credentials.txt
        
        echo "Configuration updated. Restarting Redis..."
        docker compose restart redis app
        ;;
        
    3)
        echo
        echo "Resetting Grafana admin password..."
        
        # Generate new password
        NEW_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
        
        docker exec mikrotik-grafana grafana-cli admin reset-admin-password "$NEW_PASSWORD"
        
        if [[ $? -eq 0 ]]; then
            # Update configuration
            sed -i "s/GRAFANA_PASSWORD=.*/GRAFANA_PASSWORD=$NEW_PASSWORD/" /opt/mikrotik-vpn/configs/setup.env
            sed -i "s/GRAFANA_PASSWORD=.*/GRAFANA_PASSWORD=$NEW_PASSWORD/" /opt/mikrotik-vpn/.env
            
            # Update credentials file
            sed -i "s/Grafana Password: .*/Grafana Password: $NEW_PASSWORD/" /opt/mikrotik-vpn/configs/credentials.txt
            
            echo "Grafana admin password reset to: $NEW_PASSWORD"
        else
            echo "Failed to reset Grafana password."
        fi
        ;;
        
    4)
        echo
        echo "Application user password reset"
        read -p "Enter username: " username
        
        # This would require implementing password reset in the application
        echo "Feature not yet implemented. Please use the application API."
        ;;
        
    5)
        exit 0
        ;;
        
    *)
        echo "Invalid choice"
        ;;
esac
EOF

    # Security audit script
    cat << 'EOF' > "$SCRIPT_DIR/security-audit.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Security Audit Report                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo
echo "Date: $(date)"
echo "System: MikroTik VPN Management System v5.0"
echo

# Check for world-writable files
echo "1. World-Writable Files Check"
echo "───────────────────────────"
writable_files=$(find /opt/mikrotik-vpn -type f -perm -002 2>/dev/null | wc -l)
if [[ $writable_files -eq 0 ]]; then
    echo "✓ No world-writable files found"
else
    echo "⚠ Found $writable_files world-writable files:"
    find /opt/mikrotik-vpn -type f -perm -002 2>/dev/null | head -10
fi
echo

# Check file permissions
echo "2. Configuration File Permissions"
echo "───────────────────────────────"
for file in /opt/mikrotik-vpn/configs/setup.env /opt/mikrotik-vpn/.env /opt/mikrotik-vpn/configs/credentials.txt; do
    if [[ -f "$file" ]]; then
        perms=$(stat -c "%a" "$file")
        if [[ "$perms" == "600" ]]; then
            echo "✓ $file: $perms (secure)"
        else
            echo "⚠ $file: $perms (should be 600)"
        fi
    fi
done
echo

# Check listening ports
echo "3. Open Ports"
echo "────────────"
if command -v ss &>/dev/null; then
    ss -tulpn 2>/dev/null | grep LISTEN | grep -E "(9080|9443|27017|6379|1194|3000|9090|3001)" | while read line; do
        port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
        service=$(echo "$line" | awk '{print $1}')
        echo "• Port $port ($service)"
    done
else
    netstat -tulpn 2>/dev/null | grep LISTEN
fi
echo

# Check Docker container security
echo "4. Docker Container Status"
echo "────────────────────────"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep mikrotik
echo

# Check for security updates
echo "5. System Security Updates"
echo "────────────────────────"
if command -v apt &>/dev/null; then
    updates=$(apt list --upgradable 2>/dev/null | grep -i security | wc -l)
    if [[ $updates -eq 0 ]]; then
        echo "✓ No security updates available"
    else
        echo "⚠ $updates security updates available"
        echo "  Run: apt update && apt upgrade"
    fi
fi
echo

# Check SSL certificate
echo "6. SSL Certificate Status"
echo "───────────────────────"
if [[ -f /opt/mikrotik-vpn/nginx/ssl/fullchain.pem ]]; then
    expiry=$(openssl x509 -enddate -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem 2>/dev/null | cut -d= -f2)
    issuer=$(openssl x509 -issuer -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem 2>/dev/null | cut -d= -f2-)
    echo "✓ Certificate found"
    echo "  Expires: $expiry"
    echo "  Issuer: $issuer"
    
    # Check if self-signed
    if echo "$issuer" | grep -q "MikroTik VPN"; then
        echo "  ⚠ Self-signed certificate detected"
    fi
else
    echo "✗ No SSL certificate found"
fi
echo

# Check failed login attempts
echo "7. Authentication Security"
echo "────────────────────────"
if [[ -f /var/log/auth.log ]]; then
    failed_ssh=$(grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l)
    echo "SSH failed login attempts: $failed_ssh"
    
    if [[ $failed_ssh -gt 10 ]]; then
        echo "⚠ High number of failed SSH attempts detected"
        echo "  Recent attempts:"
        grep "Failed password" /var/log/auth.log 2>/dev/null | tail -3 | sed 's/^/  /'
    fi
else
    echo "Auth log not found"
fi
echo

# Check firewall status
echo "8. Firewall Status"
echo "────────────────"
if command -v ufw &>/dev/null; then
    if ufw status | grep -q "Status: active"; then
        echo "✓ UFW firewall is active"
        echo "  Rules:"
        ufw status numbered | grep -E "^\[[0-9]+\]" | head -5 | sed 's/^/  /'
    else
        echo "⚠ UFW firewall is not active"
    fi
elif command -v iptables &>/dev/null; then
    rules=$(iptables -L -n | grep -E "(ACCEPT|DROP|REJECT)" | wc -l)
    echo "iptables rules: $rules"
fi
echo

# Summary
echo "════════════════════════════════════════════════════════════════"
echo "Audit Summary:"
if [[ $writable_files -eq 0 ]] && [[ $failed_ssh -lt 10 ]]; then
    echo "✓ No critical security issues found"
else
    echo "⚠ Some security concerns require attention"
fi
echo
echo "Recommendations:"
echo "• Keep system and Docker images updated"
echo "• Monitor failed login attempts"
echo "• Consider installing a proper SSL certificate"
echo "• Review and restrict open ports as needed"
echo "• Enable and configure firewall rules"
echo "════════════════════════════════════════════════════════════════"
EOF

    # Clear logs script
    cat << 'EOF' > "$SCRIPT_DIR/clear-logs.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Log Cleanup Utility                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

echo "This will clear logs for:"
echo "• Application logs in /var/log/mikrotik-vpn/"
echo "• Docker container logs"
echo "• System installation logs"
echo

echo "Note: This action cannot be undone!"
read -p "Are you sure you want to continue? (yes/no): " confirm

if [[ "$confirm" != "yes" ]]; then
    echo "Operation cancelled."
    exit 0
fi

echo
echo "Clearing logs..."

# Application logs
echo -n "• Clearing application logs... "
find /opt/mikrotik-vpn/logs -name "*.log" -type f -exec truncate -s 0 {} \; 2>/dev/null
find /var/log/mikrotik-vpn -name "*.log" -type f -exec truncate -s 0 {} \; 2>/dev/null
echo "Done"

# Docker logs
echo "• Clearing Docker container logs:"
docker ps --format "{{.Names}}" | grep mikrotik | while read container; do
    echo -n "  - $container... "
    # Docker logs are managed by Docker, we can only truncate logs inside containers
    docker exec $container sh -c 'find /var/log -name "*.log" -type f -exec truncate -s 0 {} \; 2>/dev/null' 2>/dev/null || true
    
    # For containers using stdout/stderr, we need to use Docker's log rotation
    log_file=$(docker inspect --format='{{.LogPath}}' $container 2>/dev/null)
    if [[ -f "$log_file" ]]; then
        truncate -s 0 "$log_file" 2>/dev/null || echo "(requires root)"
    fi
    echo "Done"
done

# Nginx logs
echo -n "• Clearing Nginx logs... "
if [[ -d /opt/mikrotik-vpn/logs/nginx ]]; then
    find /opt/mikrotik-vpn/logs/nginx -name "*.log" -type f -exec truncate -s 0 {} \;
fi
echo "Done"

# Installation log (keep last 1000 lines)
echo -n "• Trimming installation log... "
if [[ -f /var/log/mikrotik-vpn/installation.log ]]; then
    tail -n 1000 /var/log/mikrotik-vpn/installation.log > /tmp/install.log
    mv /tmp/install.log /var/log/mikrotik-vpn/installation.log
fi
echo "Done"

echo
echo "Log cleanup completed!"
echo
echo "Note: Some Docker logs may require root privileges to clear completely."
echo "To fully clear Docker logs, you may need to restart the containers."
EOF

    # Generate API key script
    cat << 'EOF' > "$SCRIPT_DIR/generate-api-key.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "=== Generate API Key ==="
echo

# Generate new API key
NEW_API_KEY=$(openssl rand -base64 32 | tr -d "=+/")

echo "New API Key generated:"
echo "────────────────────"
echo "$NEW_API_KEY"
echo

echo "To use this API key:"
echo "1. Update your application configuration"
echo "2. Add to request headers as: Authorization: Bearer $NEW_API_KEY"
echo

read -p "Save this API key to configuration? (y/n): " save_key

if [[ $save_key == "y" ]]; then
    # Update configuration
    sed -i "s/API_KEY=.*/API_KEY=$NEW_API_KEY/" /opt/mikrotik-vpn/configs/setup.env
    sed -i "s/API_KEY=.*/API_KEY=$NEW_API_KEY/" /opt/mikrotik-vpn/.env
    echo "API key saved to configuration."
    echo "Please restart the application to apply changes."
fi
EOF

    # System info script
    cat << 'EOF' > "$SCRIPT_DIR/system-info.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                 System Information Report                     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

# System Info
echo "System Information"
echo "═════════════════"
echo "Hostname: $(hostname)"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "Timezone: $(timedatectl show -p Timezone --value 2>/dev/null || echo $TIMEZONE)"
echo

# Hardware Info
echo "Hardware Resources"
echo "═════════════════"
echo "CPU Cores: $(nproc)"
echo "CPU Model: $(cat /proc/cpuinfo | grep "model name" | head -1 | cut -d: -f2 | xargs)"
echo "Total Memory: $(free -h | awk '/^Mem:/{print $2}')"
echo "Used Memory: $(free -h | awk '/^Mem:/{print $3}')"
echo "Free Memory: $(free -h | awk '/^Mem:/{print $4}')"
echo "Disk Usage: $(df -h / | awk 'NR==2 {print $3" / "$2" ("$5" used)"}')"
echo

# Docker Info
echo "Docker Information"
echo "═════════════════"
docker --version
docker compose version
echo "Docker Root Dir: $(docker info 2>/dev/null | grep "Docker Root Dir" | cut -d: -f2 | xargs)"
echo "Storage Driver: $(docker info 2>/dev/null | grep "Storage Driver" | cut -d: -f2 | xargs)"
echo "Running Containers: $(docker ps -q | wc -l)"
echo "Total Containers: $(docker ps -aq | wc -l)"
echo "Total Images: $(docker images -q | wc -l)"
echo

# Network Info
echo "Network Configuration"
echo "═══════════════════"
echo "Primary IP: $(ip route get 1 | awk '{print $7}' | head -1)"
echo "Docker Network: $(docker network ls --format '{{.Name}}' | grep mikrotik-vpn-net)"
echo "Open Ports:"
if command -v ss &>/dev/null; then
    ss -tulpn 2>/dev/null | grep LISTEN | grep -E "(9080|9443|27017|6379|1194|3000|9090|3001)" | while read line; do
        port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
        echo "  • Port $port"
    done
fi
echo

# MikroTik VPN Info
echo "MikroTik VPN Configuration"
echo "════════════════════════"
echo "Version: 5.0"
echo "Domain: $DOMAIN_NAME"
echo "Admin Email: $ADMIN_EMAIL"
echo "VPN Network: $VPN_NETWORK"
echo "Installation Date: $(stat -c %y /opt/mikrotik-vpn 2>/dev/null | cut -d' ' -f1)"
echo "Environment Type: $([ "$NO_SYSTEMD" = "true" ] && echo "No systemd" || echo "Standard")"
echo

# Service Status
echo "Service Status"
echo "═════════════"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep mikrotik | while read line; do
    if [[ ! "$line" =~ "NAMES" ]]; then
        name=$(echo "$line" | awk '{print $1}')
        status=$(echo "$line" | awk '{print $2" "$3}')
        echo "• $name: $status"
    fi
done
EOF

    chmod +x "$SCRIPT_DIR"/*.sh
}

# Create MongoDB management scripts
create_mongodb_scripts() {
    # MongoDB shell script
    cat << 'EOF' > "$SCRIPT_DIR/mongo-shell.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "Connecting to MongoDB..."
echo "To exit, type: exit"
echo

docker exec -it mikrotik-mongodb mongosh \
    -u admin -p "$MONGO_ROOT_PASSWORD" \
    --authenticationDatabase admin
EOF

    # MongoDB backup script
    cat << 'EOF' > "$SCRIPT_DIR/backup-mongodb.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

BACKUP_DIR="/opt/mikrotik-vpn/backups/mongodb"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/mongodb-backup-$DATE.gz"

mkdir -p "$BACKUP_DIR"

echo "Starting MongoDB backup..."
echo "Backup directory: $BACKUP_DIR"
echo

# Check if MongoDB is running
if ! docker ps | grep -q mikrotik-mongodb; then
    echo "Error: MongoDB container is not running!"
    exit 1
fi

# Perform backup
echo "Creating backup..."
docker exec mikrotik-mongodb mongodump \
    --uri="mongodb://admin:$MONGO_ROOT_PASSWORD@localhost:27017/admin" \
    --archive="/tmp/backup.gz" \
    --gzip

if [[ $? -eq 0 ]]; then
    # Copy backup from container
    docker cp mikrotik-mongodb:/tmp/backup.gz "$BACKUP_FILE"
    docker exec mikrotik-mongodb rm /tmp/backup.gz
    
    # Get backup size
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    
    echo "Backup completed successfully!"
    echo "File: $BACKUP_FILE"
    echo "Size: $BACKUP_SIZE"
    
    # Keep only last 7 backups
    echo "Cleaning old backups..."
    ls -t "$BACKUP_DIR"/*.gz 2>/dev/null | tail -n +8 | xargs -r rm
    
    # List current backups
    echo
    echo "Current backups:"
    ls -lh "$BACKUP_DIR"/*.gz 2>/dev/null | tail -5
else
    echo "Backup failed!"
    exit 1
fi
EOF

    # MongoDB restore script
    cat << 'EOF' > "$SCRIPT_DIR/restore-mongodb.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

BACKUP_DIR="/opt/mikrotik-vpn/backups/mongodb"

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                 MongoDB Restore Utility                       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

# Check if MongoDB is running
if ! docker ps | grep -q mikrotik-mongodb; then
    echo "Error: MongoDB container is not running!"
    exit 1
fi

# List available backups
echo "Available MongoDB backups:"
echo "────────────────────────"

if [[ -d "$BACKUP_DIR" ]]; then
    backups=$(ls -t "$BACKUP_DIR"/*.gz 2>/dev/null)
    
    if [[ -z "$backups" ]]; then
        echo "No backups found in $BACKUP_DIR"
        exit 1
    fi
    
    i=1
    for backup_file in $backups; do
        backup_name=$(basename "$backup_file")
        backup_size=$(du -h "$backup_file" | cut -f1)
        backup_date=$(stat -c %y "$backup_file" | cut -d' ' -f1,2 | cut -d. -f1)
        echo "$i. $backup_name ($backup_size, $backup_date)"
        i=$((i + 1))
    done
else
    echo "Backup directory not found!"
    exit 1
fi

echo
read -p "Select backup to restore (number) or 0 to cancel: " selection

if [[ $selection -eq 0 ]]; then
    echo "Restore cancelled."
    exit 0
fi

# Get selected backup file
i=1
for backup_file in $backups; do
    if [[ $i -eq $selection ]]; then
        BACKUP_FILE="$backup_file"
        break
    fi
    i=$((i + 1))
done

if [[ -z "$BACKUP_FILE" ]]; then
    echo "Invalid selection!"
    exit 1
fi

echo
echo "Selected: $(basename "$BACKUP_FILE")"
echo
echo "WARNING: This will overwrite the current database!"
echo "All existing data will be lost!"
echo
read -p "Are you sure you want to continue? (yes/no): " confirm

if [[ "$confirm" != "yes" ]]; then
    echo "Restore cancelled."
    exit 0
fi

echo
echo "Starting restore..."

# Copy backup to container
docker cp "$BACKUP_FILE" mikrotik-mongodb:/tmp/restore.gz

# Perform restore
docker exec mikrotik-mongodb mongorestore \
    --uri="mongodb://admin:$MONGO_ROOT_PASSWORD@localhost:27017/admin" \
    --archive="/tmp/restore.gz" \
    --gzip \
    --drop

if [[ $? -eq 0 ]]; then
    docker exec mikrotik-mongodb rm /tmp/restore.gz
    echo
    echo "Restore completed successfully!"
    echo "The database has been restored from: $(basename "$BACKUP_FILE")"
else
    echo
    echo "Restore failed!"
    docker exec mikrotik-mongodb rm -f /tmp/restore.gz
    exit 1
fi
EOF

    # MongoDB status script
    cat << 'EOF' > "$SCRIPT_DIR/mongodb-status.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    MongoDB Status                             ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

# Check if MongoDB is running
if ! docker ps | grep -q mikrotik-mongodb; then
    echo "Error: MongoDB container is not running!"
    exit 1
fi

# Get MongoDB status
docker exec mikrotik-mongodb mongosh \
    -u admin -p "$MONGO_ROOT_PASSWORD" \
    --authenticationDatabase admin \
    --eval "
    print('MongoDB Server Status');
    print('═══════════════════');
    
    var status = db.serverStatus();
    print('Version: ' + status.version);
    print('Uptime: ' + Math.floor(status.uptime / 3600) + ' hours');
    print('Connections: ' + status.connections.current + ' current, ' + status.connections.available + ' available');
    print('');
    
    print('Database Statistics');
    print('═════════════════');
    
    db = db.getSiblingDB('mikrotik_vpn');
    var stats = db.stats();
    print('Database: mikrotik_vpn');
    print('Collections: ' + stats.collections);
    print('Data Size: ' + (stats.dataSize / 1024 / 1024).toFixed(2) + ' MB');
    print('Storage Size: ' + (stats.storageSize / 1024 / 1024).toFixed(2) + ' MB');
    print('');
    
    print('Collections:');
    db.getCollectionNames().forEach(function(col) {
        var count = db[col].countDocuments();
        print('  • ' + col + ': ' + count + ' documents');
    });
    "
EOF

    chmod +x "$SCRIPT_DIR"/*.sh
}

# Create monitoring dashboard JSON
create_monitoring_dashboards() {
    # System overview dashboard
    cat << 'DASHBOARD' > "$SYSTEM_DIR/monitoring/grafana/dashboards/system-overview.json"
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "gnetId": null,
  "graphTooltip": 0,
  "id": null,
  "links": [],
  "panels": [
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "tooltip": false,
              "viz": false,
              "legend": false
            },
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": true,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          },
          "unit": "percent"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "id": 1,
      "options": {
        "tooltip": {
          "mode": "single"
        },
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom"
        }
      },
      "pluginVersion": "8.0.0",
      "targets": [
        {
          "expr": "100 - (avg by (instance) (irate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)",
          "legendFormat": "CPU Usage",
          "refId": "A"
        }
      ],
      "title": "CPU Usage",
      "type": "timeseries"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "tooltip": false,
              "viz": false,
              "legend": false
            },
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": true,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 80
              }
            ]
          },
          "unit": "percent"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 0
      },
      "id": 2,
      "options": {
        "tooltip": {
          "mode": "single"
        },
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom"
        }
      },
      "pluginVersion": "8.0.0",
      "targets": [
        {
          "expr": "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100",
          "legendFormat": "Memory Usage",
          "refId": "A"
        }
      ],
      "title": "Memory Usage",
      "type": "timeseries"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [
            {
              "options": {
                "0": {
                  "color": "red",
                  "index": 1,
                  "text": "Down"
                },
                "1": {
                  "color": "green",
                  "index": 0,
                  "text": "Up"
                }
              },
              "type": "value"
            }
          ],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "red",
                "value": null
              },
              {
                "color": "green",
                "value": 1
              }
            ]
          },
          "unit": "short"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 8
      },
      "id": 3,
      "options": {
        "colorMode": "background",
        "graphMode": "none",
        "justifyMode": "center",
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "text": {},
        "textMode": "auto"
      },
      "pluginVersion": "8.0.0",
      "targets": [
        {
          "expr": "up{job=\"mikrotik-app\"}",
          "legendFormat": "Application",
          "refId": "A"
        },
        {
          "expr": "up{job=\"mongodb\"}",
          "legendFormat": "MongoDB",
          "refId": "B"
        },
        {
          "expr": "up{job=\"redis\"}",
          "legendFormat": "Redis",
          "refId": "C"
        },
        {
          "expr": "up{job=\"nginx\"}",
          "legendFormat": "Nginx",
          "refId": "D"
        }
      ],
      "title": "Service Status",
      "type": "stat"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "tooltip": false,
              "viz": false,
              "legend": false
            },
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": true,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              }
            ]
          },
          "unit": "bytes"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 8
      },
      "id": 4,
      "options": {
        "tooltip": {
          "mode": "single"
        },
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom"
        }
      },
      "pluginVersion": "8.0.0",
      "targets": [
        {
          "expr": "node_filesystem_avail_bytes{mountpoint=\"/\"}",
          "legendFormat": "Available Disk Space",
          "refId": "A"
        }
      ],
      "title": "Disk Space",
      "type": "timeseries"
    }
  ],
  "schemaVersion": 27,
  "style": "dark",
  "tags": [
    "mikrotik",
    "system",
    "overview"
  ],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-6h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "",
  "title": "MikroTik VPN System Overview",
  "uid": "mikrotik-system-overview",
  "version": 0
}
DASHBOARD

    # Application dashboard
    cat << 'DASHBOARD' > "$SYSTEM_DIR/monitoring/grafana/dashboards/application.json"
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "gnetId": null,
  "graphTooltip": 0,
  "id": null,
  "links": [],
  "panels": [
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [
            {
              "options": {
                "0": {
                  "color": "red",
                  "index": 1,
                  "text": "Disconnected"
                },
                "1": {
                  "color": "green",
                  "index": 0,
                  "text": "Connected"
                }
              },
              "type": "value"
            }
          ],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "red",
                "value": null
              },
              {
                "color": "green",
                "value": 1
              }
            ]
          }
        },
        "overrides": []
      },
      "gridPos": {
        "h": 4,
        "w": 6,
        "x": 0,
        "y": 0
      },
      "id": 1,
      "options": {
        "colorMode": "background",
        "graphMode": "none",
        "justifyMode": "center",
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "text": {},
        "textMode": "auto"
      },
      "pluginVersion": "8.0.0",
      "targets": [
        {
          "expr": "app_mongodb_connected",
          "refId": "A"
        }
      ],
      "title": "MongoDB Connection",
      "type": "stat"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [
            {
              "options": {
                "0": {
                  "color": "red",
                  "index": 1,
                  "text": "Disconnected"
                },
                "1": {
                  "color": "green",
                  "index": 0,
                  "text": "Connected"
                }
              },
              "type": "value"
            }
          ],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "red",
                "value": null
              },
              {
                "color": "green",
                "value": 1
              }
            ]
          }
        },
        "overrides": []
      },
      "gridPos": {
        "h": 4,
        "w": 6,
        "x": 6,
        "y": 0
      },
      "id": 2,
      "options": {
        "colorMode": "background",
        "graphMode": "none",
        "justifyMode": "center",
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "text": {},
        "textMode": "auto"
      },
      "pluginVersion": "8.0.0",
      "targets": [
        {
          "expr": "app_redis_connected",
          "refId": "A"
        }
      ],
      "title": "Redis Connection",
      "type": "stat"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "red",
                "value": 0
              }
            ]
          }
        },
        "overrides": []
      },
      "gridPos": {
        "h": 4,
        "w": 6,
        "x": 12,
        "y": 0
      },
      "id": 3,
      "options": {
        "colorMode": "value",
        "graphMode": "none",
        "justifyMode": "center",
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "text": {},
        "textMode": "auto"
      },
      "pluginVersion": "8.0.0",
      "targets": [
        {
          "expr": "app_up",
          "refId": "A"
        }
      ],
      "title": "Application Status",
      "type": "stat"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "tooltip": false,
              "viz": false,
              "legend": false
            },
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": true,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              }
            ]
          },
          "unit": "bytes"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 24,
        "x": 0,
        "y": 4
      },
      "id": 4,
      "options": {
        "tooltip": {
          "mode": "single"
        },
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom"
        }
      },
      "pluginVersion": "8.0.0",
      "targets": [
        {
          "expr": "app_memory_usage_bytes{type=\"heap_used\"}",
          "legendFormat": "Heap Used",
          "refId": "A"
        },
        {
          "expr": "app_memory_usage_bytes{type=\"heap_total\"}",
          "legendFormat": "Heap Total",
          "refId": "B"
        },
        {
          "expr": "app_memory_usage_bytes{type=\"rss\"}",
          "legendFormat": "RSS",
          "refId": "C"
        }
      ],
      "title": "Application Memory Usage",
      "type": "timeseries"
    }
  ],
  "schemaVersion": 27,
  "style": "dark",
  "tags": [
    "mikrotik",
    "application"
  ],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-6h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "",
  "title": "MikroTik VPN Application",
  "uid": "mikrotik-application",
  "version": 0
}
DASHBOARD

    # VPN dashboard
    cat << 'DASHBOARD' > "$SYSTEM_DIR/monitoring/grafana/dashboards/vpn.json"
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": "-- Grafana --",
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "gnetId": null,
  "graphTooltip": 0,
  "id": null,
  "links": [],
  "panels": [
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "thresholds"
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              },
              {
                "color": "yellow",
                "value": 500
              },
              {
                "color": "red",
                "value": 900
              }
            ]
          },
          "unit": "short"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 0,
        "y": 0
      },
      "id": 1,
      "options": {
        "orientation": "auto",
        "reduceOptions": {
          "calcs": [
            "lastNotNull"
          ],
          "fields": "",
          "values": false
        },
        "showThresholdLabels": false,
        "showThresholdMarkers": true
      },
      "pluginVersion": "8.0.0",
      "targets": [
        {
          "expr": "openvpn_server_connected_clients",
          "refId": "A"
        }
      ],
      "title": "Connected VPN Clients",
      "type": "gauge"
    },
    {
      "datasource": "Prometheus",
      "fieldConfig": {
        "defaults": {
          "color": {
            "mode": "palette-classic"
          },
          "custom": {
            "axisLabel": "",
            "axisPlacement": "auto",
            "barAlignment": 0,
            "drawStyle": "line",
            "fillOpacity": 10,
            "gradientMode": "none",
            "hideFrom": {
              "tooltip": false,
              "viz": false,
              "legend": false
            },
            "lineInterpolation": "linear",
            "lineWidth": 1,
            "pointSize": 5,
            "scaleDistribution": {
              "type": "linear"
            },
            "showPoints": "never",
            "spanNulls": true,
            "stacking": {
              "group": "A",
              "mode": "none"
            },
            "thresholdsStyle": {
              "mode": "off"
            }
          },
          "mappings": [],
          "thresholds": {
            "mode": "absolute",
            "steps": [
              {
                "color": "green",
                "value": null
              }
            ]
          },
          "unit": "binBps"
        },
        "overrides": []
      },
      "gridPos": {
        "h": 8,
        "w": 12,
        "x": 12,
        "y": 0
      },
      "id": 2,
      "options": {
        "tooltip": {
          "mode": "single"
        },
        "legend": {
          "calcs": [],
          "displayMode": "list",
          "placement": "bottom"
        }
      },
      "pluginVersion": "8.0.0",
      "targets": [
        {
          "expr": "rate(openvpn_server_route_bytes_sent[5m])",
          "legendFormat": "Bytes Sent",
          "refId": "A"
        },
        {
          "expr": "rate(openvpn_server_route_bytes_received[5m])",
          "legendFormat": "Bytes Received",
          "refId": "B"
        }
      ],
      "title": "VPN Traffic",
      "type": "timeseries"
    }
  ],
  "schemaVersion": 27,
  "style": "dark",
  "tags": [
    "mikrotik",
    "vpn"
  ],
  "templating": {
    "list": []
  },
  "time": {
    "from": "now-6h",
    "to": "now"
  },
  "timepicker": {},
  "timezone": "",
  "title": "MikroTik VPN Status",
  "uid": "mikrotik-vpn",
  "version": 0
}
DASHBOARD
}

# Create SSL management scripts
create_ssl_scripts() {
    # Update SSL script
    cat << 'EOF' > "$SCRIPT_DIR/update-ssl.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                  SSL Certificate Management                   ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

echo "1. Generate new self-signed certificate"
echo "2. Install Let's Encrypt certificate (Certbot)"
echo "3. Import existing certificate"
echo "4. View current certificate info"
echo "5. Setup auto-renewal (Let's Encrypt)"
echo "6. Exit"
echo

read -p "Select option (1-6): " choice

case $choice in
    1)
        echo
        echo "Generating self-signed certificate..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /opt/mikrotik-vpn/nginx/ssl/privkey.pem \
            -out /opt/mikrotik-vpn/nginx/ssl/fullchain.pem \
            -subj "/C=TH/ST=Bangkok/L=Bangkok/O=MikroTik VPN/CN=$DOMAIN_NAME" \
            -addext "subjectAltName=DNS:$DOMAIN_NAME,DNS:admin.$DOMAIN_NAME,DNS:monitor.$DOMAIN_NAME"
        
        echo "Restarting Nginx..."
        docker restart mikrotik-nginx
        echo "✓ Self-signed certificate generated and installed!"
        ;;
        
    2)
        echo
        echo "Installing Let's Encrypt certificate..."
        echo
        echo "Requirements:"
        echo "• Domain must point to this server's IP"
        echo "• Ports 80 and 443 must be accessible from internet"
        echo "• Current domain: $DOMAIN_NAME"
        echo
        read -p "Continue? (y/n): " confirm
        
        if [[ $confirm == "y" ]]; then
            # Stop nginx temporarily
            docker stop mikrotik-nginx
            
            # Run certbot
            docker run -it --rm \
                -v /opt/mikrotik-vpn/nginx/ssl:/etc/letsencrypt \
                -v /opt/mikrotik-vpn/nginx/html:/var/www/certbot \
                -p 80:80 -p 443:443 \
                certbot/certbot certonly \
                --standalone \
                --email $ADMIN_EMAIL \
                --agree-tos \
                --no-eff-email \
                -d $DOMAIN_NAME \
                -d admin.$DOMAIN_NAME \
                -d monitor.$DOMAIN_NAME
            
            if [[ $? -eq 0 ]]; then
                # Create symlinks
                ln -sf /opt/mikrotik-vpn/nginx/ssl/live/$DOMAIN_NAME/fullchain.pem \
                       /opt/mikrotik-vpn/nginx/ssl/fullchain.pem
                ln -sf /opt/mikrotik-vpn/nginx/ssl/live/$DOMAIN_NAME/privkey.pem \
                       /opt/mikrotik-vpn/nginx/ssl/privkey.pem
                
                echo "✓ Let's Encrypt certificate installed!"
            else
                echo "✗ Certificate installation failed!"
            fi
            
            # Start nginx again
            docker start mikrotik-nginx
        fi
        ;;
        
    3)
        echo
        echo "Import existing certificate"
        echo
        echo "Place your certificate files in:"
        echo "  Certificate: /opt/mikrotik-vpn/nginx/ssl/fullchain.pem"
        echo "  Private Key: /opt/mikrotik-vpn/nginx/ssl/privkey.pem"
        echo
        read -p "Press Enter when files are ready..."
        
        if [[ -f /opt/mikrotik-vpn/nginx/ssl/fullchain.pem ]] && \
           [[ -f /opt/mikrotik-vpn/nginx/ssl/privkey.pem ]]; then
            # Set proper permissions
            chmod 644 /opt/mikrotik-vpn/nginx/ssl/fullchain.pem
            chmod 600 /opt/mikrotik-vpn/nginx/ssl/privkey.pem
            
            docker restart mikrotik-nginx
            echo "✓ Certificate imported successfully!"
        else
            echo "✗ Certificate files not found!"
        fi
        ;;
        
    4)
        echo
        echo "Current Certificate Information"
        echo "══════════════════════════════"
        
        if [[ -f /opt/mikrotik-vpn/nginx/ssl/fullchain.pem ]]; then
            echo "Subject:"
            openssl x509 -subject -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem | sed 's/subject=/  /'
            echo
            echo "Issuer:"
            openssl x509 -issuer -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem | sed 's/issuer=/  /'
            echo
            echo "Validity:"
            openssl x509 -dates -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem | sed 's/^/  /'
            echo
            echo "SANs:"
            openssl x509 -text -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/^/  /'
        else
            echo "No certificate found!"
        fi
        ;;
        
    5)
        echo
        echo "Setting up auto-renewal for Let's Encrypt..."
        
        # Create renewal script
        cat << 'RENEW' > /opt/mikrotik-vpn/scripts/renew-certificates.sh
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "[$(date)] Starting certificate renewal..."

# Renew certificates
docker run --rm \
    -v /opt/mikrotik-vpn/nginx/ssl:/etc/letsencrypt \
    -v /opt/mikrotik-vpn/nginx/html:/var/www/certbot \
    certbot/certbot renew \
    --webroot \
    --webroot-path=/var/www/certbot \
    --quiet

if [[ $? -eq 0 ]]; then
    echo "[$(date)] Certificate renewed successfully"
    docker restart mikrotik-nginx
else
    echo "[$(date)] Certificate renewal failed"
fi
RENEW
        
        chmod +x /opt/mikrotik-vpn/scripts/renew-certificates.sh
        
        # Add to crontab
        (crontab -l 2>/dev/null | grep -v "renew-certificates.sh"; echo "0 3 * * * /opt/mikrotik-vpn/scripts/renew-certificates.sh >> /var/log/mikrotik-vpn/cert-renewal.log 2>&1") | crontab -
        
        echo "✓ Auto-renewal configured!"
        echo "Certificates will be checked daily at 3:00 AM"
        ;;
        
    6)
        exit 0
        ;;
        
    *)
        echo "Invalid option"
        ;;
esac
EOF

    # SSL certificate info script
    cat << 'EOF' > "$SCRIPT_DIR/check-ssl.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    SSL Certificate Check                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

# Check certificate file
if [[ ! -f /opt/mikrotik-vpn/nginx/ssl/fullchain.pem ]]; then
    echo "✗ No SSL certificate found!"
    echo
    echo "Run 'update-ssl.sh' to install a certificate."
    exit 1
fi

# Get certificate info
echo "Certificate Information"
echo "═════════════════════"

# Subject
echo -n "Domain: "
openssl x509 -subject -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem | grep -oP 'CN=\K[^,/]*'

# Issuer
issuer=$(openssl x509 -issuer -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem | grep -oP 'CN=\K[^,/]*')
echo "Issuer: $issuer"

# Check if self-signed
if [[ "$issuer" == *"MikroTik VPN"* ]]; then
    echo "Type: Self-signed certificate ⚠️"
else
    echo "Type: CA-signed certificate ✓"
fi

# Validity
echo
echo "Validity"
echo "────────"
start_date=$(openssl x509 -startdate -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem | cut -d= -f2)
end_date=$(openssl x509 -enddate -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem | cut -d= -f2)

echo "Valid from: $start_date"
echo "Valid until: $end_date"

# Check expiration
end_epoch=$(date -d "$end_date" +%s)
now_epoch=$(date +%s)
days_left=$(( ($end_epoch - $now_epoch) / 86400 ))

echo
if [[ $days_left -lt 0 ]]; then
    echo "Status: ✗ EXPIRED!"
elif [[ $days_left -lt 30 ]]; then
    echo "Status: ⚠️  Expires in $days_left days"
else
    echo "Status: ✓ Valid for $days_left more days"
fi

# SANs
echo
echo "Subject Alternative Names"
echo "───────────────────────"
openssl x509 -text -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem | grep -A1 "Subject Alternative Name" | tail -1 | tr ',' '\n' | sed 's/DNS://g' | sed 's/^[ \t]*/  • /'

# Cipher info
echo
echo "Certificate Details"
echo "─────────────────"
echo -n "Signature Algorithm: "
openssl x509 -text -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem | grep "Signature Algorithm" | head -1 | awk '{print $3}'

echo -n "Public Key: "
openssl x509 -text -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem | grep "Public Key Algorithm" | awk '{print $4}'

# Test HTTPS connection
echo
echo "Connection Test"
echo "─────────────"
if curl -k https://localhost:9443 -o /dev/null -s -w "%{http_code}\n" | grep -q "200\|301\|302"; then
    echo "✓ HTTPS is working"
else
    echo "✗ HTTPS connection failed"
fi

# Check nginx status
if docker ps | grep -q mikrotik-nginx; then
    echo "✓ Nginx is running"
else
    echo "✗ Nginx is not running"
fi
EOF

    chmod +x "$SCRIPT_DIR"/*.sh
}

# Create troubleshooting scripts
create_troubleshooting_scripts() {
    # Diagnostic script
    cat << 'EOF' > "$SCRIPT_DIR/diagnose.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║              MikroTik VPN System Diagnostics                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo
echo "Date: $(date)"
echo "Version: 5.0"
echo

# System information
echo "System Information"
echo "═════════════════"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo "Kernel: $(uname -r)"
echo "CPU: $(nproc) cores"
echo "Memory: $(free -h | awk '/^Mem:/{print $2}')"
echo "Disk: $(df -h / | awk 'NR==2 {print $4}' ) free of $(df -h / | awk 'NR==2 {print $2}')"
echo "Load: $(uptime | awk -F'load average:' '{print $2}')"
echo

# Docker information
echo "Docker Status"
echo "════════════"
docker_version=$(docker --version 2>/dev/null || echo "Not installed")
echo "Docker: $docker_version"
if docker ps &>/dev/null; then
    echo "Docker daemon: ✓ Running"
    echo "Containers: $(docker ps -q | wc -l) running, $(docker ps -aq | wc -l) total"
else
    echo "Docker daemon: ✗ Not running"
fi
echo

# Network information
echo "Network Configuration"
echo "═══════════════════"
echo "Primary IP: $(ip route get 1 | awk '{print $7}' | head -1 || echo "Unknown")"
echo "Docker network: $(docker network ls --format '{{.Name}}' 2>/dev/null | grep mikrotik-vpn-net || echo "Not found")"
echo

# Service status check
echo "Service Status"
echo "════════════"
services="mongodb redis app nginx openvpn prometheus grafana"
all_running=true

for service in $services; do
    if docker ps 2>/dev/null | grep -q "mikrotik-$service"; then
        # Get container status details
        status=$(docker ps --format "table {{.Status}}" --filter "name=mikrotik-$service" | tail -1)
        echo "✓ $service: $status"
    else
        echo "✗ $service: Not running"
        all_running=false
    fi
done
echo

# Port availability
echo "Port Status"
echo "═════════"
ports="9080 9443 3000 27017 6379 1194 9090 3001 8081 8082"
for port in $ports; do
    if nc -z localhost $port 2>/dev/null; then
        service=""
        case $port in
            9080) service="(HTTP)" ;;
            9443) service="(HTTPS)" ;;
            3000) service="(App)" ;;
            27017) service="(MongoDB)" ;;
            6379) service="(Redis)" ;;
            1194) service="(OpenVPN)" ;;
            9090) service="(Prometheus)" ;;
            3001) service="(Grafana)" ;;
            8081) service="(Mongo Express)" ;;
            8082) service="(Redis Commander)" ;;
        esac
        echo "✓ Port $port $service: Open"
    else
        echo "✗ Port $port: Closed"
    fi
done
echo

# Check connectivity
echo "Connectivity Tests"
echo "════════════════"
# Internet connectivity
if ping -c 1 8.8.8.8 &>/dev/null; then
    echo "✓ Internet connectivity: OK"
else
    echo "✗ Internet connectivity: Failed"
fi

# DNS resolution
if nslookup google.com &>/dev/null; then
    echo "✓ DNS resolution: OK"
else
    echo "✗ DNS resolution: Failed"
fi

# MongoDB connectivity
if docker exec mikrotik-mongodb mongosh --eval "db.adminCommand('ping')" -u admin -p "$MONGO_ROOT_PASSWORD" --authenticationDatabase admin --quiet &>/dev/null 2>&1; then
    echo "✓ MongoDB authentication: OK"
else
    echo "✗ MongoDB authentication: Failed"
fi

# Redis connectivity
if docker exec mikrotik-redis redis-cli --pass "$REDIS_PASSWORD" ping 2>/dev/null | grep -q "PONG"; then
    echo "✓ Redis authentication: OK"
else
    echo "✗ Redis authentication: Failed"
fi
echo

# Recent errors
echo "Recent Errors (if any)"
echo "═══════════════════"
if [[ -f /var/log/mikrotik-vpn/installation.log ]]; then
    error_count=$(grep -i "error\|failed" /var/log/mikrotik-vpn/installation.log | wc -l)
    if [[ $error_count -gt 0 ]]; then
        echo "Found $error_count error(s) in installation log:"
        grep -i "error\|failed" /var/log/mikrotik-vpn/installation.log | tail -5 | sed 's/^/  /'
    else
        echo "✓ No errors found in installation log"
    fi
else
    echo "Installation log not found"
fi

# Docker logs errors
echo
echo "Recent Docker errors:"
for service in $services; do
    if docker ps 2>/dev/null | grep -q "mikrotik-$service"; then
        errors=$(docker logs mikrotik-$service 2>&1 | grep -i "error\|fatal" | wc -l)
        if [[ $errors -gt 0 ]]; then
            echo "  $service: $errors error(s) found"
        fi
    fi
done
echo

# Summary
echo "═══════════════════════════════════════════════════════════════"
echo "Diagnostic Summary"
echo "═══════════════════════════════════════════════════════════════"
if [[ "$all_running" == "true" ]] && docker ps &>/dev/null; then
    echo "✓ System appears to be healthy"
else
    echo "⚠ Some issues detected - review the output above"
fi
echo

# Suggestions
if [[ "$all_running" != "true" ]]; then
    echo "Suggestions:"
    echo "• Run 'mikrotik-vpn start' to start all services"
    echo "• Check 'docker compose logs' for detailed error messages"
    echo "• Run 'fix-common-issues.sh' to attempt automatic fixes"
fi
EOF

    # Fix common issues script
    cat << 'EOF' > "$SCRIPT_DIR/fix-common-issues.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                 Common Issues Fix Script                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

echo "This script will attempt to fix common issues."
echo

echo "1. Docker not starting"
echo "2. MongoDB authentication errors"
echo "3. Services not starting"
echo "4. Network connectivity issues"
echo "5. Permission issues"
echo "6. Port conflicts"
echo "7. Full system reset"
echo "8. Exit"
echo

read -p "Select issue to fix (1-8): " choice

case $choice in
    1)
        echo
        echo "Fixing Docker startup issues..."
        
        # Stop everything first
        pkill -f dockerd 2>/dev/null || true
        pkill -f containerd 2>/dev/null || true
        sleep 3
        
        # Clean up
        rm -rf /var/run/docker.sock 2>/dev/null || true
        rm -rf /var/run/docker.pid 2>/dev/null || true
        rm -rf /var/run/docker/ 2>/dev/null || true
        rm -rf /var/lib/docker/network/files/local-kv.db 2>/dev/null || true
        
        # Try to start Docker
        echo "Starting Docker..."
        $SCRIPT_DIR/start-docker.sh
        
        if docker ps &>/dev/null; then
            echo "✓ Docker is now running"
        else
            echo "✗ Docker still not running. Check logs:"
            echo "  /var/log/docker-manual.log"
        fi
        ;;
        
    2)
        echo
        echo "Fixing MongoDB authentication..."
        cd /opt/mikrotik-vpn || exit 1
        
        # Stop MongoDB
        docker compose stop mongodb
        sleep 5
        
        # Start MongoDB without auth temporarily
        echo "Starting MongoDB in recovery mode..."
        docker run -d --name temp-mongo \
            -v /opt/mikrotik-vpn/mongodb/data:/data/db \
            -p 27017:27017 \
            mongo:7.0 mongod --noauth
        
        sleep 10
        
        # Reset passwords
        echo "Resetting MongoDB users..."
        docker exec temp-mongo mongosh --eval "
        use admin
        db.dropUser('admin')
        db.createUser({
            user: 'admin',
            pwd: '$MONGO_ROOT_PASSWORD',
            roles: ['root']
        })
        
        use mikrotik_vpn
        db.dropUser('mikrotik_app')
        db.createUser({
            user: 'mikrotik_app',
            pwd: '$MONGO_APP_PASSWORD',
            roles: [{role: 'readWrite', db: 'mikrotik_vpn'}]
        })
        "
        
        # Stop temp container
        docker stop temp-mongo
        docker rm temp-mongo
        
        # Start MongoDB normally
        docker compose up -d
        
        echo "✓ Services restarted"
        ;;
        
    4)
        echo
        echo "Fixing network connectivity..."
        
        # Fix Docker network
        docker network rm mikrotik-vpn-net 2>/dev/null || true
        docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16
        
        # Fix DNS
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
        echo "nameserver 8.8.4.4" >> /etc/resolv.conf
        
        # Restart services
        cd /opt/mikrotik-vpn && docker compose restart
        
        echo "✓ Network settings updated"
        ;;
        
    5)
        echo
        echo "Fixing permissions..."
        
        # Fix ownership
        chown -R mikrotik-vpn:mikrotik-vpn /opt/mikrotik-vpn
        chown -R mikrotik-vpn:mikrotik-vpn /var/log/mikrotik-vpn
        
        # Fix permissions
        chmod -R 755 /opt/mikrotik-vpn
        chmod 600 /opt/mikrotik-vpn/configs/setup.env
        chmod 600 /opt/mikrotik-vpn/.env
        chmod 600 /opt/mikrotik-vpn/configs/credentials.txt
        chmod 755 /opt/mikrotik-vpn/scripts/*.sh
        
        echo "✓ Permissions fixed"
        ;;
        
    6)
        echo
        echo "Checking for port conflicts..."
        
        ports="9080 9443 3000 27017 6379 1194 9090 3001 8081 8082"
        conflicts=false
        
        for port in $ports; do
            if lsof -i :$port | grep -v "docker\|mikrotik" &>/dev/null; then
                echo "⚠ Port $port is in use by another process:"
                lsof -i :$port | grep -v "docker\|mikrotik" | tail -n +2
                conflicts=true
            fi
        done
        
        if [[ "$conflicts" == "true" ]]; then
            echo
            echo "Found port conflicts. You can:"
            echo "1. Stop the conflicting services"
            echo "2. Change MikroTik VPN ports in docker-compose.yml"
        else
            echo "✓ No port conflicts found"
        fi
        ;;
        
    7)
        echo
        echo "⚠️  WARNING: Full System Reset"
        echo "This will:"
        echo "• Stop all services"
        echo "• Reset all configurations"
        echo "• Clear all data"
        echo
        read -p "Are you SURE you want to continue? (type 'reset' to confirm): " confirm
        
        if [[ "$confirm" == "reset" ]]; then
            echo "Performing full system reset..."
            
            # Stop everything
            cd /opt/mikrotik-vpn
            docker compose down -v
            
            # Remove all containers and images
            docker ps -aq | xargs -r docker rm -f
            docker images | grep mikrotik | awk '{print $3}' | xargs -r docker rmi -f
            
            # Clear data
            rm -rf /opt/mikrotik-vpn/mongodb/data/*
            rm -rf /opt/mikrotik-vpn/redis/data/*
            rm -rf /opt/mikrotik-vpn/logs/*
            
            # Restart from scratch
            $SCRIPT_DIR/start-services.sh
            
            echo "✓ System reset completed"
        else
            echo "Reset cancelled"
        fi
        ;;
        
    8)
        exit 0
        ;;
        
    *)
        echo "Invalid option"
        ;;
esac
EOF

    # Network test script
    cat << 'EOF' > "$SCRIPT_DIR/test-network.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Network Connectivity Test                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

# Test categories
echo "1. External Connectivity"
echo "───────────────────────"

# Internet connectivity
echo -n "• Internet (8.8.8.8): "
if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
    echo "✓ OK"
else
    echo "✗ Failed"
fi

# DNS resolution
echo -n "• DNS (google.com): "
if nslookup google.com &>/dev/null; then
    echo "✓ OK"
else
    echo "✗ Failed"
fi

# HTTPS connectivity
echo -n "• HTTPS (https://www.google.com): "
if curl -s -o /dev/null -w "%{http_code}" https://www.google.com | grep -q "200"; then
    echo "✓ OK"
else
    echo "✗ Failed"
fi

echo
echo "2. Docker Network"
echo "───────────────"

# Check Docker network exists
echo -n "• Docker network (mikrotik-vpn-net): "
if docker network ls | grep -q mikrotik-vpn-net; then
    echo "✓ Exists"
    
    # Get network details
    subnet=$(docker network inspect mikrotik-vpn-net --format='{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)
    echo "  Subnet: $subnet"
else
    echo "✗ Not found"
fi

echo
echo "3. Inter-container Connectivity"
echo "─────────────────────────────"

# Test connectivity between containers
if docker ps | grep -q mikrotik-app; then
    echo "Testing from app container:"
    
    # Test MongoDB
    echo -n "  • MongoDB (mongodb:27017): "
    if docker exec mikrotik-app nc -zv mongodb 27017 2>&1 | grep -q succeeded; then
        echo "✓ OK"
    else
        echo "✗ Failed"
    fi
    
    # Test Redis
    echo -n "  • Redis (redis:6379): "
    if docker exec mikrotik-app nc -zv redis 6379 2>&1 | grep -q succeeded; then
        echo "✓ OK"
    else
        echo "✗ Failed"
    fi
else
    echo "App container not running - skipping inter-container tests"
fi

echo
echo "4. Service Endpoints"
echo "─────────────────"

# Test each service endpoint
endpoints=(
    "http://localhost:9080/health|Web (HTTP)"
    "https://localhost:9443/health|Web (HTTPS)"
    "http://localhost:3000/health|App API"
    "http://localhost:9090/-/healthy|Prometheus"
    "http://localhost:3001/api/health|Grafana"
)

for endpoint_info in "${endpoints[@]}"; do
    url=$(echo $endpoint_info | cut -d'|' -f1)
    name=$(echo $endpoint_info | cut -d'|' -f2)
    
    echo -n "• $name: "
    if curl -k -s -o /dev/null -w "%{http_code}" "$url" | grep -q "200\|301\|302"; then
        echo "✓ OK"
    else
        echo "✗ Failed"
    fi
done

echo
echo "5. Port Binding Test"
echo "─────────────────"

# Check if ports are properly bound
port_services=(
    "9080:nginx"
    "9443:nginx"
    "3000:app"
    "27017:mongodb"
    "6379:redis"
    "1194:openvpn"
    "9090:prometheus"
    "3001:grafana"
)

for port_info in "${port_services[@]}"; do
    port=$(echo $port_info | cut -d: -f1)
    service=$(echo $port_info | cut -d: -f2)
    
    echo -n "• Port $port ($service): "
    if netstat -tln 2>/dev/null | grep -q ":$port " || ss -tln 2>/dev/null | grep -q ":$port "; then
        echo "✓ Listening"
    else
        echo "✗ Not listening"
    fi
done

echo
echo "═══════════════════════════════════════════════════════════════"
echo "Network Test Summary"
echo "═══════════════════════════════════════════════════════════════"

# Provide recommendations based on results
if ping -c 1 8.8.8.8 &>/dev/null && docker network ls | grep -q mikrotik-vpn-net; then
    echo "✓ Network configuration appears healthy"
else
    echo "⚠ Network issues detected"
    echo
    echo "Recommendations:"
    if ! ping -c 1 8.8.8.8 &>/dev/null; then
        echo "• Check your internet connection"
        echo "• Verify firewall settings"
    fi
    if ! docker network ls | grep -q mikrotik-vpn-net; then
        echo "• Run: docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16"
    fi
fi
EOF

    chmod +x "$SCRIPT_DIR"/*.sh
}

check "Secure file permissions" "[[ $(stat -c %a /opt/mikrotik-vpn/configs/setup.env) == 600 ]]"

echo
echo "Database Connectivity"
echo "═══════════════════"

check "MongoDB authentication" "docker exec mikrotik-mongodb mongosh --eval 'db.adminCommand(\"ping\")' -u admin -p '$MONGO_ROOT_PASSWORD' --authenticationDatabase admin --quiet"
check "Redis authentication" "docker exec mikrotik-redis redis-cli --pass '$REDIS_PASSWORD' ping | grep -q PONG"
check "Application health check" "curl -s http://localhost:3000/health | grep -q OK"

echo
echo "═══════════════════════════════════════════════════════════════"
echo "Pre-Deployment Check Summary"
echo "═══════════════════════════════════════════════════════════════"
echo "Checks passed: $CHECKS_PASSED"
echo "Checks failed: $CHECKS_FAILED"
echo

if [[ $CHECKS_FAILED -eq 0 ]]; then
    echo -e "${GREEN}✓ All checks passed! System is ready for deployment.${NC}"
else
    echo -e "${RED}✗ Some checks failed. Please fix the issues before deployment.${NC}"
    echo
    echo "Recommendations:"
    echo "• Run 'diagnose.sh' for detailed diagnostics"
    echo "• Check logs with 'docker compose logs'"
    echo "• Run 'fix-common-issues.sh' to attempt automatic fixes"
fi
EOF

    # Production deployment script
    cat << 'EOF' > "$SCRIPT_DIR/deploy-production.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                Production Deployment Script                   ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

echo "This script will prepare the system for production deployment."
echo

# Run pre-deployment check first
echo "Running pre-deployment checks..."
$SCRIPT_DIR/pre-deployment-check.sh

echo
read -p "Continue with production deployment? (yes/no): " confirm

if [[ $confirm != "yes" ]]; then
    echo "Deployment cancelled."
    exit 0
fi

echo
echo "1. Security Hardening"
echo "═══════════════════"

# Change default passwords if still using them
echo -n "• Checking for default passwords... "
if grep -q "SecurePassword123" /opt/mikrotik-vpn/configs/setup.env 2>/dev/null; then
    echo "Found!"
    echo "  Generating new secure passwords..."
    
    # Generate new passwords
    NEW_MONGO_ROOT=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    NEW_MONGO_APP=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    NEW_REDIS=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    NEW_GRAFANA=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    
    # Update passwords
    $SCRIPT_DIR/reset-password.sh <<< "1" <<< "y" >/dev/null 2>&1
    $SCRIPT_DIR/reset-password.sh <<< "2" <<< "y" >/dev/null 2>&1
    $SCRIPT_DIR/reset-password.sh <<< "3" >/dev/null 2>&1
    
    echo "  ✓ Passwords updated"
else
    echo "OK"
fi

# Disable unnecessary ports
echo -n "• Securing management interfaces... "
cd /opt/mikrotik-vpn

# Update docker-compose to bind management tools to localhost only
sed -i 's/- "8081:8081"/- "127.0.0.1:8081:8081"/' docker-compose.yml
sed -i 's/- "8082:8081"/- "127.0.0.1:8082:8081"/' docker-compose.yml
sed -i 's/- "9090:9090"/- "127.0.0.1:9090:9090"/' docker-compose.yml
sed -i 's/- "3001:3000"/- "127.0.0.1:3001:3000"/' docker-compose.yml

echo "OK"

echo
echo "2. Performance Optimization"
echo "════════════════════════"

# MongoDB optimization
echo -n "• Optimizing MongoDB... "
docker exec mikrotik-mongodb mongosh \
    -u admin -p "$MONGO_ROOT_PASSWORD" \
    --authenticationDatabase admin \
    --eval "
    db.adminCommand({ setParameter: 1, internalQueryExecMaxBlockingSortBytes: 268435456 });
    db.adminCommand({ setParameter: 1, failIndexKeyTooLong: false });
    " >/dev/null 2>&1
echo "OK"

# Redis optimization
echo -n "• Optimizing Redis... "
docker exec mikrotik-redis redis-cli --pass "$REDIS_PASSWORD" CONFIG SET save "900 1 300 10" >/dev/null
docker exec mikrotik-redis redis-cli --pass "$REDIS_PASSWORD" CONFIG SET maxmemory-policy allkeys-lru >/dev/null
echo "OK"

# Nginx optimization
echo -n "• Optimizing Nginx... "
cat << 'NGINX' > /opt/mikrotik-vpn/nginx/conf.d/optimization.conf
# Cache configuration
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=app_cache:10m max_size=1g inactive=60m use_temp_path=off;

# Connection optimization
upstream app_backend_optimized {
    least_conn;
    server app:3000 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
NGINX
echo "OK"

echo
echo "3. Monitoring Setup"
echo "════════════════"

# Enable monitoring alerts
echo -n "• Configuring production alerts... "
cat << 'ALERTS' > /opt/mikrotik-vpn/monitoring/prometheus/rules/production.yml
groups:
  - name: production_alerts
    interval: 30s
    rules:
      - alert: ServiceDown
        expr: up == 0
        for: 2m
        labels:
          severity: critical
          environment: production
        annotations:
          summary: "Service {{ $labels.job }} is down"
          description: "{{ $labels.job }} on {{ $labels.instance }} has been down for more than 2 minutes."
      
      - alert: HighMemoryUsage
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 90
        for: 5m
        labels:
          severity: warning
          environment: production
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage is above 90% (current value: {{ $value }}%)"
      
      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100 < 10
        for: 5m
        labels:
          severity: critical
          environment: production
        annotations:
          summary: "Low disk space"
          description: "Disk space is below 10% (current value: {{ $value }}%)"
      
      - alert: MongoDBDown
        expr: mongodb_up == 0
        for: 1m
        labels:
          severity: critical
          environment: production
        annotations:
          summary: "MongoDB is down"
          description: "MongoDB has been down for more than 1 minute"
      
      - alert: HighVPNConnections
        expr: openvpn_server_connected_clients > 900
        for: 5m
        labels:
          severity: warning
          environment: production
        annotations:
          summary: "High number of VPN connections"
          description: "VPN connections approaching limit (current: {{ $value }})"
ALERTS
echo "OK"

echo
echo "4. Backup Configuration"
echo "═══════════════════"

# Setup automated backups
echo -n "• Configuring automated backups... "
cat << 'BACKUP' > /etc/cron.d/mikrotik-vpn-backup
# MikroTik VPN System Automated Backups
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Daily backup at 2:00 AM
0 2 * * * root /opt/mikrotik-vpn/scripts/backup-system.sh >> /var/log/mikrotik-vpn/backup.log 2>&1

# Weekly MongoDB optimization at 3:00 AM on Sundays
0 3 * * 0 root /opt/mikrotik-vpn/scripts/maintain-database.sh <<< "3" >> /var/log/mikrotik-vpn/maintenance.log 2>&1

# Monthly old data cleanup at 4:00 AM on the 1st
0 4 1 * * root /opt/mikrotik-vpn/scripts/maintain-database.sh <<< "2" <<< "90" >> /var/log/mikrotik-vpn/maintenance.log 2>&1
BACKUP
echo "OK"

echo
echo "5. SSL Certificate"
echo "════════════════"

# Check SSL certificate
if openssl x509 -checkend 86400 -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem 2>/dev/null; then
    issuer=$(openssl x509 -issuer -noout -in /opt/mikrotik-vpn/nginx/ssl/fullchain.pem | grep -oP 'CN=\K[^,/]*')
    if [[ "$issuer" == *"MikroTik VPN"* ]]; then
        echo "⚠ Warning: Using self-signed certificate"
        echo "  For production, install a proper SSL certificate:"
        echo "  Run: update-ssl.sh"
    else
        echo "✓ Valid SSL certificate installed"
    fi
else
    echo "✗ SSL certificate expired or invalid!"
fi

echo
echo "6. Final Steps"
echo "════════════"

# Restart all services with new configuration
echo -n "• Restarting services with production configuration... "
docker compose down
docker compose up -d
sleep 10
echo "OK"

# Create production info file
cat << INFO > /opt/mikrotik-vpn/PRODUCTION_DEPLOYMENT.txt
MikroTik VPN System - Production Deployment
===========================================
Deployment Date: $(date)
Domain: $DOMAIN_NAME
Version: 5.0

Production URLs:
- Main Application: https://$DOMAIN_NAME:9443
- VPN Server: $DOMAIN_NAME:1194/udp

Management Access (localhost only):
- MongoDB Express: http://localhost:8081
- Redis Commander: http://localhost:8082
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3001

Security Notes:
- All passwords have been changed from defaults
- Management interfaces bound to localhost only
- Monitoring alerts configured
- Automated backups enabled

Maintenance:
- Daily backups at 2:00 AM
- Weekly database optimization on Sundays
- Monthly old data cleanup on the 1st

For remote management access, use SSH tunnel:
ssh -L 8081:localhost:8081 -L 8082:localhost:8082 -L 9090:localhost:9090 -L 3001:localhost:3001 user@$DOMAIN_NAME
INFO

echo
echo "═══════════════════════════════════════════════════════════════"
echo "Production Deployment Complete!"
echo "═══════════════════════════════════════════════════════════════"
echo
echo "✓ Security hardening applied"
echo "✓ Performance optimizations configured"
echo "✓ Monitoring alerts enabled"
echo "✓ Automated backups scheduled"
echo
echo "Next steps:"
echo "1. Update DNS to point $DOMAIN_NAME to this server"
echo "2. Install proper SSL certificate (run: update-ssl.sh)"
echo "3. Configure email alerts (run: configure-alerts.sh)"
echo "4. Test VPN connectivity"
echo "5. Review /opt/mikrotik-vpn/PRODUCTION_DEPLOYMENT.txt"
echo
echo "To monitor system health: mikrotik-vpn health"
EOF

    # Migration script
    cat << 'EOF' > "$SCRIPT_DIR/migrate-data.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Data Migration Tool                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

echo "This tool helps migrate data from another MikroTik VPN instance."
echo

echo "1. Import from backup file"
echo "2. Import from remote server"
echo "3. Export current data"
echo "4. Exit"
echo

read -p "Select option (1-4): " choice

case $choice in
    1)
        echo
        echo "Import from Backup File"
        echo "═════════════════════"
        
        read -p "Enter backup file path: " backup_file
        
        if [[ ! -f "$backup_file" ]]; then
            echo "File not found: $backup_file"
            exit 1
        fi
        
        # Extract backup
        temp_dir="/tmp/mikrotik-vpn-import-$"
        mkdir -p "$temp_dir"
        
        echo "Extracting backup..."
        tar -xzf "$backup_file" -C "$temp_dir"
        
        # Find MongoDB backup
        mongo_backup=$(find "$temp_dir" -name "mongodb-backup.gz" -o -name "backup.gz" | head -1)
        
        if [[ -z "$mongo_backup" ]]; then
            echo "No MongoDB backup found in archive!"
            rm -rf "$temp_dir"
            exit 1
        fi
        
        echo "Found MongoDB backup: $mongo_backup"
        
        read -p "This will overwrite current data. Continue? (yes/no): " confirm
        
        if [[ $confirm != "yes" ]]; then
            echo "Import cancelled."
            rm -rf "$temp_dir"
            exit 0
        fi
        
        # Import MongoDB data
        echo "Importing MongoDB data..."
        docker cp "$mongo_backup" mikrotik-mongodb:/tmp/import.gz
        docker exec mikrotik-mongodb mongorestore \
            --uri="mongodb://admin:$MONGO_ROOT_PASSWORD@localhost:27017/admin" \
            --archive="/tmp/import.gz" \
            --gzip \
            --drop
        
        # Import Redis data if exists
        redis_backup=$(find "$temp_dir" -name "redis-dump.rdb" | head -1)
        if [[ -n "$redis_backup" ]]; then
            echo "Importing Redis data..."
            docker compose stop redis
            docker cp "$redis_backup" mikrotik-redis:/data/dump.rdb
            docker compose start redis
        fi
        
        # Clean up
        rm -rf "$temp_dir"
        docker exec mikrotik-mongodb rm /tmp/import.gz
        
        echo "Import completed successfully!"
        ;;
        
    2)
        echo
        echo "Import from Remote Server"
        echo "═══════════════════════"
        
        read -p "Remote server address: " remote_server
        read -p "Remote SSH user: " remote_user
        read -p "Remote SSH port (default 22): " remote_port
        remote_port=${remote_port:-22}
        
        echo
        echo "Testing connection..."
        if ! ssh -p $remote_port $remote_user@$remote_server "echo 'Connection successful'" 2>/dev/null; then
            echo "Failed to connect to remote server!"
            exit 1
        fi
        
        echo "Creating remote backup..."
        ssh -p $remote_port $remote_user@$remote_server \
            "cd /opt/mikrotik-vpn && sudo ./scripts/backup-system.sh" || exit 1
        
        # Get latest backup filename
        remote_backup=$(ssh -p $remote_port $remote_user@$remote_server \
            "ls -t /opt/mikrotik-vpn/backups/*.tar.gz | head -1")
        
        if [[ -z "$remote_backup" ]]; then
            echo "No backup found on remote server!"
            exit 1
        fi
        
        echo "Downloading backup..."
        local_backup="/tmp/remote-backup-$(date +%Y%m%d_%H%M%S).tar.gz"
        scp -P $remote_port $remote_user@$remote_server:"$remote_backup" "$local_backup"
        
        # Import the backup
        $0 <<< "1" <<< "$local_backup" <<< "yes"
        
        # Clean up
        rm -f "$local_backup"
        ;;
        
    3)
        echo
        echo "Export Current Data"
        echo "═════════════════"
        
        export_dir="/tmp/mikrotik-vpn-export-$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$export_dir"
        
        echo "Exporting data..."
        
        # Run backup
        $SCRIPT_DIR/backup-system.sh
        
        # Get latest backup
        latest_backup=$(ls -t /opt/mikrotik-vpn/backups/*.tar.gz | head -1)
        
        if [[ -z "$latest_backup" ]]; then
            echo "Backup failed!"
            exit 1
        fi
        
        cp "$latest_backup" "$export_dir/"
        
        # Export additional configs
        cp -r /opt/mikrotik-vpn/configs "$export_dir/" 2>/dev/null
        cp -r /opt/mikrotik-vpn/clients "$export_dir/" 2>/dev/null
        
        # Create info file
        cat << EXPORTINFO > "$export_dir/export-info.txt"
MikroTik VPN Data Export
========================
Export Date: $(date)
Source Domain: $DOMAIN_NAME
Version: 5.0

Contents:
- Full system backup
- Configuration files
- VPN client configs

To import on another system:
1. Copy this directory to the target server
2. Run: migrate-data.sh
3. Select "Import from backup file"
4. Point to the .tar.gz file in this directory
EXPORTINFO

        # Create archive
        cd /tmp
        tar -czf "mikrotik-vpn-export-$(date +%Y%m%d_%H%M%S).tar.gz" "$(basename $export_dir)"
        
        echo
        echo "Export completed!"
        echo "File: /tmp/mikrotik-vpn-export-$(date +%Y%m%d_%H%M%S).tar.gz"
        ;;
        
    4)
        exit 0
        ;;
        
    *)
        echo "Invalid option"
        ;;
esac
EOF

    chmod +x "$SCRIPT_DIR"/*.sh
}

# Create integration scripts
create_integration_scripts() {
    # API integration helper
    cat << 'EOF' > "$SCRIPT_DIR/api-integration.sh"
#!/bin/bash
source /opt/mikrotik-vpn/configs/setup.env

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    API Integration Helper                     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo

API_BASE="http://localhost:3000/api"

show_menu() {
    echo "1. Test API connectivity"
    echo "2. Generate API documentation"
    echo "3. Create API test client"
    echo "4. Monitor API usage"
    echo "5. API performance test"
    echo "6. Exit"
    echo
}

test_api_connectivity() {
    echo "Testing API Endpoints"
    echo "═══════════════════"
    
    # Health check
    echo -n "• Health check: "
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/health)
    if [[ $response == "200" ]]; then
        echo "✓ OK"
    else
        echo "✗ Failed (HTTP $response)"
    fi
    
    # API info
    echo -n "• API info: "
    response=$(curl -s http://localhost:3000/api)
    if echo "$response" | grep -q "MikroTik VPN API"; then
        echo "✓ OK"
        echo "  Version: $(echo "$response" | jq -r .version)"
        echo "  Status: $(echo "$response" | jq -r .status)"
    else
        echo "✗ Failed"
    fi
    
    # Metrics endpoint
    echo -n "• Metrics endpoint: "
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/metrics)
    if [[ $response == "200" ]]; then
        echo "✓ OK"
    else
        echo "✗ Failed (HTTP $response)"
    fi
}

generate_api_docs() {
    echo "Generating API Documentation"
    echo "══════════════════════════"
    
    cat << 'APIDOC' > /opt/mikrotik-vpn/API_DOCUMENTATION.md
# MikroTik VPN Management API Documentation

## Base URL
```
http://localhost:3000/api
```

## Authentication
All API requests require an API key in the Authorization header:
```
Authorization: Bearer YOUR_API_KEY
```

## Endpoints

### Health Check
```
GET /health
```
Returns system health status.

**Response:**
```json
{
  "status": "OK",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "services": {
    "mongodb": "connected",
    "redis": "connected"
  }
}
```

### API Info
```
GET /api
```
Returns API information.

**Response:**
```json
{
  "message": "MikroTik VPN API",
  "version": "1.0.0",
  "status": "operational"
}
```

### Metrics
```
GET /metrics
```
Returns Prometheus-formatted metrics.

### Device Management

#### List Devices
```
GET /api/devices
```

#### Get Device
```
GET /api/devices/:id
```

#### Create Device
```
POST /api/devices
Content-Type: application/json

{
  "serialNumber": "ABC123",
  "macAddress": "00:11:22:33:44:55",
  "model": "RB4011",
  "siteName": "Main Office"
}
```

#### Update Device
```
PUT /api/devices/:id
Content-Type: application/json

{
  "siteName": "Branch Office",
  "status": "active"
}
```

#### Delete Device
```
DELETE /api/devices/:id
```

### User Management

#### List Users
```
GET /api/users
```

#### Create User
```
POST /api/users
Content-Type: application/json

{
  "username": "john.doe",
  "email": "john@example.com",
  "role": "admin"
}
```

### Voucher Management

#### Generate Vouchers
```
POST /api/vouchers/generate
Content-Type: application/json

{
  "count": 10,
  "duration": "24h",
  "bandwidth": "10M"
}
```

#### Validate Voucher
```
POST /api/vouchers/validate
Content-Type: application/json

{
  "code": "ABCD-EFGH-IJKL"
}
```

### Session Management

#### Active Sessions
```
GET /api/sessions/active
```

#### Session History
```
GET /api/sessions/history?userId=USER_ID&days=7
```

## Error Responses

All errors follow this format:
```json
{
  "error": true,
  "message": "Error description",
  "code": "ERROR_CODE"
}
```

Common HTTP status codes:
- 200: Success
- 400: Bad Request
- 401: Unauthorized
- 404: Not Found
- 500: Internal Server Error

## Rate Limiting

API requests are rate limited to:
- 100 requests per minute per IP
- 1000 requests per hour per API key

## Webhooks

Configure webhooks for real-time notifications:

```
POST /api/webhooks
Content-Type: application/json

{
  "url": "https://your-server.com/webhook",
  "events": ["device.connected", "device.disconnected", "user.created"]
}
```

## Examples

### cURL Example
```bash
# Get all devices
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:3000/api/devices

# Create a new device
curl -X POST \
     -H "Authorization: Bearer YOUR_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"serialNumber":"ABC123","macAddress":"00:11:22:33:44:55"}' \
     http://localhost:3000/api/devices
```

### Python Example
```python
import requests

api_key = "YOUR_API_KEY"
base_url = "http://localhost:3000/api"

headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

# Get devices
response = requests.get(f"{base_url}/devices", headers=headers)
devices = response.json()

# Create device
device_data = {
    "serialNumber": "ABC123",
    "macAddress": "00:11:22:33:44:55"
}
response = requests.post(f"{base_url}/devices", json=device_data, headers=headers)
```

### Node.js Example
```javascript
const axios = require('axios');

const apiKey = 'YOUR_API_KEY';
const baseURL = 'http://localhost:3000/api';

const api = axios.create({
  baseURL,
  headers: {
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json'
  }
});

// Get devices
api.get('/devices')
  .then(response => console.log(response.data))
  .catch(error => console.error(error));

// Create device
const deviceData = {
  serialNumber: 'ABC123',
  macAddress: '00:11:22:33:44:55'
};

api.post('/devices', deviceData)
  .then(response => console.log(response.data))
  .catch(error => console.error(error));
```
APIDOC

    echo "API documentation generated: /opt/mikrotik-vpn/API_DOCUMENTATION.md"
}

create_api_test_client() {
    echo "Creating API Test Client"
    echo "═════════════════════"
    
    cat << 'TESTCLIENT' > /opt/mikrotik-vpn/test-api-client.py
#!/usr/bin/env python3
"""
MikroTik VPN API Test Client
"""

import requests
import json
import time
from datetime import datetime

class MikroTikAPIClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    def test_endpoint(self, method, endpoint, data=None):
        """Test an API endpoint"""
        url = f"{self.base_url}{endpoint}"
        print(f"\n{method} {endpoint}")
        print("-" * 50)
        
        try:
            if method == "GET":
                response = requests.get(url, headers=self.headers)
            elif method == "POST":
                response = requests.post(url, json=data, headers=self.headers)
            elif method == "PUT":
                response = requests.put(url, json=data, headers=self.headers)
            elif method == "DELETE":
                response = requests.delete(url, headers=self.headers)
            
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text[:200]}...")
            
            return response
        except Exception as e:
            print(f"Error: {e}")
            return None
    
    def run_tests(self):
        """Run all API tests"""
        print("=" * 60)
        print("MikroTik VPN API Test Suite")
        print("=" * 60)
        
        # Test health endpoint
        self.test_endpoint("GET", "/health")
        
        # Test API info
        self.test_endpoint("GET", "/api")
        
        # Test metrics
        self.test_endpoint("GET", "/metrics")
        
        # Test devices endpoint (if implemented)
        self.test_endpoint("GET", "/api/devices")
        
        # Test creating a device
        device_data = {
            "serialNumber": f"TEST-{int(time.time())}",
            "macAddress": "00:11:22:33:44:55",
            "model": "RB4011",
            "siteName": "Test Site"
        }
        response = self.test_endpoint("POST", "/api/devices", device_data)
        
        if response and response.status_code == 200:
            device_id = response.json().get('id')
            if device_id:
                # Test getting specific device
                self.test_endpoint("GET", f"/api/devices/{device_id}")
                
                # Test updating device
                update_data = {"status": "active"}
                self.test_endpoint("PUT", f"/api/devices/{device_id}", update_data)
                
                # Test deleting device
                self.test_endpoint("DELETE", f"/api/devices/{device_id}")

if __name__ == "__main__":
    # Configuration
    BASE_URL = "http://localhost:3000"
    API_KEY = "YOUR_API_KEY"  # Replace with actual API key
    
    client = MikroTikAPIClient(BASE_URL, API_KEY)
    client.run_tests()
TESTCLIENT

    chmod +x /opt/mikrotik-vpn/test-api-client.py
    
    echo "Test client created: /opt/mikrotik-vpn/test-api-client.py"
    echo
    echo "To use:"
    echo "1. Update API_KEY in the script"
    echo "2. Run: python3 /opt/mikrotik-vpn/test-api-client.py"
}

monitor_api_usage() {
    echo "API Usage Monitor"
    echo "═══════════════"
    
    # Parse nginx access logs for API calls
    if [[ -f /opt/mikrotik-vpn/logs/nginx/access.log ]]; then
        echo "Recent API calls:"
        grep "/api" /opt/mikrotik-vpn/logs/nginx/access.log | tail -20 | \
            awk '{print $1 " " $4 " " $7 " " $9}' | \
            sed 's/\[//g'
        
        echo
        echo "API call statistics:"
        echo "──────────────────"
        
        total_calls=$(grep "/api" /opt/mikrotik-vpn/logs/nginx/access.log | wc -l)
        echo "Total API calls: $total_calls"
        
        echo
        echo "Top endpoints:"
        grep "/api" /opt/mikrotik-vpn/logs/nginx/access.log | \
            awk '{print $7}' | sort | uniq -c | sort -rn | head -10
        
        echo
        echo "Response codes:"
        grep "/api" /opt/mikrotik-vpn/logs/nginx/access.log | \
            awk '{print $9}' | sort | uniq -c | sort -rn
    else
        echo "No API logs found"
    fi
}

api_performance_test() {
    echo "API Performance Test"
    echo "═════════════════"
    
    read -p "Number of requests (default 100): " num_requests
    num_requests=${num_requests:-100}
    
    read -p "Concurrent connections (default 10): " concurrent
    concurrent=${concurrent:-10}
    
    echo
    echo "Testing with $num_requests requests, $concurrent concurrent..."
    
    # Use Apache Bench if available
    if command -v ab >/dev/null; then
        ab -n $num_requests -c $concurrent http://localhost:3000/health
    else
        # Simple bash performance test
        echo "Starting at: $(date)"
        start_time=$(date +%s)
        
        for ((i=1; i<=$num_requests; i++)); do
            curl -s -o /dev/null http://localhost:3000/health &
            
            # Limit concurrent connections
            if [[ $((i % concurrent)) -eq 0 ]]; then
                wait
            fi
        done
        
        wait
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        
        echo "Completed at: $(date)"
        echo "Duration: $duration seconds"
        echo "Requests per second: $(awk "BEGIN {print $num_requests/$duration}")"
    fi
}

# Main menu loop
while true; do
    echo
    show_menu
    read -p "Select option (1-6): " choice
    
    case $choice in
        1) test_api_connectivity ;;
        2) generate_api_docs ;;
        3) create_api_test_client ;;
        4) monitor_api_usage ;;
        5) api_performance_test ;;
        6) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
    
    echo
    read -p "Press Enter to continue..."
done
EOF

    chmod +x "$SCRIPT_DIR"/*.sh
}

# =============================================================================
# MAIN EXECUTION WITH ALL COMPONENTS
# =============================================================================

main() {
    # Initialize
    print_header
    check_root
    
    # Run installation phases
    phase0_system_detection
    phase1_configuration
    phase2_system_preparation
    phase3_docker_installation
    phase4_directory_structure
    phase5_nodejs_application
    phase6_configuration_files
    phase7_docker_compose
    phase8_management_scripts
    
    # Create all additional scripts
    create_utility_scripts_fixed
    create_mongodb_scripts
    create_monitoring_dashboards
    create_ssl_scripts
    create_troubleshooting_scripts
    create_management_utility_scripts
    create_deployment_scripts
    create_integration_scripts
    
    phase9_security_configuration
    phase10_final_setup
    
    # Success
    log "=================================================================="
    log "MikroTik VPN Management System installation completed successfully!"
    log "=================================================================="
    log ""
    log "To manage the system, run: mikrotik-vpn"
    log ""
    
    # Don't cleanup Docker on successful completion
    CLEANUP_DOCKER=false
    
    return 0
}

# Execute main function
main "$@"
exit $?d mongodb
        sleep 10
        
        # Test connection
        if docker exec mikrotik-mongodb mongosh --eval "db.adminCommand('ping')" -u admin -p "$MONGO_ROOT_PASSWORD" --authenticationDatabase admin --quiet &>/dev/null; then
            echo "✓ MongoDB authentication fixed"
        else
            echo "✗ MongoDB authentication still failing"
        fi
        ;;
        
    3)
        echo
        echo "Restarting all services..."
        cd /opt/mikrotik-vpn || exit 1
        
        # Ensure Docker is running
        if ! docker ps &>/dev/null; then
            $SCRIPT_DIR/start-docker.sh
        fi
        
        # Stop everything
        docker compose down
        
        # Clean up
        docker system prune -f
        
        # Recreate network
        docker network rm mikrotik-vpn-net 2>/dev/null || true
        docker network create mikrotik-vpn-net --driver bridge --subnet=172.20.0.0/16
        
        # Start services in order
        echo "Starting services..."
        docker compose up -d mongodb redis
        sleep 15
        docker compose up -d app
        sleep 10
        docker compose up -
