#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Logging functions
print_section_header() {
    echo -e "\n${BLUE}${BOLD}=== $1 ===${NC}\n"
}

print_subsection() {
    echo -e "\n${BOLD}$1${NC}"
}

log_status() {
    status=$1
    message=$2
    details=$3

    case $status in
        "PASS")
            echo -e "[${GREEN}PASS${NC}] $message"
            ;;
        "FAIL")
            echo -e "[${RED}FAIL${NC}] $message"
            ;;
        "WARN")
            echo -e "[${YELLOW}WARN${NC}] $message"
            ;;
        "INFO")
            echo -e "[${BLUE}INFO${NC}] $message"
            ;;
    esac

    if [ ! -z "$details" ]; then
        echo -e "       ${details}" | sed 's/^/       /'
    fi
}

# System security checks
check_system() {
    print_section_header "System Security Audit"

    print_subsection "Password Policies"
    # Check password expiration
    pass_max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
    pass_min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
    pass_warn_age=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')
    
    log_status "INFO" "Password expiration settings" \
               "Maximum days: $pass_max_days\nMinimum days: $pass_min_days\nWarning days: $pass_warn_age"

    print_subsection "User Accounts"
    # Check for users with empty passwords
    empty_pass=$(grep "^[^:]*::" /etc/shadow 2>/dev/null)
    if [ ! -z "$empty_pass" ]; then
        log_status "FAIL" "Users with empty passwords found" "\n$empty_pass"
    else
        log_status "PASS" "No users with empty passwords"
    fi

    # Check for users with UID 0
    root_users=$(awk -F: '($3 == 0) {print}' /etc/passwd)
    if [ "$(echo "$root_users" | wc -l)" -gt 1 ]; then
        log_status "FAIL" "Multiple users with UID 0 found" "\n$root_users"
    else
        log_status "PASS" "Only root has UID 0"
    fi

    print_subsection "System Updates"
    # Check if system is up to date (works for both apt and yum)
    if command -v apt &> /dev/null; then
        updates=$(apt list --upgradable 2>/dev/null | grep -v "Listing...")
        if [ ! -z "$updates" ]; then
            log_status "WARN" "System updates available" "\n$updates"
        else
            log_status "PASS" "System is up to date"
        fi
    elif command -v yum &> /dev/null; then
        updates=$(yum check-update --quiet | grep -v "^$")
        if [ ! -z "$updates" ]; then
            log_status "WARN" "System updates available" "\n$updates"
        else
            log_status "PASS" "System is up to date"
        fi
    fi
}

# Network security checks
check_network() {
    print_section_header "Network Security Audit"

    print_subsection "Open Ports"
    if command -v netstat &> /dev/null; then
        open_ports=$(netstat -tuln | grep "LISTEN")
    elif command -v ss &> /dev/null; then
        open_ports=$(ss -tuln | grep "LISTEN")
    fi
    log_status "INFO" "Open ports and services" "\n$open_ports"

    print_subsection "Firewall Status"
    # Check UFW status
    if command -v ufw &> /dev/null; then
        ufw_status=$(ufw status verbose)
        log_status "INFO" "UFW Firewall status" "\n$ufw_status"
    # Check firewalld status
    elif command -v firewall-cmd &> /dev/null; then
        firewalld_status=$(firewall-cmd --list-all)
        log_status "INFO" "FirewallD status" "\n$firewalld_status"
    else
        log_status "WARN" "No supported firewall found"
    fi

    print_subsection "Network Interfaces"
    interfaces=$(ip a)
    log_status "INFO" "Network interfaces" "\n$interfaces"
}

# Filesystem security checks
check_filesystem() {
    print_section_header "Filesystem Security Audit"

    print_subsection "World-Writable Files"
    world_writable=$(find / -type f -perm -002 -exec ls -l {} \; 2>/dev/null | head -n 20)
    if [ ! -z "$world_writable" ]; then
        log_status "WARN" "World-writable files found (showing first 20)" "\n$world_writable"
    else
        log_status "PASS" "No world-writable files found"
    fi

    print_subsection "SUID/SGID Files"
    suid_sgid=$(find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null)
    log_status "INFO" "SUID/SGID files" "\n$suid_sgid"

    print_subsection "Critical File Permissions"
    critical_files=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow" "/etc/ssh/sshd_config")
    for file in "${critical_files[@]}"; do
        if [ -f "$file" ]; then
            perms=$(stat -c "%a %U:%G" "$file")
            log_status "INFO" "Permissions for $file" "$perms"
        fi
    done
}

# SSH security checks
check_ssh() {
    print_section_header "SSH Security Audit"

    print_subsection "SSH Daemon Configuration"
    
    if [ ! -f "/etc/ssh/sshd_config" ]; then
        log_status "WARN" "SSH daemon configuration file not found"
        return
    fi

    declare -A ssh_checks=(
        ["PermitRootLogin"]="no"
        ["PasswordAuthentication"]="no"
        ["X11Forwarding"]="no"
        ["MaxAuthTries"]="4"
        ["Protocol"]="2"
        ["PermitEmptyPasswords"]="no"
        ["UsePrivilegeSeparation"]="yes"
    )

    for param in "${!ssh_checks[@]}"; do
        expected="${ssh_checks[$param]}"
        actual=$(grep "^${param}" /etc/ssh/sshd_config | awk '{print $2}')
        
        if [ -z "$actual" ]; then
            log_status "WARN" "SSH $param" "Parameter not set (recommended: $expected)"
        elif [ "$actual" == "$expected" ]; then
            log_status "PASS" "SSH $param" "Set to recommended value: $actual"
        else
            log_status "FAIL" "SSH $param" "Current: $actual (recommended: $expected)"
        fi
    done

    print_subsection "Authorized Keys Check"
    for user_home in /home/*; do
        user=$(basename "$user_home")
        auth_keys_file="$user_home/.ssh/authorized_keys"
        
        if [ -f "$auth_keys_file" ]; then
            key_count=$(wc -l < "$auth_keys_file")
            file_perms=$(stat -c "%a" "$auth_keys_file")
            
            if [ "$file_perms" == "600" ]; then
                log_status "PASS" "Authorized keys file permissions for $user" \
                          "File: $auth_keys_file\nPermissions: $file_perms\nKeys: $key_count"
            else
                log_status "FAIL" "Authorized keys file permissions for $user" \
                          "File: $auth_keys_file\nPermissions: $file_perms (should be 600)\nKeys: $key_count"
            fi
        fi
    done
}

# Docker security checks
check_docker() {
    print_section_header "Docker Security Audit"

    if ! command -v docker &> /dev/null; then
        log_status "WARN" "Docker is not installed"
        return
    fi

    print_subsection "Docker Socket Security"
    socket_perms=$(stat -c "%a %u %g" /var/run/docker.sock)
    log_status "INFO" "Docker socket permissions" "Permissions: $socket_perms"

    print_subsection "Docker Containers"
    docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}"

    print_subsection "Privileged Containers"
    privileged_containers=$(docker ps -q | xargs -I {} docker inspect {} --format '{{.Name}}:{{.HostConfig.Privileged}}' | grep true)
    if [ ! -z "$privileged_containers" ]; then
        log_status "WARN" "Privileged containers found" "\n$privileged_containers"
    else
        log_status "PASS" "No privileged containers running"
    fi

    print_subsection "Docker Volume Mounts"
    volume_mounts=$(docker ps -q | xargs -I {} docker inspect {} --format '{{.Name}}:{{range .Mounts}}{{.Type}}:{{.Source}}->{{.Destination}} {{end}}')
    log_status "INFO" "Container volume mounts" "\n$volume_mounts"

    print_subsection "Docker Networks"
    networks=$(docker network ls --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}")
    log_status "INFO" "Docker networks" "\n$networks"
}

# Main execution
main() {
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}Please run as root${NC}"
        exit 1
    }

    echo -e "${BLUE}${BOLD}Starting Security Audit...${NC}"
    echo -e "${YELLOW}Generated on: $(date)${NC}"
    echo -e "${YELLOW}Hostname: $(hostname)${NC}"
    echo -e "${YELLOW}OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)${NC}\n"

    check_system
    check_network
    check_filesystem
    check_ssh
    check_docker

    echo -e "\n${BLUE}${BOLD}Security Audit Completed${NC}"
}

main "$@"
