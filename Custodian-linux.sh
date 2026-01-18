#!/bin/bash
#===============================================================================
# Custodian-HT Linux Collection Script
#RootGuard
# Version: 1.0.0
#
# Description:
#   Comprehensive Linux forensic artifact collection for DFIR and threat hunting.
#   Collects system info, network data, processes, logs, persistence mechanisms,
#   and creates a compressed archive for analysis.
#
# Usage:
#   sudo bash Custodian-linux.sh [OPTIONS]
#
# Options:
#   -o, --output    Output directory (default: /tmp/custodian_collection)
#   -q, --quick     Quick collection (essential artifacts only)
#   -m, --memory    Include memory dump (requires AVML)
#   -h, --help      Show help message
#
#===============================================================================

set -e

# Configuration
VERSION="1.0.0"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
HOSTNAME=$(hostname)
OUTPUT_DIR="/tmp/custodian_collection_${HOSTNAME}_${TIMESTAMP}"
QUICK_MODE=false
MEMORY_DUMP=false
LOG_FILE=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

#===============================================================================
# Helper Functions
#===============================================================================

show_banner() {
    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════════════════════════════╗"
    echo "  ║           CUSTODIAN-HT LINUX COLLECTION v${VERSION}              ║"
    echo "  ║              RootGuard Cyber Defence                    ║"
    echo "  ╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${CYAN}[*]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" >> "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1" >> "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >> "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

show_help() {
    echo "Usage: sudo bash $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -o, --output DIR    Output directory (default: /tmp/custodian_collection)"
    echo "  -q, --quick         Quick collection (essential artifacts only)"
    echo "  -m, --memory        Include memory dump (requires AVML)"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo bash $0                    # Full collection"
    echo "  sudo bash $0 -q                 # Quick collection"
    echo "  sudo bash $0 -o /mnt/evidence   # Custom output path"
    echo "  sudo bash $0 -m                 # Include memory dump"
}

#===============================================================================
# Collection Functions
#===============================================================================

init_collection() {
    log_info "Initializing collection directory: $OUTPUT_DIR"
    
    mkdir -p "$OUTPUT_DIR"/{system,network,processes,logs,persistence,users,files,memory}
    
    LOG_FILE="$OUTPUT_DIR/collection.log"
    touch "$LOG_FILE"
    
    log_success "Collection directory created"
}

collect_system_info() {
    log_info "Collecting system information..."
    local dir="$OUTPUT_DIR/system"
    
    # Basic system info
    hostname > "$dir/hostname.txt" 2>/dev/null
    uname -a > "$dir/uname.txt" 2>/dev/null
    cat /etc/os-release > "$dir/os-release.txt" 2>/dev/null
    uptime > "$dir/uptime.txt" 2>/dev/null
    date > "$dir/date.txt" 2>/dev/null
    timedatectl > "$dir/timedatectl.txt" 2>/dev/null
    
    # Hardware info
    lscpu > "$dir/lscpu.txt" 2>/dev/null
    free -h > "$dir/memory.txt" 2>/dev/null
    df -h > "$dir/disk_usage.txt" 2>/dev/null
    lsblk > "$dir/block_devices.txt" 2>/dev/null
    fdisk -l > "$dir/fdisk.txt" 2>/dev/null
    mount > "$dir/mounts.txt" 2>/dev/null
    cat /proc/meminfo > "$dir/meminfo.txt" 2>/dev/null
    cat /proc/cpuinfo > "$dir/cpuinfo.txt" 2>/dev/null
    
    # Kernel info
    lsmod > "$dir/kernel_modules.txt" 2>/dev/null
    sysctl -a > "$dir/sysctl.txt" 2>/dev/null
    dmesg > "$dir/dmesg.txt" 2>/dev/null
    
    # Environment
    env > "$dir/environment.txt" 2>/dev/null
    printenv > "$dir/printenv.txt" 2>/dev/null
    
    log_success "System information collected"
}

collect_network_info() {
    log_info "Collecting network information..."
    local dir="$OUTPUT_DIR/network"
    
    # Network configuration
    ip addr > "$dir/ip_addr.txt" 2>/dev/null
    ip route > "$dir/ip_route.txt" 2>/dev/null
    ip neigh > "$dir/arp_cache.txt" 2>/dev/null
    ifconfig -a > "$dir/ifconfig.txt" 2>/dev/null
    
    # Active connections
    ss -tulpn > "$dir/ss_listening.txt" 2>/dev/null
    ss -anp > "$dir/ss_all.txt" 2>/dev/null
    netstat -tulpn > "$dir/netstat_listening.txt" 2>/dev/null
    netstat -anp > "$dir/netstat_all.txt" 2>/dev/null
    
    # DNS
    cat /etc/resolv.conf > "$dir/resolv.conf" 2>/dev/null
    cat /etc/hosts > "$dir/hosts.txt" 2>/dev/null
    
    # Firewall rules
    iptables -L -n -v > "$dir/iptables.txt" 2>/dev/null
    iptables-save > "$dir/iptables_save.txt" 2>/dev/null
    nft list ruleset > "$dir/nftables.txt" 2>/dev/null
    ufw status verbose > "$dir/ufw_status.txt" 2>/dev/null
    firewall-cmd --list-all > "$dir/firewalld.txt" 2>/dev/null
    
    # Network services
    cat /etc/ssh/sshd_config > "$dir/sshd_config.txt" 2>/dev/null
    
    log_success "Network information collected"
}

collect_processes() {
    log_info "Collecting process information..."
    local dir="$OUTPUT_DIR/processes"
    
    # Process listing
    ps auxwww > "$dir/ps_aux.txt" 2>/dev/null
    ps -ef > "$dir/ps_ef.txt" 2>/dev/null
    ps axjf > "$dir/ps_tree.txt" 2>/dev/null
    pstree -p > "$dir/pstree.txt" 2>/dev/null
    
    # Process details
    top -bn1 > "$dir/top.txt" 2>/dev/null
    
    # Open files
    lsof > "$dir/lsof_all.txt" 2>/dev/null
    lsof -i > "$dir/lsof_network.txt" 2>/dev/null
    
    # Proc filesystem
    ls -la /proc/*/exe 2>/dev/null | grep -v "Permission denied" > "$dir/proc_exe_links.txt"
    ls -la /proc/*/cwd 2>/dev/null | grep -v "Permission denied" > "$dir/proc_cwd_links.txt"
    
    # Process maps and file descriptors for suspicious processes
    for pid in $(ps -eo pid --no-headers); do
        if [[ -d "/proc/$pid" ]]; then
            cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
            if [[ -n "$cmdline" ]]; then
                echo "PID $pid: $cmdline" >> "$dir/proc_cmdlines.txt"
            fi
        fi
    done
    
    log_success "Process information collected"
}

collect_user_info() {
    log_info "Collecting user information..."
    local dir="$OUTPUT_DIR/users"
    
    # User accounts
    cat /etc/passwd > "$dir/passwd.txt" 2>/dev/null
    cat /etc/shadow > "$dir/shadow.txt" 2>/dev/null
    cat /etc/group > "$dir/group.txt" 2>/dev/null
    cat /etc/sudoers > "$dir/sudoers.txt" 2>/dev/null
    cat /etc/sudoers.d/* > "$dir/sudoers.d.txt" 2>/dev/null
    
    # Currently logged in users
    who > "$dir/who.txt" 2>/dev/null
    w > "$dir/w.txt" 2>/dev/null
    last -a > "$dir/last.txt" 2>/dev/null
    lastlog > "$dir/lastlog.txt" 2>/dev/null
    lastb > "$dir/lastb.txt" 2>/dev/null
    
    # SSH keys
    mkdir -p "$dir/ssh_keys"
    for user_home in /home/* /root; do
        if [[ -d "$user_home/.ssh" ]]; then
            user=$(basename "$user_home")
            cp -r "$user_home/.ssh" "$dir/ssh_keys/${user}_ssh" 2>/dev/null
        fi
    done
    
    # Bash history for all users
    mkdir -p "$dir/bash_history"
    for user_home in /home/* /root; do
        if [[ -f "$user_home/.bash_history" ]]; then
            user=$(basename "$user_home")
            cp "$user_home/.bash_history" "$dir/bash_history/${user}_bash_history.txt" 2>/dev/null
        fi
        if [[ -f "$user_home/.zsh_history" ]]; then
            user=$(basename "$user_home")
            cp "$user_home/.zsh_history" "$dir/bash_history/${user}_zsh_history.txt" 2>/dev/null
        fi
    done
    
    log_success "User information collected"
}

collect_persistence() {
    log_info "Collecting persistence mechanisms..."
    local dir="$OUTPUT_DIR/persistence"
    
    # Cron jobs
    mkdir -p "$dir/cron"
    crontab -l > "$dir/cron/root_crontab.txt" 2>/dev/null
    cp -r /etc/cron.* "$dir/cron/" 2>/dev/null
    cp /etc/crontab "$dir/cron/etc_crontab.txt" 2>/dev/null
    cat /var/spool/cron/crontabs/* > "$dir/cron/user_crontabs.txt" 2>/dev/null
    
    # Systemd services
    mkdir -p "$dir/systemd"
    systemctl list-units --type=service --all > "$dir/systemd/services.txt" 2>/dev/null
    systemctl list-unit-files > "$dir/systemd/unit_files.txt" 2>/dev/null
    systemctl list-timers --all > "$dir/systemd/timers.txt" 2>/dev/null
    cp -r /etc/systemd/system/*.service "$dir/systemd/" 2>/dev/null
    cp -r /lib/systemd/system/*.service "$dir/systemd/lib_services/" 2>/dev/null
    
    # Init scripts
    ls -la /etc/init.d/ > "$dir/init.d_listing.txt" 2>/dev/null
    ls -la /etc/rc*.d/ > "$dir/rc.d_listing.txt" 2>/dev/null
    
    # Profile scripts
    mkdir -p "$dir/profile"
    cp /etc/profile "$dir/profile/" 2>/dev/null
    cp /etc/profile.d/* "$dir/profile/" 2>/dev/null
    cp /etc/bash.bashrc "$dir/profile/" 2>/dev/null
    for user_home in /home/* /root; do
        user=$(basename "$user_home")
        cp "$user_home/.bashrc" "$dir/profile/${user}_bashrc.txt" 2>/dev/null
        cp "$user_home/.profile" "$dir/profile/${user}_profile.txt" 2>/dev/null
        cp "$user_home/.bash_profile" "$dir/profile/${user}_bash_profile.txt" 2>/dev/null
    done
    
    # At jobs
    atq > "$dir/at_queue.txt" 2>/dev/null
    ls -la /var/spool/at/ > "$dir/at_spool.txt" 2>/dev/null
    
    # LD_PRELOAD
    cat /etc/ld.so.preload > "$dir/ld_preload.txt" 2>/dev/null
    ldconfig -p > "$dir/ldconfig.txt" 2>/dev/null
    
    log_success "Persistence mechanisms collected"
}

collect_logs() {
    log_info "Collecting log files..."
    local dir="$OUTPUT_DIR/logs"
    
    # Auth logs
    cp /var/log/auth.log* "$dir/" 2>/dev/null
    cp /var/log/secure* "$dir/" 2>/dev/null
    
    # System logs
    cp /var/log/syslog* "$dir/" 2>/dev/null
    cp /var/log/messages* "$dir/" 2>/dev/null
    cp /var/log/kern.log* "$dir/" 2>/dev/null
    cp /var/log/dmesg* "$dir/" 2>/dev/null
    
    # Application logs
    cp /var/log/apache2/*.log "$dir/" 2>/dev/null
    cp /var/log/nginx/*.log "$dir/" 2>/dev/null
    cp /var/log/mysql/*.log "$dir/" 2>/dev/null
    
    # Audit logs
    cp /var/log/audit/*.log "$dir/" 2>/dev/null
    
    # Journal logs
    journalctl --no-pager > "$dir/journalctl_all.txt" 2>/dev/null
    journalctl -u ssh --no-pager > "$dir/journalctl_ssh.txt" 2>/dev/null
    journalctl -u sshd --no-pager > "$dir/journalctl_sshd.txt" 2>/dev/null
    
    # Login records
    utmpdump /var/log/wtmp > "$dir/wtmp_dump.txt" 2>/dev/null
    utmpdump /var/log/btmp > "$dir/btmp_dump.txt" 2>/dev/null
    
    log_success "Log files collected"
}

collect_files() {
    log_info "Collecting file system artifacts..."
    local dir="$OUTPUT_DIR/files"
    
    # Recently modified files (last 24 hours)
    find / -type f -mtime -1 2>/dev/null | head -1000 > "$dir/recently_modified_24h.txt"
    
    # Recently accessed files
    find / -type f -atime -1 2>/dev/null | head -1000 > "$dir/recently_accessed_24h.txt"
    
    # SUID/SGID files
    find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null > "$dir/suid_sgid_files.txt"
    
    # World-writable files
    find / -type f -perm -0002 2>/dev/null | head -500 > "$dir/world_writable_files.txt"
    
    # Hidden files in common directories
    find /tmp /var/tmp /dev/shm -type f -name ".*" 2>/dev/null > "$dir/hidden_files_tmp.txt"
    
    # Suspicious file locations
    ls -la /tmp/ > "$dir/tmp_listing.txt" 2>/dev/null
    ls -la /var/tmp/ > "$dir/var_tmp_listing.txt" 2>/dev/null
    ls -la /dev/shm/ > "$dir/dev_shm_listing.txt" 2>/dev/null
    
    # Web directories
    ls -laR /var/www/ > "$dir/www_listing.txt" 2>/dev/null
    
    # Package information
    dpkg -l > "$dir/dpkg_packages.txt" 2>/dev/null
    rpm -qa > "$dir/rpm_packages.txt" 2>/dev/null
    pip list > "$dir/pip_packages.txt" 2>/dev/null
    pip3 list > "$dir/pip3_packages.txt" 2>/dev/null
    
    log_success "File system artifacts collected"
}

collect_memory() {
    if [[ "$MEMORY_DUMP" != true ]]; then
        log_info "Skipping memory dump (use -m to enable)"
        return
    fi
    
    log_info "Collecting memory dump..."
    local dir="$OUTPUT_DIR/memory"
    
    # Check for AVML
    if command -v avml &> /dev/null; then
        avml "$dir/memory_${HOSTNAME}_${TIMESTAMP}.lime"
        log_success "Memory dump collected with AVML"
    elif [[ -f "./avml" ]]; then
        ./avml "$dir/memory_${HOSTNAME}_${TIMESTAMP}.lime"
        log_success "Memory dump collected with AVML"
    else
        log_warn "AVML not found. Download from: https://github.com/microsoft/avml"
        
        # Fallback: collect /proc/kcore if available
        if [[ -r /proc/kcore ]]; then
            log_info "Attempting /proc/kcore collection..."
            dd if=/proc/kcore of="$dir/kcore_dump.raw" bs=1M count=1024 2>/dev/null
        fi
    fi
}

create_archive() {
    log_info "Creating compressed archive..."
    
    local archive_name="custodian_${HOSTNAME}_${TIMESTAMP}.tar.gz"
    local archive_path="/tmp/$archive_name"
    
    cd /tmp
    tar -czf "$archive_name" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")"
    
    # Calculate hash
    sha256sum "$archive_path" > "${archive_path}.sha256"
    
    log_success "Archive created: $archive_path"
    log_success "SHA256: $(cat ${archive_path}.sha256)"
    
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Collection Complete!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Output directory: $OUTPUT_DIR"
    echo "Archive file: $archive_path"
    echo "Archive hash: ${archive_path}.sha256"
    echo ""
    echo "Transfer command:"
    echo "  scp $archive_path user@analyst-workstation:/path/to/evidence/"
    echo ""
}

#===============================================================================
# Main Execution
#===============================================================================

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -q|--quick)
            QUICK_MODE=true
            shift
            ;;
        -m|--memory)
            MEMORY_DUMP=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main execution
show_banner
check_root
init_collection

echo ""
log_info "Starting collection on $HOSTNAME"
log_info "Output directory: $OUTPUT_DIR"
log_info "Quick mode: $QUICK_MODE"
log_info "Memory dump: $MEMORY_DUMP"
echo ""

# Run collections
collect_system_info
collect_network_info
collect_processes
collect_user_info
collect_persistence

if [[ "$QUICK_MODE" != true ]]; then
    collect_logs
    collect_files
fi

collect_memory
create_archive

exit 0