cat << 'EOF' > check_dns.sh
#!/bin/bash

# Format: "Device_Name:IP:GNS3_Console_Port"
devices=(
  "API:10.10.10.200:5008"
  "DB:10.10.10.210:5011"
  "DNS1:10.10.10.10:5013"
  "DNS2:10.10.10.20:5017"
  "PC1:192.168.10.101:5032"
  "PC2:192.168.20.100:5029"
  "PC3:192.168.30.101:5031"
  "PC4:192.168.10.102:5012"
  "SMTP:10.10.10.100:5019"
  "SVR1:192.168.20.210:5022"
  "SVR2:192.168.30.210:5014"
)

for entry in "${devices[@]}"; do
  IFS=":" read -r name ip port <<< "$entry"
  echo "=========================================="
  echo ">>> Checking $name ($ip) [Console Port: $port]"
  echo "=========================================="

  # 1. Try standard SSH first (ignoring systemd comments to show real nameservers)
  ssh_out=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -p 22 ubuntu@$ip \
    "echo 'HOSTNAME:' \$(hostname); \
     echo '--- resolvectl ---'; resolvectl dns 2>/dev/null; \
     echo '--- resolv.conf ---'; grep -E '^nameserver' /etc/resolv.conf; \
     echo '--- netplan ---'; cat /etc/netplan/*.yaml 2>/dev/null" 2>&1)

  if [ $? -eq 0 ]; then
    echo "$ssh_out"
  else
    echo "[!] SSH Failed: $ssh_out"
    echo "[*] Falling back to GNS3 Console Port ($port) on 127.0.0.1..."
    
    # 2. Console fallback: sends commands directly to GNS3 telnet console
    (
      sleep 1; echo ""; 
      sleep 1; echo "ubuntu"; 
      sleep 1; echo "ubuntu"; 
      sleep 1; echo "echo 'HOSTNAME:' \$(hostname); echo '--- IP Config ---'; ip -br a; echo '--- Netplan Config ---'; cat /etc/netplan/*.yaml 2>/dev/null; exit";
      sleep 2
    ) | telnet 127.0.0.1 $port 2>/dev/null | grep -E "(HOSTNAME:|--- IP Config ---|--- Netplan Config ---|ens|eth|addresses:|gateway|nameservers)" -A 2
  fi
  echo
done
EOF
chmod +x check_dns.sh
./check_dns.sh


for ip in 10.10.10.1 10.10.10.100; do
    echo "========== $ip =========="

    if [ "$ip" = "10.10.10.1" ]; then
        echo "ROUTER1 - VyOS"
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 vyos@$ip \
            "hostname; show configuration commands | grep name-server; cat /etc/resolv.conf"
    else
        echo "SMTP - Ubuntu"
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ubuntu@$ip \
            "hostname; resolvectl dns 2>/dev/null; cat /etc/resolv.conf"
    fi

    echo
done