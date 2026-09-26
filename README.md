curl \
  -H "Authorization: Bearer vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE" \
  http://api.d522.wgu.internal:5000/api/tickets

  # Create a test ticket
curl -X POST "http://api.d522.wgu.internal:5000/api/tickets" -H "Authorization: Bearer  vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE" -H "Content-Type: application/json" -d '{"title":"DNS Configuration Altered - TEST","description":"Test DNS ticket","status":"open","priority":"medium"}'

# Resolve it (replace ID)
curl -X PATCH "http://api.d522.wgu.internal:5000/api/tickets/7" -H "Authorization: Bearer vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE" -H "Content-Type: application/json" -d '{"status":"resolved"}'

ssh -o StrictHostKeyChecking=no -p 22 ubuntu@10.10.10.10
# password from CSV: ubuntu

ssh -o StrictHostKeyChecking=no -p 22 ubuntu@192.168.10.102
cat /etc/resolv.conf


ssh -o StrictHostKeyChecking=no -p 22 ubuntu@10.10.10.200 "resolvectl dns; echo '---'; cat /etc/resolv.conf"

for ip in 10.10.10.200 10.10.10.210 10.10.10.10 10.10.10.20 \
          192.168.10.101 192.168.20.100 192.168.30.101 192.168.10.102 \
          10.10.10.100 192.168.20.210 192.168.30.210
do
  echo "========== $ip =========="
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p 22 ubuntu@$ip \
    "hostname; resolvectl dns 2>/dev/null; cat /etc/resolv.conf" 2>&1 | head -20
  echo
done


ssh -o StrictHostKeyChecking=no -p 22 vyos@10.10.10.1

show system name-server
# or
show configuration commands | grep name-server



sshpass -p "ubuntu" ssh -o StrictHostKeyChecking=no ubuntu@192.168.30.210 "resolvectl dns ens3 && resolvectl status ens3 | grep -E 'Current DNS|DNS Servers'"


ssh -o StrictHostKeyChecking=no ubuntu@192.168.30.210 "echo ubuntu | sudo -S resolvectl dns ens3 10.10.10.10 10.10.10.20 && resolvectl dns ens3"