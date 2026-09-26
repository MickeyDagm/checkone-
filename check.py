for ip in \
10.10.10.200 \
10.10.10.210 \
10.10.10.10 \
10.10.10.20 \
192.168.10.101 \
192.168.20.100 \
192.168.30.101 \
192.168.10.102 \
10.10.10.1 \
10.10.10.100 \
192.168.20.210 \
192.168.30.210
do

    echo "========== $ip =========="

    case "$ip" in

        10.10.10.1)
            echo "ROUTER1 - VyOS"

            ssh -o StrictHostKeyChecking=no \
                -o ConnectTimeout=5 \
                vyos@$ip \
                "/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands | grep name-server; echo '--- resolv.conf ---'; cat /etc/resolv.conf" \
                2>&1 | head -20
            ;;

        *)
            ssh -o StrictHostKeyChecking=no \
                -o ConnectTimeout=5 \
                ubuntu@$ip \
                "hostname; resolvectl dns 2>/dev/null; cat /etc/resolv.conf" \
                2>&1 | head -20
            ;;

    esac

    echo
done