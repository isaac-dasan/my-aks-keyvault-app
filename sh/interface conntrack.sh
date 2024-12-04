# Policy based routing for eth0:
# Create eth0 routing table
echo "200 eth0_table" >> /etc/iproute2/rt_tables
# Make eth0 default in eth0_table
ip route add default via 169.254.1.1 dev eth0 table eth0_table
# connMark packets coming from eth0 as `1`
iptables -t mangle -A PREROUTING -i eth0 -j CONNMARK --set-mark 1
#Restore connMark to packet mark
iptables -t mangle -A OUTPUT -j CONNMARK --restore-mark
# Add a rule to lookup custom route table 200 for marked packets
ip rule add fwmark 1 table 200
