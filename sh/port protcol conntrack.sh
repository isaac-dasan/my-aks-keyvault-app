# Set Connection Marks on Incoming Packets: Use iptables to mark incoming packets.
# For example, to mark packets coming to port 80:
iptables -t mangle -A PREROUTING -p tcp --dport 80 -j CONNMARK --set-mark 1
# Restore Connection Marks to Packet Marks:
# Ensure that the connection mark is restored to the packet mark for outgoing packets:
iptables -t mangle -A OUTPUT -j CONNMARK --restore-mark
# Add Routing Rules Based on Marks: Add rules to route packets based on the marks.
# First, create custom routing tables in /etc/iproute2/rt_tables:
echo "100 custom_table1" | tee -a /etc/iproute2/rt_tables
# Configure Routes in Custom Tables: Add routes to the custom tables. For example:
ip route add default via <gateway1> dev <interface1> table custom_table1
# Add IP Rules to Use Custom Tables: Add rules to use the custom routing tables based on the packet marks:
ip rule add fwmark 1 table custom_table1
#Verify the Configuration: Check the rules and routes to ensure they are set correctly:
ip rule show
ip route show table custom_table1