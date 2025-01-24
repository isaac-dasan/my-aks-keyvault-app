eth0_ip_addr=$(ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
eth1_ip_addr=$(ip addr show eth1 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)

# Any packet with the FW mark of 3740 (eth0) or from a source ip address of eth0 should 
# lookup table 200, which defaults to eth0
ip rule add from $eth0_ip_addr lookup 200
ip route add default dev eth0 proto static table 200

# If we only want to do the solution proposed by MS, set this env to true
[[ $ONLY_MS_PBR == true ]] && exit

# If we continue on, we are executing whats proposed here:
# https://confluence.ngage.netapp.com/pages/viewpage.action?pageId=987245656#SwiftEnabledPublicEgressviaProxy(NGINX)-NTAPCounterProposal
# Here is the hack we came up with just as an internal demo. Since in our stack all traffic leaving istio-proxy should be eth0 traffic,
# we can add marks on istio-proxy traffic (basically using istio-proxy as the policy to base our routing) that is destined for eth1 and use SNAT to change the source address.
# We would not propose this as a viable solution but since you are curious
ip rule add fwmark 3740 table 200
iptables -t mangle -N QUARK_OUTPUT

# Jump to QUARK_OUTPUT if the process emittting the packet is Istio and the source address is eth1.
# This should only happen when Istio sets the destination address to cluster external
iptables -t mangle -A OUTPUT -s $eth1_ip_addr/32 -m owner --uid-owner 1337 -j QUARK_OUTPUT
iptables -t mangle -A OUTPUT -s $eth1_ip_addr/32 -m owner --gid-owner 1337 -j QUARK_OUTPUT

# Any packet redirected to this chain will get the "eth0" mark
iptables -t mangle -A QUARK_OUTPUT -j MARK --set-mark 3740
if [[ $ADD_IPTABLE_LOGS == true ]]; then
  iptables -t mangle -I QUARK_OUTPUT 1 -j LOG --log-prefix "QUARK_OUTPUT-IN: "
  iptables -t mangle -A QUARK_OUTPUT -j LOG --log-prefix "QUARK_OUTPUT-OUT: "
fi

iptables -t nat -N QUARK_POSTROUTING

# Jump to the QUARK_POSTROUTING table if the soruce address is eth1 but the output interface is eth0
# and the process emitting the packet is Istio. These packets have gone through routing with the FW mark 
# and have been translated to eth0 while maintinain the original default source.
iptables -t nat -A POSTROUTING -s $eth1_ip_addr/32 -o eth0 -m owner --uid-owner 1337 -j QUARK_POSTROUTING
iptables -t nat -A POSTROUTING -s $eth1_ip_addr/32 -o eth0 -m owner --gid-owner 1337 -j QUARK_POSTROUTING

# Any packet reirected to this chain will be SNATed to eth0
iptables -t nat -A QUARK_POSTROUTING -j SNAT --to-source $eth0_ip_addr
if [[ $ADD_IPTABLE_LOGS == true ]]; then
  iptables -t nat -I QUARK_POSTROUTING 1 -j LOG --log-prefix "QUARK_POSTROUTING-IN: "
  iptables -t nat -A QUARK_POSTROUTING -j LOG --log-prefix "QUARK_POSTROUTING-OUT: "
fi

# We need to relax the reverse path to allow the packet coming back to be recieved.
# This is because Istio will be listening on eth1 but our NATed packet will come back on eth0.
# Conntrack will reverse the source back to eth1 but not the interface.
# This is asymetric routing.
#
# 2 - Loose mode as defined in RFC3704 Loose Reverse Path
#       Each incoming packet's source address is also tested against the FIB
#       and if the source address is not reachable via any interface
#       the packet check will fail.
#
#   Current recommended practice in RFC3704 is to enable strict mode
#   to prevent IP spoofing from DDos attacks. If using asymmetric routing
#   or other complicated routing, then loose mode is recommended.
#
# See "rp_filter" here for more: https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
sysctl -w net.ipv4.conf.eth0.rp_filter=2