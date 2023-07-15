#REMEMBER TO DO system reset-configuration skip-backup=yes no-defaults=yes

#must set all private ip addresses as unique, otherwise PIM-SM sources will collide!

{

:delay 15s

:local publicIpAddressLastOctet 2;
:local lanNumber 24;   #SET THIS TO THE LAN NUMBER (permitted: 1-254).
		     #WILL GIVE A UNIQUE PRIVATE ADDRESS SPACE OF THE FORM 192.168.$lanNumber.1/24
		     #PUBLIC IP ADDRESS WILL BE SET TO 10.$lanNumber.0.$publicIpAddressLastOctet/16


:local numOfInterfaces;
:set numOfInterfaces [:len [/interface find name~"ether"]]; #get number of ether interfaces
:log info "This device has $numOfInterfaces ethernet interfaces.";
:log info "Creating two bridges: LAN and WAN"
/interface bridge add name=LAN
/interface bridge add name=WAN
:log info "Setting the first ether as WAN..."
interface bridge port add bridge=WAN interface=ether1
:log info "Setting the others as LAN..."
:foreach ethPort in=[/interface find name~"ether[^1]"] do={
	interface bridge port add bridge=LAN interface=$ethPort
} 
:log info "Setting public ip address..."
/ip addr add address="10.$lanNumber.0.$publicIpAddressLastOctet/16" interface=WAN
:log info "Setting private ip address..."
/ip addr add address="192.168.$lanNumber.1/24" interface=LAN
:log info "Generating pool"
/ip pool add ranges="192.168.$lanNumber.2-192.168.$lanNumber.254" name=dhcp-pool1
:log info "Activating DHCP server on LAN bridge"
/ip dhcp-server add interface=LAN address-pool=dhcp-pool1 authoritative=yes disabled=no name=dhcp1 use-radius=no
/ip dhcp-server network add address="192.168.$lanNumber.0/24" gateway="192.168.$lanNumber.1"

:log info "Copying firewall and NAT rules"
/ip firewall connection tracking
set enabled=auto generic-timeout=10m icmp-timeout=10s loose-tcp-tracking=yes \
    tcp-close-timeout=10s tcp-close-wait-timeout=10s tcp-established-timeout=\
    1d tcp-fin-wait-timeout=10s tcp-last-ack-timeout=10s \
    tcp-max-retrans-timeout=5m tcp-syn-received-timeout=5s \
    tcp-syn-sent-timeout=5s tcp-time-wait-timeout=10s tcp-unacked-timeout=5m \
    udp-stream-timeout=3m udp-timeout=10s
/ip firewall filter
add action=accept chain=input connection-state=established,related
add action=drop chain=input connection-state=invalid
add action=accept chain=input comment="allow icmp" in-interface=WAN protocol=\
    icmp
add action=accept chain=input comment="allow winbox" in-interface=WAN port=\
    8291 protocol=tcp
add action=accept chain=input comment="allow ssh" in-interface=WAN port=22 \
    protocol=tcp
add action=accept chain=input comment="allow PIM" in-interface=WAN protocol=\
    pim
add action=accept chain=input comment="allow IGMP" protocol=igmp
add action=accept chain=input comment="allow RIP updates" dst-port=520 \
    protocol=udp src-port=520
add action=drop chain=input comment="INPUT - DEFAULT DROP"
add action=fasttrack-connection chain=forward comment=\
    "Fasttrack for established, related" connection-state=established,related
add action=accept chain=forward comment=\
    "Accept if packet escapes fasttrack for established, related" \
    connection-state=established,related
add action=drop chain=forward comment="drop invalid" connection-state=invalid
add action=accept chain=forward comment="accept OMN traffic." dst-address=\
    239.192.0.66 protocol=udp
add action=drop chain=forward comment="drop those new connections not in DSTNA\
    T rules! This is the last rule, if otherwise accept default" \
    connection-nat-state=!dstnat connection-state=new in-interface=WAN
/ip firewall nat
add action=masquerade chain=srcnat !connection-bytes !connection-limit \
    !connection-mark !connection-rate !connection-type !content disabled=yes \
    !dscp !dst-address !dst-address-list !dst-address-type !dst-limit \
    !dst-port !fragment !hotspot !icmp-options !in-bridge-port \
    !in-bridge-port-list !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" \
    !nth !out-bridge-port !out-bridge-port-list out-interface=WAN \
    !out-interface-list !packet-mark !packet-size !per-connection-classifier \
    !port !priority !protocol !psd !random !routing-mark !routing-table \
    !src-address !src-address-list !src-address-type !src-mac-address \
    !src-port !tcp-mss !time !tls-host !to-addresses !to-ports !ttl
add action=masquerade chain=srcnat comment="Gotta NAT all traffic, even multic\
    ast, otherwise we can't have 2 OMN commanders/slave with the same IP behin\
    d 2 different NAT-ted subnets!" !connection-bytes !connection-limit \
    !connection-mark !connection-rate !connection-type !content disabled=no \
    !dscp !dst-address !dst-address-list !dst-address-type !dst-limit \
    !dst-port !fragment !hotspot !icmp-options !in-bridge-port \
    !in-bridge-port-list !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" \
    !nth !out-bridge-port !out-bridge-port-list out-interface=WAN \
    !out-interface-list !packet-mark !packet-size !per-connection-classifier \
    !port !priority !protocol !psd !random !routing-mark !routing-table \
    !src-address !src-address-list !src-address-type !src-mac-address \
    !src-port !tcp-mss !time !tls-host !to-addresses !to-ports !ttl
add action=masquerade chain=srcnat !connection-bytes !connection-limit \
    !connection-mark !connection-rate !connection-type !content disabled=yes \
    !dscp !dst-address !dst-address-list dst-address-type="" !dst-limit \
    !dst-port !fragment !hotspot !icmp-options !in-bridge-port \
    !in-bridge-port-list !in-interface !in-interface-list !ingress-priority \
    !ipsec-policy !ipv4-options !layer7-protocol !limit log=no log-prefix="" \
    !nth !out-bridge-port !out-bridge-port-list !out-interface \
    !out-interface-list !packet-mark !packet-size !per-connection-classifier \
    !port !priority protocol=udp !psd !random !routing-mark !routing-table \
    !src-address !src-address-list !src-address-type !src-mac-address \
    !src-port !tcp-mss !time !tls-host !to-addresses !to-ports !ttl
/ip firewall service-port
set ftp disabled=no ports=21
set tftp disabled=no ports=69
set irc disabled=no ports=6667
set h323 disabled=no
set sip disabled=no ports=5060,5061 sip-direct-media=yes sip-timeout=1h
set pptp disabled=no
set udplite disabled=no
set dccp disabled=no
set sctp disabled=no
/

:log info "Adding RIP network, will be shared!"
/routing rip network add network="10.$lanNumber.0.0/16"
:log info "Activating RIP interface..."
/routing rip interface add interface=WAN passive=no send=v2 receive=v1-2 authentication=none

:log info "Adding PIM"
/routing pim
set switch-to-spt=yes switch-to-spt-bytes=0 switch-to-spt-interval=1m40s
/routing pim interface
add alternative-subnets="" assert-override-interval=3s assert-time=3m \
    disabled=no dr-priority=1 hello-holdtime=1m45s hello-period=30s \
    hello-trigerred-delay=5s igmp-version=IGMPv2 interface=WAN \
    join-prune-holdtime=3m30s join-prune-period=1m override-interval=250 \
    preferred-source-address=0.0.0.0 propagation-delay=50 protocols=pim,igmp \
    require-hello=yes tracking-support=yes
add alternative-subnets="" assert-override-interval=3s assert-time=3m \
    disabled=no dr-priority=1 hello-holdtime=1m45s hello-period=30s \
    hello-trigerred-delay=5s igmp-version=IGMPv2 interface=LAN \
    join-prune-holdtime=3m30s join-prune-period=1m override-interval=250 \
    preferred-source-address=0.0.0.0 propagation-delay=50 protocols=pim,igmp \
    require-hello=yes tracking-support=yes
/routing pim rp
add address=10.1.0.1 comment=OMN disabled=no group=239.192.0.66/32 \
    hash-mask-length=30 priority=192
/

/system identity set name="LAN$lanNumber_ROUTER"
/ip dhcp-client remove 0
/tool romon set enabled=yes secrets="test_mikrotik"
/password old-password="" new-password="test_mikrotik" confirm-new-password="test_mikrotik"
/log info "Installation completed!"
}







