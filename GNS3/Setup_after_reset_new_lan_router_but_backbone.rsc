{
:local input do={:put $1;:return}
:local numNewLan ([$input "Give me the number of LAN you adding: "])

:local numLanInterface ($numNewLan+1)

:put "Adding bridge LAN$numNewLan"
/interface bridge add name="LAN$numNewLan"

:put "Adding port ether$numLanInterface to bridge LAN$numNewLan"
/interface bridge port add interface="ether$numLanInterface" bridge="LAN$numNewLan"

:put "Adding router's ip address 10.$numNewLan.0.1/16 to interface LAN$numNewLan"
/ip addr add address="10.$numNewLan.0.1/16" interface="LAN$numNewLan"


:put "Adding new network 10.$numNewLan.0.0/16 to RIP network list to be shared"
/routing rip network add network="10.$numNewLan.0.0/16"


:put "Adding new RIP interface at port LAN$numNewLan"
/routing rip interface add interface="LAN$numNewLan"


:put "Adding new PIM-SM interface at port LAN$numNewLan"
/routing pim interface add alternative-subnets=192.168.1.0/24 assert-override-interval=3s \
    assert-time=3m disabled=no dr-priority=1 hello-holdtime=1m45s \
    hello-period=30s hello-trigerred-delay=5s igmp-version=IGMPv2 interface=\
    "LAN$numNewLan" join-prune-holdtime=3m30s join-prune-period=1m override-interval=250 \
    preferred-source-address=0.0.0.0 propagation-delay=50 protocols=pim,igmp \
    require-hello=yes tracking-support=yes


}
