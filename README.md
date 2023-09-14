# fwmark - Kubernetes CNI Plugin

The `fwmark` CNI plugin allows setting a netfilter/iptables mark based on pod
annotations.

## Use case

Each kubernetes node may have an interface called `vpn0` set up through some
out-of-band process. There may be a requirement that all internet traffic
originating from a certain pod should be routed through this interface, to
ensure that anytime the pod talks to the internet, it happens through a VPN
connection.

Practically, this can be accomplished by setting a `mark` on the traffic coming
from certain pods, and using that to route the traffic through a different
default gateway. This plugin provides the ability to set that `mark`.

Now for the real-world example:  we've set up an OpenVPN client in OPNsense to
some external VPN provider's service. We've also set up a firewall rule for
packets originating from a specific subnet on the LAN network (`192.168.2.x`) to
have its gateway set to this OpenVPN client's interface, effectively routing
any internet traffic from that subnet through our upstream VPN provider.

On each kubernetes node, through some infrastructure management process, we set
up an interface called `vpn0` which is tied to the `eth0` physical interface.
We assign an IP within the above subnet to this interface, and make sure that
the marked traffic goes through this interface to reach its default gateway.

A node might have the following commands run to set this up:

```bash
# Create vpn0 interface
ip link add name vpn0 link eth0 type macvlan

# Set the vpn0 interface address
ip addr add 192.168.2.10/24 dev vpn0

# Bring the vpn0 interface up
ip link set dev vpn0 up

# Set up default route for interface in a separate table with ID 123
ip route add default via 192.168.2.1 dev vpn0 table 123

# NOTE: The priority for the rule which looks up the main table for every
# request is 32766, and each table should have a unique priority.

# First, check the main table for any non-default routes
ip rule add priority 32764 from all lookup main suppress_prefixlength 0

# Then, for traffic where the 5th bit mark is set (0x10 or 16) use the default gatway
# above defined in table 123.
ip rule add priority 32765 from all fwmark 0x10/0x10 lookup 123

# By default, rule 32766 looks up routes (including the default gateway) from
# the main table for all packets
```

**Now all you need to do is set the `mark` certain pods to the correct value
(`0x10/0x10`, where `0x10`in hex is `16` in decimal), and that pod's traffic
will be routed through the VPN client on OPNsense.**

To accomplish this, add the `fwmark` plugin to the CNI chain after your main
network provider (flannel, calico, etc):

```json
{
  "type": "fwmark",
  "capabilities": {
     "io.kubernetes.cri.pod-annotations": true
  },
  "marks": {
     "vpn": {"mark": 16, "mask": 16}
  }
}

```

In context, with the default `k3s` CNI configuration:


```json
{
  "name":"cbr0",
  "cniVersion":"1.0.0",
  "plugins":[
    {
      "type":"flannel",
      "delegate":{
        "hairpinMode":true,
        "forceAddress":true,
        "isDefaultGateway":true
      }
    },
    {
      "type":"portmap",
      "capabilities":{
        "portMappings":true
      }
    },
    {
      "type":"bandwidth",
      "capabilities":{
        "bandwidth":true
      }
    },
    {
      "type": "fwmark",
      "capabilities": {
         "io.kubernetes.cri.pod-annotations": true
      },
      "marks": {
         "vpn": {"mark": 16, "mask": 16}
      }
    }
  ]
}

```

Now the setup is done! Just mark any pods with the following annotation to set
the default gateway for that pod:

```
cni.fwmark.net/name: vpn
```

This will match with the `vpn` entry in the `marks` object in the CNI
configuration and set the corresponding mark in the `mangle` table for any
packets originating from the annotated pod.

The possibilities are limitless. The rest is up to you!
