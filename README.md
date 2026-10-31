# Packet Sniffer in C

A command-line packet sniffer built on Linux raw sockets (`AF_PACKET`).
Parses Ethernet, ARP, IPv4, TCP, UDP and ICMP headers, with filtering and a traffic summary.

## Build & run
    make
    sudo ./sniffer                    # all interfaces
    sudo ./sniffer -I eth0 -p tcp -P 443
    sudo ./sniffer -i 8.8.8.8 -p icmp -n 10
    sudo ./sniffer -p udp -x          # with hex dump

## Options
| Flag | Meaning |
|------|---------|
| -I iface | capture on one interface |
| -p proto | tcp, udp, icmp, arp |
| -i ip    | match source or destination IPv4 |
| -P port  | match source or destination port (TCP/UDP) |
| -n N     | stop after N matching packets |
| -x       | hex dump |

## How it works
1. `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` receives whole Ethernet frames.
2. Each frame is cast to `struct ether_header`, then the IPv4 header (length from IHL x 4), then the L4 header.
3. Multi-byte fields are converted with `ntohs`/`ntohl`; lengths are bounds-checked before every cast.
4. Ctrl+C sets a flag and prints per-protocol counts and top talkers.

## Testing
Generate traffic with `ping 8.8.8.8`, `curl example.com`, `nslookup google.com`
and compare with Wireshark / `tcpdump`.

## Ideas to extend
- GRE encapsulation + forwarding to a remote host
- IPv6 and DNS parsing
- Write a .pcap file
- TCP flow tracking
