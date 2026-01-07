# console.py
from arp_poisoning import ARPPoisoner
from dns_spoofing import DNSSpoofer
from enum import Enum
from typing import Collection
import sys


class AttackType(Enum):
    ARP_POISONING = "arp_pois"
    DNS_SPOOFING = "dns_spoof"


class Console:
    
    @staticmethod
    def execute(argv: Collection[str]) -> None:
        if len(argv) == 0:
            raise ValueError("Attack type is not given.")
        
        match argv[0]:
            
            case AttackType.ARP_POISONING.value: 
                if len(argv) != 4:
                    raise ValueError(
                        "ARP Poisoning attack is invoked in the following way: \n"
                        "./path_to_main.py arp_pois ip1 ip2 interface")
                
                arp_poisoner = ARPPoisoner(argv[1], argv[2], argv[3])
                arp_poisoner.run()
            
            case AttackType.DNS_SPOOFING.value:
                if len(argv) != 4:
                    raise ValueError(
                        "DNS Spoofing attack is invoked in the following way: \n"
                        "./path_to_main.py dns_spoof target_domain fake_ip interface")
                
                dns_spoofer = DNSSpoofer(argv[1], argv[2], argv[3])
                dns_spoofer.run()
            
            case _:
                raise ValueError("Incorrect flag for attack type is provided. Choose 'arp_pois' or 'dns_spoof'.")