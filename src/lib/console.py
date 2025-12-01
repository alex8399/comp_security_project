from arp_poisoning import ARPPoisoner
from enum import Enum
from typing import Collection


class AttackType(Enum):
    ARP_POISONING = "arp_pois"


class Console:
    
    @staticmethod
    def execute(self, argv: Collection[str]) -> None:
        if len(argv) == 0:
            raise ValueError("Attack type is not given.")
        
        match argv[0]:
            case AttackType.ARP_POISONING:
                if len(argv) != 4:
                    raise ValueError(
                        "ARP Poisoning attack is invoking in the following way: \n\
                        ./main.py ip1 ip2 interface")
                
                ARPPoisoner.run(argv[1], argv[2], argv[3])
            case _:
                raise ValueError("Incorrect flag for attack type was provided.")