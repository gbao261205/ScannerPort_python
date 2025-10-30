# ScanDevicesIp.py
from scapy.all import ARP, Ether, srp

def arp_scan(target_ip):
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        print(f"[+] {received.psrc} - {received.hwsrc}")
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices
