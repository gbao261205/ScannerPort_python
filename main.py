# main.py
import GetIp
import ScanDevicesIp
import PortScanner
import NmapRunner   # <-- thêm

import re
import string
from typing import Union

def identify_service(port, banner):
    common = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        3306: "mysql",
        3389: "rdp",
        8080: "http-alt",
    }
    if banner:
        b = banner.lower()
        if "ssh" in b:
            return "ssh"
        if "ftp" in b:
            return "ftp"
        if "http" in b or "server:" in b:
            return "http"
        if "smtp" in b or b.startswith("220"):
            return "smtp"
        if "mysql" in b:
            return "mysql"
    return common.get(port, "unknown")

def prettyBanner(banner: Union[bytes, str], max_len: int = 200) -> str:
    if banner is None:
        return ""

    if isinstance(banner, bytes):
        try:
            s = banner.decode('utf-8', errors='replace')
        except Exception:
            s = banner.decode('latin-1', errors='replace')
    else:
        s = str(banner)

    http_pattern = re.compile(r'^\s*HTTP/\d\.\d', re.IGNORECASE)
    typical_header_pattern = re.compile(
        r'(?:^|\r|\n)(Content-Type|Server|Date|Connection|Content-Length)\s*:', re.IGNORECASE
    )

    if http_pattern.search(s) or typical_header_pattern.search(s):
        return "HTTP"

    printable = set(string.printable)
    cleaned = ''.join(ch if ch in printable else '?' for ch in s)

    cleaned = re.sub(r'\r\n(\r\n)+', '\r\n\r\n', cleaned)
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
    cleaned = re.sub(r'[ \t]{2,}', ' ', cleaned)

    if len(cleaned) > max_len:
        head = cleaned[: max_len // 2].rstrip()
        tail = cleaned[- (max_len // 2) :].lstrip()
        cleaned = head + '\n...<snip>...\n' + tail

    return cleaned


def main():
    # chỗ này tuỳ GetIp.main() của cậu trả về gì
    # nếu GetIp.main() trả về chỉ 1 giá trị thì đổi thành: target_cidr = GetIp.main()
    target_cidr = GetIp.main()
    if isinstance(target_cidr, tuple):
        # trường hợp cũ của cậu: return f"{netip}/{prefix}", netip
        target_cidr = target_cidr[0]

    if not target_cidr:
        print("Không lấy được dải mạng để quét.")
        return

    print(f"Bắt đầu ARP scan trên: {target_cidr}")
    devices = ScanDevicesIp.arp_scan(target_cidr)

    if not devices:
        print("Không tìm thấy thiết bị nào trong mạng.")
        return

    # kiểm tra luôn 1 lần ở đầu
    has_nmap = NmapRunner.is_nmap_available()
    if not has_nmap:
        print("[i] Nmap chưa cài hoặc chưa có trong PATH. Vẫn quét được nhưng không chạy dò lỗ hổng nâng cao.")

    for dev in devices:
        target = dev['ip']
        print(f"\n======================================")
        print(f"Quét cổng trên thiết bị: {target}")
        open_ports = PortScanner.scan_host_ports(target, start_port=1, end_port=9999, threads=100)

        if open_ports:
            for item in open_ports:
                port = item["port"]
                banner = item["banner"]
                service = identify_service(port, banner)
                print(f"Port {port} open -> {service} | {prettyBanner(banner)}")
        else:
            print(f"Không tìm thấy cổng mở trên {target}.")
            continue  # không có port thì khỏi chạy nmap

        # ======================
        # GỌI NMAP Ở ĐÂY
        # ======================
        if has_nmap:
            print(f"\n[+] Chạy nmap trên {target} cho các cổng đã mở ...")
            nmap_output = NmapRunner.run_nmap(target, open_ports, scripts="vuln")
            print(nmap_output)
        else:
            print("[i] Bỏ qua bước nmap vì chưa có nmap.")

if __name__ == "__main__":
    main()
