# main.py
import GetIp
import ScanDevicesIp
import PortScanner

import re
import string
from typing import Union

def identify_service(port, banner):
    # 1. thử map theo port trước
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
    """
    Nhận banner (bytes hoặc str). Nếu banner trông giống phản hồi HTTP,
    trả về "HTTP". Ngược lại, trả về banner đã được làm sạch (loại bỏ ký tự không in được),
    và cắt ngắn nếu quá dài.

    Tham số:
    - banner: bytes hoặc str
    - max_len: độ dài tối đa của chuỗi trả về (mặc định 200)

    Trả về:
    - str: "HTTP" nếu là HTTP, hoặc chuỗi đã làm sạch khác.
    """
    if banner is None:
        return ""

    # Nếu là bytes, chuyển sang str bằng utf-8 (fallback latin1 để giữ byte values)
    if isinstance(banner, bytes):
        try:
            s = banner.decode('utf-8', errors='replace')
        except Exception:
            s = banner.decode('latin-1', errors='replace')
    else:
        s = str(banner)

    # Xác định HTTP: bắt đầu bằng "HTTP/" hoặc có header HTTP điển hình (Content-Type, Server, HTTP/1.1 ... \r\n)
    http_pattern = re.compile(r'^\s*HTTP/\d\.\d', re.IGNORECASE)
    typical_header_pattern = re.compile(
        r'(?:^|\r|\n)(Content-Type|Server|Date|Connection|Content-Length)\s*:', re.IGNORECASE
    )

    if http_pattern.search(s) or typical_header_pattern.search(s):
        return "HTTP"

    # Nếu không phải HTTP, làm sạch: loại bỏ các ký tự non-printable, giữ tab/newline/carriage return
    printable = set(string.printable)
    cleaned = ''.join(ch if ch in printable else '?' for ch in s)

    # Loại bỏ chuỗi điều khiển lặp lại \r\n dư thừa ở cuối, rút gọn khoảng trắng liền kề
    # Thay thế nhiều newline thành tối đa 3 newline
    cleaned = re.sub(r'\r\n(\r\n)+', '\r\n\r\n', cleaned)
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
    cleaned = re.sub(r'[ \t]{2,}', ' ', cleaned)

    # Nếu quá dài, cắt ngắn và báo bằng dấu "..." ở giữa hoặc cuối
    if len(cleaned) > max_len:
        # giữ đầu và cuối để dễ nhận biết
        head = cleaned[: max_len // 2].rstrip()
        tail = cleaned[- (max_len // 2) :].lstrip()
        cleaned = head + '\n...<snip>...\n' + tail

    return cleaned


def main():
    target_cidr, _ = GetIp.main()
    if not target_cidr:
        print("Không lấy được dải mạng để quét.")
        return

    # dùng luôn dải lấy được
    print(f"Bắt đầu ARP scan trên: {target_cidr}")
    device = ScanDevicesIp.arp_scan(target_cidr)
    # print(f"Tổng số thiết bị tìm thấy: {len(device)}")
    if not device:
        print("Không tìm thấy thiết bị nào trong mạng.")
        return
    
    for i in range(len(device)):
        target=device[i]['ip']
        print(f"\nQuét cổng trên thiết bị: {target}")
        open_ports = PortScanner.scan_host_ports(target, start_port=1, end_port=9999, threads=100)
        if open_ports:
            #print(f"Cổng mở trên {target}: {open_ports['port']}")
            for item in open_ports:
                port = item["port"]
                banner = item["banner"]
                service = identify_service(port, banner)
                print(f"Port {port} open -> {service} | {prettyBanner(banner)}")
        else:
            print(f"Không tìm thấy cổng mở trên {target}.")
        

    
if __name__ == "__main__":
    main()
