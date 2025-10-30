# GetIp.py
import platform
import re
import subprocess
import ipaddress

def _parse_windows_block(name, block_lines):
    block_text = "\n".join(block_lines)
    ip_match = re.search(r"IPv4 Address.*?:\s*([\d.]+)", block_text)
    mask_match = re.search(r"Subnet Mask.*?:\s*([\d.]+)", block_text)

    if ip_match and mask_match:
        ip = ip_match.group(1)
        mask = mask_match.group(1)
        return {
            "name": name,
            "ip": ip,
            "mask": mask
        }
    return None

def get_ifaces_windows():
    output = subprocess.check_output("ipconfig", encoding="utf-8", errors="ignore")
    lines = output.splitlines()

    ifaces = []
    current_name = None
    current_block = []

    for line in lines:
        line_stripped = line.strip()

        # đúng tên interface
        if line_stripped.endswith(":") and "adapter" in line_stripped.lower():
            # đóng block cũ
            if current_name and current_block:
                iface = _parse_windows_block(current_name, current_block)
                if iface:
                    ifaces.append(iface)
            # mở block mới
            current_name = line_stripped
            current_block = []
        else:
            if current_name:
                current_block.append(line)

    # block cuối
    if current_name and current_block:
        iface = _parse_windows_block(current_name, current_block)
        if iface:
            ifaces.append(iface)

    return ifaces

def get_ifaces_unix():
    ifaces = []
    try:
        output = subprocess.check_output(["ip", "addr"], encoding="utf-8", errors="ignore")
        blocks = re.split(r"\n\d+:\s", "\n" + output)[1:]
        for b in blocks:
            lines = b.splitlines()
            name = lines[0].split(":")[0].strip()
            for line in lines:
                m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
                if m:
                    ip = m.group(1)
                    prefix = int(m.group(2))
                    mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
                    ifaces.append({
                        "name": name,
                        "ip": ip,
                        "mask": mask
                    })
    except Exception:
        pass
    return ifaces

def list_all_ifaces():
    system = platform.system().lower()
    if "windows" in system:
        return get_ifaces_windows()
    else:
        return get_ifaces_unix()

def calc_network(ip, mask):
    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    return str(net.network_address), str(net.netmask), net.prefixlen

def main():
    """Hàm này HIỂN THỊ và CHO CHỌN, sau đó TRẢ VỀ network/prefix."""
    ifaces = list_all_ifaces()

    cleaned = []
    for iface in ifaces:
        ip = iface["ip"]
        if ip.startswith("127."):
            continue
        if ip.startswith("169.254."):
            continue
        cleaned.append(iface)

    if not cleaned:
        print("Không tìm thấy interface IPv4 nào phù hợp.")
        return None, None

    print("Các interface tìm thấy:")
    for idx, iface in enumerate(cleaned):
        ip = iface["ip"]
        mask = iface["mask"]
        netip, _, prefix = calc_network(ip, mask)
        print(f"{idx}. {iface['name']}  -> IP: {ip}  Mask: {mask}  Network: {netip}/{prefix}")

    choice = input("Chọn số interface muốn quét (0,1,2,...): ").strip()
    try:
        choice = int(choice)
    except ValueError:
        print("Lựa chọn không hợp lệ.")
        return None, None

    if choice < 0 or choice >= len(cleaned):
        print("Lựa chọn ngoài phạm vi.")
        return None, None

    chosen = cleaned[choice]
    ip = chosen["ip"]
    mask = chosen["mask"]
    netip, netmask, prefix = calc_network(ip, mask)

    print("\nBạn đã chọn:")
    print(f"Interface: {chosen['name']}")
    print(f"IP: {ip}")
    print(f"Mask: {mask} (/{prefix})")
    print(f"Dải mạng: {netip}/{prefix}")

    # QUAN TRỌNG: TRẢ VỀ ĐỂ FILE main.py DÙNG
    return f"{netip}/{prefix}", netip
