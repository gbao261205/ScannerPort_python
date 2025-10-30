# NmapRunner.py
import shutil
import subprocess

def is_nmap_available() -> bool:
    """Kiểm tra xem máy có nmap trong PATH không."""
    return shutil.which("nmap") is not None

def run_nmap(ip: str, ports: list[int] | list[dict], scripts: str = "vuln") -> str:
    """
    Chạy nmap trên 1 host với danh sách port đã phát hiện.
    ports: có thể là [80,443] hoặc [{"port": 80, ...}, ...]
    """
    if not ports:
        return "No open ports to scan."

    # chuẩn hoá port -> "80,443,8080"
    if isinstance(ports[0], dict):
        port_list = [str(p["port"]) for p in ports]
    else:
        port_list = [str(p) for p in ports]
    ports_str = ",".join(port_list)

    cmd = ["nmap", ports_str]
    if scripts:
        cmd += ["--script", scripts]
    cmd.append(ip)

    # chạy nmap
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        # nếu lỗi thì trả cả stderr để debug
        return proc.stdout + "\n" + proc.stderr
    return proc.stdout
