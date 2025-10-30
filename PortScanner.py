# PortScanner.py
import socket
import threading
from queue import Queue

def grab_banner(ip, port, timeout=1.0):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        # thử nhận trước
        try:
            data = s.recv(1024)
            if data:
                return data.decode(errors="ignore").strip()
        except socket.timeout:
            pass
        # thử HTTP
        try:
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = s.recv(1024)
            if data:
                return data.decode(errors="ignore").strip()
        except:
            pass
    except:
        return None
    finally:
        try: s.close()
        except: pass
    return None

def worker(target, port_queue, results, lock):
    while not port_queue.empty():
        port = port_queue.get()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((target, port))
        except:
            s.close()
        else:
            banner = grab_banner(target, port)
            with lock:
                results.append({
                    "port": port,
                    "banner": banner,
                })
            s.close()
        finally:
            port_queue.task_done()

def scan_host_ports(target, start_port=1, end_port=1024, threads=100):
    port_queue = Queue()
    results = []
    lock = threading.Lock()

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    for _ in range(threads):
        t = threading.Thread(target=worker, args=(target, port_queue, results, lock))
        t.daemon = True
        t.start()

    port_queue.join()

    # sắp xếp theo port
    results.sort(key=lambda x: x["port"])
    return results
