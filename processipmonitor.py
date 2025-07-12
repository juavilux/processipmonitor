from scapy.all import sniff, IP
import socket
import psutil
import time

seen_ips = set()

def get_process_info(ip, port):
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr and conn.raddr.ip == ip and conn.raddr.port == port:
            try:
                pid = conn.pid
                if pid:
                    proc = psutil.Process(pid)
                    return f"{proc.name()} (PID {pid})"
            except:
                pass
    return "Desconhecido"

def packet_callback(packet):
    if IP in packet:
        ip_dst = packet[IP].dst
        ip_src = packet[IP].src

        for ip in [ip_src, ip_dst]:
            if ip != "127.0.0.1" and ip not in seen_ips:
                seen_ips.add(ip)
                try:
                    host = socket.gethostbyaddr(ip)[0]
                except:
                    host = "Host desconhecido"

                port = packet.sport if ip == ip_src else packet.dport
                process_info = get_process_info(ip, port)

                print(f"[{time.strftime('%H:%M:%S')}] IP: {ip} | Host: {host} | Processo: {process_info}")

print("🔍 Monitorando IPs com nome de host e processo...\n")
sniff(prn=packet_callback, store=0)
