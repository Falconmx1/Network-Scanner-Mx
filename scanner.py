#!/usr/bin/env python3
# Network Scanner Mx - Escáner de red local PROFESIONAL
# Autor: Falconmx1
# Repo: https://github.com/Falconmx1/Network-Scanner-Mx
# Uso: python scanner.py [OPCIONES]

import scapy.all as scapy
import argparse
import socket
import platform
import subprocess
import sys
import re
import json
import csv
from datetime import datetime
import threading
from queue import Queue

# Colores para terminal (ANSI)
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[04m'

# Variables globales
verbose_mode = False
scan_results = []

def print_verbose(message, level="INFO"):
    """Imprime mensajes solo si verbose está activado"""
    if verbose_mode:
        color = Colors.GREEN if level == "INFO" else Colors.YELLOW if level == "WARN" else Colors.RED
        print(f"{color}[{level}]{Colors.END} {message}")

def get_network_range():
    """Detecta automáticamente la red local actual"""
    sistema = platform.system()
    print_verbose(f"Sistema operativo detectado: {sistema}")
    
    try:
        if sistema == "Windows":
            resultado = subprocess.run(["ipconfig"], capture_output=True, text=True)
            ip_match = re.search(r"IPv4.*: (\d+\.\d+\.\d+\.\d+)", resultado.stdout)
            if ip_match:
                ip = ip_match.group(1)
                network = ".".join(ip.split(".")[:3]) + ".1/24"
                print_verbose(f"IP detectada: {ip}, red: {network}")
                return network
        else:  # Linux / macOS
            resultado = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for linea in resultado.stdout.split("\n"):
                if "src" in linea:
                    partes = linea.split()
                    for i, p in enumerate(partes):
                        if p == "src":
                            ip = partes[i+1]
                            network = ".".join(ip.split(".")[:3]) + ".1/24"
                            print_verbose(f"IP detectada: {ip}, red: {network}")
                            return network
    except Exception as e:
        print_verbose(f"Error detectando red: {e}", "WARN")
    
    network = input(f"{Colors.YELLOW}No se pudo detectar la red. Escribe el rango (ej. 192.168.1.0/24): {Colors.END}")
    return network

def get_vendor_from_oui(oui_prefix):
    """Consulta fabricante por OUI (base extendida)"""
    vendors = {
        "0001C2": "Cisco Systems", "0050F2": "Microsoft", "8C1D96": "Intel",
        "EC1A59": "TP-Link", "4C3275": "D-Link", "F09FC2": "Arris Group",
        "00249B": "Belkin", "6881A4": "Samsung", "B827EB": "Raspberry Pi",
        "A4BF01": "Google", "000A95": "Sony", "001A11": "Apple",
        "001CF0": "Huawei", "002268": "Xiaomi", "002590": "Netgear",
        "00306E": "Motorola", "00A0C9": "3Com", "08002B": "DEC",
        "080009": "Hewlett Packard", "00037F": "Nintendo", "000F3D": "Roku",
        "0015C5": "Amazon", "001DAA": "Raspberry Pi", "E0D55E": "Espressif",
        "000666": "Zyxel", "001A70": "Tenda"
    }
    return vendors.get(oui_prefix[:6], "Desconocido")

def scan_ports(ip, ports=[22, 80, 443, 8080, 3306, 3389]):
    """Escanea puertos comunes en un dispositivo"""
    open_ports = []
    print_verbose(f"Escaneando puertos en {ip}...")
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                print_verbose(f"  Puerto {port} ABIERTO en {ip}", "INFO")
            sock.close()
        except:
            pass
    return open_ports

def scan_network(ip_range):
    """Envía ARP requests para descubrir dispositivos"""
    print_verbose(f"Iniciando escaneo ARP en {ip_range}")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    try:
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
        print_verbose(f"Paquetes ARP enviados. Respuestas recibidas: {len(answered_list)}")
    except Exception as e:
        print_verbose(f"Error en escaneo ARP: {e}", "ERROR")
        return []
    
    devices = []
    total = len(answered_list)
    
    for idx, element in enumerate(answered_list):
        ip = element[1].psrc
        mac = element[1].hwsrc
        oui = mac[:8].upper().replace(":", "")
        vendor = get_vendor_from_oui(oui)
        
        print_verbose(f"[{idx+1}/{total}] Dispositivo encontrado: {ip} - {vendor}")
        
        device = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "open_ports": []
        }
        devices.append(device)
    
    return devices

def display_results(devices):
    """Muestra resultados con estilo y colores"""
    print("\n" + Colors.CYAN + "="*70 + Colors.END)
    print(Colors.BOLD + Colors.GREEN + " 🔍 Network Scanner Mx - Dispositivos en la red" + Colors.END)
    print(Colors.CYAN + "="*70 + Colors.END)
    print(f"{Colors.YELLOW}{'IP':<18} {'MAC':<18} {'Fabricante':<22} {'Puertos abiertos'}{Colors.END}")
    print(Colors.CYAN + "-"*70 + Colors.END)
    
    for device in devices:
        ports_str = ", ".join(map(str, device['open_ports'])) if device['open_ports'] else "Ninguno"
        if device['open_ports']:
            ports_str = Colors.RED + ports_str + Colors.END
        else:
            ports_str = Colors.GREEN + ports_str + Colors.END
            
        print(f"{Colors.CYAN}{device['ip']:<18}{Colors.END} "
              f"{device['mac']:<18} "
              f"{Colors.BLUE}{device['vendor']:<22}{Colors.END} "
              f"{ports_str}")
    
    print(Colors.CYAN + "="*70 + Colors.END)
    print(f"{Colors.GREEN}{Colors.BOLD}✅ Total dispositivos encontrados: {len(devices)}{Colors.END}\n")

def export_json(devices, filename=None):
    """Exporta resultados a JSON"""
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_scan_{timestamp}.json"
    
    export_data = {
        "scan_date": datetime.now().isoformat(),
        "total_devices": len(devices),
        "devices": devices
    }
    
    with open(filename, 'w') as f:
        json.dump(export_data, f, indent=4)
    
    print(f"{Colors.GREEN}✅ Datos exportados a {filename}{Colors.END}")
    return filename

def export_csv(devices, filename=None):
    """Exporta resultados a CSV"""
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_scan_{timestamp}.csv"
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "MAC", "Fabricante", "Puertos Abiertos"])
        for device in devices:
            ports_str = "|".join(map(str, device['open_ports'])) if device['open_ports'] else ""
            writer.writerow([device['ip'], device['mac'], device['vendor'], ports_str])
    
    print(f"{Colors.GREEN}✅ Datos exportados a {filename}{Colors.END}")
    return filename

def banner():
    """Muestra banner con estilo"""
    banner_text = f"""
{Colors.RED}╔══════════════════════════════════════════════════════════════════╗
{Colors.RED}║{Colors.YELLOW}      ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  {Colors.RED}║
{Colors.RED}║{Colors.YELLOW}      ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║  {Colors.RED}║
{Colors.RED}║{Colors.YELLOW}      ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝██║  {Colors.RED}║
{Colors.RED}║{Colors.YELLOW}      ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██║  {Colors.RED}║
{Colors.RED}║{Colors.YELLOW}      ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║███████╗{Colors.RED}║
{Colors.RED}║{Colors.YELLOW}      ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝{Colors.RED}║
{Colors.RED}║{Colors.CYAN}                        📡 Network Scanner Mx                          {Colors.RED}║
{Colors.RED}║{Colors.GREEN}                   🔐 Ethical Network Discovery Tool                    {Colors.RED}║
{Colors.RED}║{Colors.BLUE}                      👤 Falconmx1 | v2.0                                {Colors.RED}║
{Colors.RED}╚══════════════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner_text)

def main():
    global verbose_mode, scan_results
    
    parser = argparse.ArgumentParser(
        description="Network Scanner Mx - Escáner profesional de red local",
        epilog="Ejemplo: python scanner.py -r 192.168.1.0/24 -p -v -o json"
    )
    parser.add_argument("-r", "--range", help="Rango de red (ej. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", action="store_true", help="Escanea puertos comunes en cada dispositivo")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose - muestra detalles del escaneo")
    parser.add_argument("-o", "--output", choices=['json', 'csv', 'both'], help="Exportar resultados a JSON y/o CSV")
    parser.add_argument("--no-color", action="store_true", help="Desactiva los colores en la terminal")
    
    args = parser.parse_args()
    
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith("__"):
                setattr(Colors, attr, "")
    
    if args.verbose:
        global verbose_mode
        verbose_mode = True
    
    banner()
    
    if args.range:
        network_range = args.range
        print_verbose(f"Rango especificado manualmente: {network_range}")
    else:
        network_range = get_network_range()
    
    print(f"\n{Colors.CYAN}🌐 Escaneando red: {Colors.BOLD}{network_range}{Colors.END}")
    print(f"{Colors.YELLOW}🕒 Por favor espera, esto puede tomar unos segundos...{Colors.END}\n")
    
    # Escaneo de red
    devices = scan_network(network_range)
    
    if not devices:
        print(f"{Colors.RED}❌ No se encontraron dispositivos en la red. Verifica tu conexión.{Colors.END}")
        return
    
    # Escaneo de puertos opcional
    if args.ports:
        print(f"{Colors.YELLOW}🔓 Iniciando escaneo de puertos en {len(devices)} dispositivos...{Colors.END}")
        for idx, device in enumerate(devices):
            print_verbose(f"Escaneando puertos en {device['ip']} ({idx+1}/{len(devices)})")
            device['open_ports'] = scan_ports(device['ip'])
        print()
    
    # Mostrar resultados
    display_results(devices)
    
    # Exportar resultados
    if args.output:
        print(f"{Colors.CYAN}📁 Exportando resultados...{Colors.END}")
        if args.output in ['json', 'both']:
            export_json(devices)
        if args.output in ['csv', 'both']:
            export_csv(devices)
    
    scan_results = devices

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️ Escaneo interrumpido por el usuario.{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}❌ Error inesperado: {e}{Colors.END}")
        sys.exit(1)
