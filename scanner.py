#!/usr/bin/env python3
# Network Scanner Mx - Escáner de red local
# Autor: TuNombre
# Uso: python scanner.py -r 192.168.1.0/24

import scapy.all as scapy
import argparse
import socket
import platform
import subprocess
import sys
import re

def get_network_range():
    """Detecta automáticamente la red local actual"""
    sistema = platform.system()
    try:
        if sistema == "Windows":
            resultado = subprocess.run(["ipconfig"], capture_output=True, text=True)
            ip_match = re.search(r"IPv4.*: (\d+\.\d+\.\d+\.\d+)", resultado.stdout)
            if ip_match:
                ip = ip_match.group(1)
                return ".".join(ip.split(".")[:3]) + ".1/24"
        else:  # Linux / macOS
            resultado = subprocess.run(["ip", "route"], capture_output=True, text=True)
            for linea in resultado.stdout.split("\n"):
                if "src" in linea:
                    partes = linea.split()
                    for i, p in enumerate(partes):
                        if p == "src":
                            ip = partes[i+1]
                            return ".".join(ip.split(".")[:3]) + ".1/24"
    except:
        pass
    return input("No se pudo detectar la red. Escribe el rango (ej. 192.168.1.0/24): ")

def scan(ip_range):
    """Envía ARP requests para descubrir dispositivos"""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        # Intenta obtener nombre del fabricante (OUI)
        oui = element[1].hwsrc[:8].upper().replace(":", "")
        device["vendor"] = get_vendor_from_oui(oui)
        devices.append(device)
    return devices

def get_vendor_from_oui(oui_prefix):
    """Consulta fabricante por OUI (base local simplificada)"""
    # Esto se puede expandir con una API o archivo oui.txt
    vendors = {
        "0001C2": "Cisco Systems",
        "0050F2": "Microsoft",
        "8C1D96": "Intel",
        "EC1A59": "TP-Link",
        "4C3275": "D-Link",
        "F09FC2": "Arris Group",
        "00249B": "Belkin",
        "6881A4": "Samsung",
        "B827EB": "Raspberry Pi",
        "A4BF01": "Google",
    }
    return vendors.get(oui_prefix[:6], "Desconocido")

def display_results(devices):
    """Muestra resultados con estilo"""
    print("\n" + "="*60)
    print(" 🔍 Network Scanner Mx - Dispositivos en la red")
    print("="*60)
    print(f"{'IP':<18} {'MAC':<18} {'Fabricante':<20}")
    print("-"*60)
    for device in devices:
        print(f"{device['ip']:<18} {device['mac']:<18} {device['vendor']:<20}")
    print("="*60)
    print(f"✅ Total dispositivos encontrados: {len(devices)}")

def main():
    parser = argparse.ArgumentParser(description="Network Scanner Mx - Escáner de red local")
    parser.add_argument("-r", "--range", help="Rango de red (ej. 192.168.1.0/24)")
    args = parser.parse_args()
    
    if args.range:
        network_range = args.range
    else:
        network_range = get_network_range()
    
    print(f"\n🌐 Escaneando red: {network_range}")
    print("🕒 Espera unos segundos...\n")
    
    devices = scan(network_range)
    display_results(devices)

if __name__ == "__main__":
    main()
