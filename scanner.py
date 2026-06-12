#!/usr/bin/env python3
# Network Scanner Mx - Escáner de red local ULTIMATE
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
import queue
import time
import os
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
from plyer import notification
from collections import defaultdict

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
monitoring_active = False
monitoring_devices = {}
previous_devices = set()

def print_verbose(message, level="INFO"):
    """Imprime mensajes solo si verbose está activado"""
    if verbose_mode:
        color = Colors.GREEN if level == "INFO" else Colors.YELLOW if level == "WARN" else Colors.RED
        print(f"{color}[{level}]{Colors.END} {message}")

def send_notification(title, message, level="info"):
    """Envía notificación de escritorio"""
    try:
        if sys.platform == "win32":
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast(title, message, duration=5)
        else:
            notification.notify(
                title=title,
                message=message,
                app_name="Network Scanner Mx",
                timeout=5
            )
        print_verbose(f"Notificación enviada: {title}")
    except Exception as e:
        print_verbose(f"Error en notificación: {e}", "WARN")

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
        else:
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
        "000666": "Zyxel", "001A70": "Tenda", "90F6BF": "Xiaomi",
        "001E2A": "LG Electronics", "58BD61": "Ubiquiti"
    }
    return vendors.get(oui_prefix[:6], "Desconocido")

def scan_ports(ip, ports):
    """Escanea puertos personalizados en un dispositivo"""
    open_ports = []
    print_verbose(f"Escaneando {len(ports)} puertos en {ip}...")
    
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

def scan_network(ip_range, ports_to_scan=None):
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
        
        if ports_to_scan:
            device['open_ports'] = scan_ports(ip, ports_to_scan)
        
        devices.append(device)
    
    return devices

def monitor_network(ip_range, ports_to_scan, interval=30):
    """Modo continuo - monitorea cambios en la red"""
    global monitoring_active, previous_devices, monitoring_devices
    
    monitoring_active = True
    print(f"\n{Colors.GREEN}{Colors.BOLD}🔍 INICIANDO MODO MONITOREO{Colors.END}")
    print(f"{Colors.CYAN}📡 Escaneando cada {interval} segundos. Presiona Ctrl+C para detener.{Colors.END}\n")
    
    send_notification("Network Scanner Mx", "Monitoreo de red iniciado")
    
    while monitoring_active:
        try:
            current_devices = scan_network(ip_range, ports_to_scan)
            current_set = {(d['ip'], d['mac']) for d in current_devices}
            
            # Detectar dispositivos nuevos
            new_devices = current_set - previous_devices
            # Detectar dispositivos perdidos
            lost_devices = previous_devices - current_set
            
            if new_devices:
                print(f"{Colors.RED}{Colors.BOLD}⚠️ NUEVOS DISPOSITIVOS DETECTADOS:{Colors.END}")
                for ip, mac in new_devices:
                    device = next((d for d in current_devices if d['ip'] == ip), None)
                    print(f"  ➕ {ip} - {mac} - {device['vendor'] if device else 'Desconocido'}")
                    send_notification("Nuevo dispositivo detectado", f"{ip} ({device['vendor'] if device else 'Desconocido'}) se ha conectado")
            
            if lost_devices:
                print(f"{Colors.YELLOW}{Colors.BOLD}📴 DISPOSITIVOS DESCONECTADOS:{Colors.END}")
                for ip, mac in lost_devices:
                    print(f"  ➖ {ip} - {mac}")
                    send_notification("Dispositivo desconectado", f"{ip} ya no está en la red")
            
            if not new_devices and not lost_devices:
                print(f"{Colors.GREEN}✅ No hubo cambios en la red ({datetime.now().strftime('%H:%M:%S')}){Colors.END}")
            
            previous_devices = current_set
            monitoring_devices = {d['ip']: d for d in current_devices}
            
            time.sleep(interval)
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}⏹️ Deteniendo monitoreo...{Colors.END}")
            monitoring_active = False
            send_notification("Network Scanner Mx", "Monitoreo de red detenido")
            break
        except Exception as e:
            print_verbose(f"Error en monitoreo: {e}", "ERROR")
            time.sleep(interval)

def display_results(devices):
    """Muestra resultados con estilo y colores"""
    print("\n" + Colors.CYAN + "="*80 + Colors.END)
    print(Colors.BOLD + Colors.GREEN + " 🔍 Network Scanner Mx - Dispositivos en la red" + Colors.END)
    print(Colors.CYAN + "="*80 + Colors.END)
    print(f"{Colors.YELLOW}{'IP':<18} {'MAC':<18} {'Fabricante':<22} {'Puertos abiertos'}{Colors.END}")
    print(Colors.CYAN + "-"*80 + Colors.END)
    
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
    
    print(Colors.CYAN + "="*80 + Colors.END)
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
{Colors.RED}╔══════════════════════════════════════════════════════════════════════════╗
{Colors.RED}║{Colors.YELLOW}      ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  {Colors.RED}║
{Colors.RED}║{Colors.YELLOW}      ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║  {Colors.RED}║
{Colors.RED}║{Colors.YELLOW}      ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝██║  {Colors.RED}║
{Colors.RED}║{Colors.YELLOW}      ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██║  {Colors.RED}║
{Colors.RED}║{Colors.YELLOW}      ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║███████╗{Colors.RED}║
{Colors.RED}║{Colors.YELLOW}      ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝{Colors.RED}║
{Colors.RED}║{Colors.CYAN}                        📡 Network Scanner Mx                          {Colors.RED}║
{Colors.RED}║{Colors.GREEN}                   🔐 Ethical Network Discovery Tool                    {Colors.RED}║
{Colors.RED}║{Colors.BLUE}                      👤 Falconmx1 | v3.0 ULTIMATE                      {Colors.RED}║
{Colors.RED}╚══════════════════════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner_text)

def gui_mode():
    """Interfaz gráfica simple con tkinter"""
    root = tk.Tk()
    root.title("Network Scanner Mx - Escáner de Red Professional")
    root.geometry("900x700")
    root.configure(bg='#1e1e1e')
    
    # Estilo
    style = ttk.Style()
    style.theme_use('clam')
    style.configure('TLabel', background='#1e1e1e', foreground='white', font=('Arial', 10))
    style.configure('TButton', background='#0e5a5a', foreground='white', font=('Arial', 10, 'bold'))
    style.configure('TFrame', background='#1e1e1e')
    style.configure('TLabelframe', background='#1e1e1e', foreground='white')
    style.configure('TLabelframe.Label', background='#1e1e1e', foreground='white')
    
    # Variables
    scan_result = []
    monitoring_thread = None
    is_monitoring = False
    
    def scan_network_gui():
        nonlocal scan_result
        try:
            ip_range = entry_range.get()
            if not ip_range:
                ip_range = get_network_range()
                entry_range.delete(0, tk.END)
                entry_range.insert(0, ip_range)
            
            ports_text = entry_ports.get()
            ports = [int(p.strip()) for p in ports_text.split(',')] if ports_text else [22, 80, 443, 8080, 3306, 3389]
            
            scan_ports_flag = var_ports.get()
            ports_to_scan = ports if scan_ports_flag else None
            
            text_output.delete(1.0, tk.END)
            text_output.insert(tk.END, f"🔄 Escaneando red: {ip_range}\n")
            text_output.insert(tk.END, "⏳ Por favor espera...\n\n")
            root.update()
            
            devices = scan_network(ip_range, ports_to_scan)
            scan_result = devices
            
            text_output.delete(1.0, tk.END)
            text_output.insert(tk.END, f"{'='*70}\n")
            text_output.insert(tk.END, f"🔍 NETWORK SCANNER MX - RESULTADOS\n")
            text_output.insert(tk.END, f"{'='*70}\n\n")
            
            for device in devices:
                ports_str = ", ".join(map(str, device['open_ports'])) if device['open_ports'] else "Ninguno"
                text_output.insert(tk.END, f"📡 IP: {device['ip']}\n")
                text_output.insert(tk.END, f"🔌 MAC: {device['mac']}\n")
                text_output.insert(tk.END, f"🏭 Fabricante: {device['vendor']}\n")
                text_output.insert(tk.END, f"🚪 Puertos abiertos: {ports_str}\n")
                text_output.insert(tk.END, f"{'-'*70}\n")
            
            text_output.insert(tk.END, f"\n✅ Total dispositivos: {len(devices)}\n")
            
            if var_export.get() and devices:
                if var_export_format.get() == "json":
                    export_json(devices)
                else:
                    export_csv(devices)
                text_output.insert(tk.END, f"📁 Datos exportados a {var_export_format.get()}\n")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error en el escaneo: {str(e)}")
    
    def start_monitoring():
        nonlocal monitoring_thread, is_monitoring
        if is_monitoring:
            messagebox.showwarning("Monitoreo activo", "Ya hay un monitoreo en curso")
            return
        
        try:
            ip_range = entry_range.get()
            if not ip_range:
                ip_range = get_network_range()
                entry_range.insert(0, ip_range)
            
            ports_text = entry_ports.get()
            ports = [int(p.strip()) for p in ports_text.split(',')] if ports_text else None
            
            interval = int(entry_interval.get()) if entry_interval.get() else 30
            
            is_monitoring = True
            monitoring_thread = threading.Thread(target=monitor_network, args=(ip_range, ports, interval), daemon=True)
            monitoring_thread.start()
            
            text_output.insert(tk.END, f"🟢 MONITOREO INICIADO - Intervalo: {interval} segundos\n")
            text_output.insert(tk.END, "🔴 Cierra la aplicación para detener el monitoreo\n\n")
            
            btn_monitor.config(text="📡 Monitoreando...", state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", f"Error iniciando monitoreo: {str(e)}")
    
    # Frame principal
    main_frame = ttk.Frame(root, padding="10")
    main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    
    # Configuración
    config_frame = ttk.LabelFrame(main_frame, text="⚙️ Configuración", padding="10")
    config_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
    
    ttk.Label(config_frame, text="Rango de red:").grid(row=0, column=0, sticky=tk.W)
    entry_range = ttk.Entry(config_frame, width=30)
    entry_range.grid(row=0, column=1, padx=5)
    
    ttk.Label(config_frame, text="Puertos (ej: 22,80,443):").grid(row=1, column=0, sticky=tk.W, pady=5)
    entry_ports = ttk.Entry(config_frame, width=30)
    entry_ports.grid(row=1, column=1, padx=5)
    entry_ports.insert(0, "22,80,443,8080,3306,3389")
    
    ttk.Label(config_frame, text="Intervalo monitoreo (seg):").grid(row=2, column=0, sticky=tk.W, pady=5)
    entry_interval = ttk.Entry(config_frame, width=30)
    entry_interval.grid(row=2, column=1, padx=5)
    entry_interval.insert(0, "30")
    
    # Opciones
    options_frame = ttk.LabelFrame(main_frame, text="🎯 Opciones", padding="10")
    options_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
    
    var_ports = tk.BooleanVar(value=True)
    chk_ports = ttk.Checkbutton(options_frame, text="Escaneo de puertos", variable=var_ports)
    chk_ports.grid(row=0, column=0, sticky=tk.W)
    
    var_export = tk.BooleanVar(value=False)
    chk_export = ttk.Checkbutton(options_frame, text="Exportar resultados", variable=var_export)
    chk_export.grid(row=1, column=0, sticky=tk.W)
    
    var_export_format = tk.StringVar(value="json")
    ttk.Radiobutton(options_frame, text="JSON", variable=var_export_format, value="json").grid(row=2, column=0, sticky=tk.W, padx=20)
    ttk.Radiobutton(options_frame, text="CSV", variable=var_export_format, value="csv").grid(row=2, column=1, sticky=tk.W, padx=20)
    
    # Botones
    buttons_frame = ttk.Frame(main_frame)
    buttons_frame.grid(row=2, column=0, columnspan=2, pady=10)
    
    btn_scan = ttk.Button(buttons_frame, text="🔍 ESCANEAR AHORA", command=scan_network_gui)
    btn_scan.grid(row=0, column=0, padx=5)
    
    btn_monitor = ttk.Button(buttons_frame, text="📡 INICIAR MONITOREO", command=start_monitoring)
    btn_monitor.grid(row=0, column=1, padx=5)
    
    # Área de resultados
    result_frame = ttk.LabelFrame(main_frame, text="📊 Resultados", padding="10")
    result_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
    
    text_output = scrolledtext.ScrolledText(result_frame, width=90, height=25, bg='#2d2d2d', fg='#00ff00', font=('Courier', 10))
    text_output.grid(row=0, column=0)
    
    # Footer
    footer_label = ttk.Label(main_frame, text="🇲🇽 Network Scanner Mx v3.0 - Falconmx1 | Uso ético solamente 🇲🇽", font=('Arial', 8))
    footer_label.grid(row=4, column=0, columnspan=2, pady=5)
    
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    main_frame.columnconfigure(0, weight=1)
    main_frame.rowconfigure(3, weight=1)
    result_frame.columnconfigure(0, weight=1)
    result_frame.rowconfigure(0, weight=1)
    
    root.mainloop()

def main():
    global verbose_mode
    
    parser = argparse.ArgumentParser(
        description="Network Scanner Mx - Escáner profesional de red local ULTIMATE",
        epilog="Ejemplo: python scanner.py -r 192.168.1.0/24 -p 22,80,443 -v -o json"
    )
    parser.add_argument("-r", "--range", help="Rango de red (ej. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", help="Puertos a escanear (ej: 22,80,443)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose")
    parser.add_argument("-o", "--output", choices=['json', 'csv', 'both'], help="Exportar resultados")
    parser.add_argument("-m", "--monitor", action="store_true", help="Modo monitoreo continuo")
    parser.add_argument("-i", "--interval", type=int, default=30, help="Intervalo de monitoreo en segundos")
    parser.add_argument("-g", "--gui", action="store_true", help="Abrir interfaz gráfica")
    parser.add_argument("--no-color", action="store_true", help="Desactiva colores")
    
    args = parser.parse_args()
    
    if args.gui:
        gui_mode()
        return
    
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith("__"):
                setattr(Colors, attr, "")
    
    if args.verbose:
        verbose_mode = True
    
    banner()
    
    if args.range:
        network_range = args.range
        print_verbose(f"Rango especificado: {network_range}")
    else:
        network_range = get_network_range()
    
    ports_to_scan = None
    if args.ports:
        ports_to_scan = [int(p.strip()) for p in args.ports.split(',')]
        print_verbose(f"Puertos a escanear: {ports_to_scan}")
    
    if args.monitor:
        monitor_network(network_range, ports_to_scan, args.interval)
        return
    
    print(f"\n{Colors.CYAN}🌐 Escaneando red: {Colors.BOLD}{network_range}{Colors.END}")
    print(f"{Colors.YELLOW}🕒 Por favor espera...{Colors.END}\n")
    
    devices = scan_network(network_range, ports_to_scan)
    
    if not devices:
        print(f"{Colors.RED}❌ No se encontraron dispositivos.{Colors.END}")
        return
    
    display_results(devices)
    
    if args.output:
        print(f"{Colors.CYAN}📁 Exportando resultados...{Colors.END}")
        if args.output in ['json', 'both']:
            export_json(devices)
        if args.output in ['csv', 'both']:
            export_csv(devices)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️ Programa interrumpido por el usuario.{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}❌ Error inesperado: {e}{Colors.END}")
        sys.exit(1)
