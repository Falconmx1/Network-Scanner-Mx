# 📊 Network Scanner Mx - ULTIMATE EDITION

> Escáner de red profesional con TODO: GUI, monitoreo continuo, notificaciones, puertos personalizados y más.

![Version](https://img.shields.io/badge/version-3.0-ff69b4)
![Python](https://img.shields.io/badge/python-3.7+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20|%20Linux%20|%20macOS-lightgrey)

## 🚀 CARACTERÍSTICAS COMPLETAS

### ✅ Implementadas al 100%
- [x] **Interfaz gráfica profesional** (tkinter)
- [x] **Monitoreo continuo de red** en tiempo real
- [x] **Notificaciones de escritorio** (nuevos/dispositivos perdidos)
- [x] **Puertos personalizables** (elige qué escanear)
- [x] **Exportación JSON/CSV**
- [x] **Modo verbose** con detalles
- [x] **Colores en terminal**
- [x] **Detección automática de red**
- [x] **Base de datos OUI** (40+ fabricantes)

## 📦 Instalación

```bash
git clone https://github.com/Falconmx1/Network-Scanner-Mx.git
cd Network-Scanner-Mx
pip install -r requirements.txt

Instalación en Linux (requiere sudo para scapy)
sudo apt-get install python3-scapy python3-tk
pip install plyer requests

Instalación en Windows
pip install -r requirements.txt
# Si no funciona tkinter, reinstala Python con la opción "tcl/tk"

🎮 MODOS DE USO
1️⃣ MODO TERMINAL (línea de comandos)
# Escaneo básico
python scanner.py

# Escaneo con puertos personalizados
python scanner.py -p 22,80,443,8080,3306

# Modo verbose + exportación
python scanner.py -v -o both

# Monitoreo continuo (cada 30 seg)
python scanner.py -m

# Monitoreo con puertos e intervalo personalizado
python scanner.py -m -p 22,80 -i 15

# Rango manual + todo junto
python scanner.py -r 192.168.0.0/24 -p 22,80,443 -v -o json -m -i 10

2️⃣ MODO GRÁFICO (GUI)
python scanner.py -g
# O ejecuta sin argumentos y selecciona la opción

Características del GUI:

Configuración visual de rango y puertos

Botón para escaneo único o monitoreo

Área de resultados en tiempo real

Exportación con un click

Tema oscuro profesional

3️⃣ MODO MONITOREO (detección de cambios)
python scanner.py -m -i 30
