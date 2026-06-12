# 📊 Network Scanner Mx

> Escáner de red local profesional con colores, exportación JSON/CSV, escaneo de puertos y modo verbose.

![Version](https://img.shields.io/badge/version-2.0-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-MIT-red)

## 🚀 Características COMPLETAS

✅ **Detección automática** de red local  
✅ **Colores en terminal** para mejor visualización  
✅ **Modo verbose (-v)** con detalles completos  
✅ **Escaneo de puertos** (22,80,443,8080,3306,3389)  
✅ **Exportación a JSON y CSV**  
✅ **Base de datos OUI** extendida (más de 30 fabricantes)  
✅ **Banner chingón** al iniciar  
✅ **Soporte Windows/Linux/macOS**  

## 📦 Instalación

```bash
git clone https://github.com/Falconmx1/Network-Scanner-Mx.git
cd Network-Scanner-Mx
pip install -r requirements.txt

Requisitos especiales en Linux/macOS:

# Linux
sudo apt-get install python3-scapy

# macOS
brew install scapy

🔧 Uso (ejemplos prácticos)

# Escaneo básico (solo dispositivos)
python scanner.py

# Escaneo con puertos
python scanner.py -p

# Modo verbose + puertos
python scanner.py -p -v

# Exportar a JSON
python scanner.py -o json

# Exportar a ambos formatos
python scanner.py -p -o both

# Sin colores (para scripts)
python scanner.py --no-color

# Rango manual + todo activado
python scanner.py -r 192.168.0.0/24 -p -v -o both

📁 Estructura de exportación
JSON
{
  "scan_date": "2026-06-12T15:30:00",
  "total_devices": 4,
  "devices": [
    {
      "ip": "192.168.1.1",
      "mac": "8C:1D:96:12:34:56",
      "vendor": "Intel",
      "open_ports": [80, 443]
    }
  ]
}

CSV
IP	MAC	Fabricante	Puertos
192.168.1.1	8C:1D:96:12:34:56	Intel	80	443
