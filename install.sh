#!/usr/bin/env bash
# install.sh - Instalador de ReconX para Kali Linux
set -e

echo "[*] Actualizando repositorios..."
sudo apt update

echo "[*] Instalando dependencias del sistema (whois, dnsutils, nmap, go)..."
sudo apt install -y python3 python3-pip whois dnsutils nmap golang-go

echo "[*] Instalando dependencias de Python..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt

echo "[*] Instalando subfinder y httpx (ProjectDiscovery, opcional pero recomendado)..."
if command -v go >/dev/null 2>&1; then
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true
    GOBIN_PATH="$(go env GOPATH)/bin"
    if ! grep -q "$GOBIN_PATH" ~/.bashrc 2>/dev/null; then
        echo "export PATH=\$PATH:$GOBIN_PATH" >> ~/.bashrc
    fi
    export PATH=$PATH:$GOBIN_PATH
    echo "[i] Recuerda abrir una terminal nueva (o 'source ~/.bashrc') para que subfinder/httpx queden en el PATH."
else
    echo "[!] Go no disponible, se omite subfinder/httpx (la herramienta sigue funcionando sin ellos)"
fi

chmod +x reconx.py

echo ""
echo "[✓] Instalación completa."
echo "    Prueba con: python3 reconx.py -d example.com --all"
echo ""
echo "    Opcional - claves de API para módulos extra:"
echo "      export SHODAN_API_KEY=tu_clave"
echo "      export VT_API_KEY=tu_clave"
