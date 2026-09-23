#!/usr/bin/env python3
"""
ReconX - Herramienta local de reconocimiento de dominios e IPs
Agrega herramientas open source existentes (whois, dig/DNS, nmap, subfinder,
httpx, shodan, virustotal, ip-api) en una sola CLI simple.

Uso:
    python3 reconx.py -d example.com --all
    python3 reconx.py -i 8.8.8.8 --whois --dns --geo
    python3 reconx.py -f objetivos.txt --all --hilos 5
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import shutil
import socket
import ssl
import subprocess
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

try:
    import dns.resolver
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False


# ---------- Colores de terminal ----------
class C:
    OK = "\033[92m"
    WARN = "\033[93m"
    ERR = "\033[91m"
    INFO = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def banner():
    print(f"""{C.INFO}{C.BOLD}
 ____                       __  __
|  _ \\ ___  ___ ___  _ __   \\ \\/ /
| |_) / _ \\/ __/ _ \\| '_ \\   \\  /
|  _ <  __/ (_| (_) | | | |  /  \\
|_| \\_\\___|\\___\\___/|_| |_| /_/\\_\\
{C.END}{C.INFO}   Recon aggregator - dominios / IPs{C.END}
""")


def is_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def which(tool):
    return shutil.which(tool) is not None


def run_cmd(cmd, timeout=60):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip() or result.stderr.strip()
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return "[!] Timeout ejecutando: " + " ".join(cmd)
    except Exception as e:
        return f"[!] Error: {e}"


# ---------- Módulos ----------

def mod_whois(target):
    print(f"{C.INFO}[*] WHOIS...{C.END}")
    if which("whois"):
        return run_cmd(["whois", target], timeout=30)
    return "[!] Comando 'whois' no instalado (apt install whois)"


def mod_dns(target):
    print(f"{C.INFO}[*] Registros DNS...{C.END}")
    records = {}
    if is_ip(target):
        try:
            host = socket.gethostbyaddr(target)
            records["PTR"] = host[0]
        except Exception:
            records["PTR"] = "No encontrado"
        return records

    tipos = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    if HAVE_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        for tipo in tipos:
            try:
                answers = resolver.resolve(target, tipo, lifetime=5)
                records[tipo] = [str(r) for r in answers]
            except Exception:
                records[tipo] = []
    elif which("dig"):
        for tipo in tipos:
            out = run_cmd(["dig", "+short", target, tipo], timeout=10)
            records[tipo] = out.splitlines() if out else []
    else:
        try:
            records["A"] = [socket.gethostbyname(target)]
        except Exception:
            records["A"] = []
    return records


def mod_geo(target):
    print(f"{C.INFO}[*] Geolocalización...{C.END}")
    ip = target
    if not is_ip(target):
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            return {"error": "No se pudo resolver el dominio"}
    if requests is None:
        return {"error": "requests no instalado"}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=8)
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def mod_ports(target, top_ports=100):
    print(f"{C.INFO}[*] Escaneo de puertos (nmap)...{C.END}")
    if not which("nmap"):
        return "[!] nmap no instalado (apt install nmap)"
    return run_cmd(["nmap", "-Pn", "--top-ports", str(top_ports), "-T4", target], timeout=180)


def mod_subdomains(target):
    print(f"{C.INFO}[*] Subdominios (subfinder)...{C.END}")
    if is_ip(target):
        return "[!] No aplica a IPs"
    if which("subfinder"):
        out = run_cmd(["subfinder", "-d", target, "-silent"], timeout=120)
        return out.splitlines() if out else []
    return "[!] subfinder no instalado (ver install.sh)"


def mod_http(target):
    print(f"{C.INFO}[*] Sondeo HTTP/HTTPS...{C.END}")
    resultados = {}
    if which("httpx"):
        out = run_cmd(
            ["bash", "-c", f"echo {target} | httpx -silent -status-code -title -tech-detect"],
            timeout=60,
        )
        resultados["httpx"] = out
        return resultados
    if requests is None:
        return "[!] requests no instalado"
    for esquema in ["https", "http"]:
        url = f"{esquema}://{target}"
        try:
            r = requests.get(url, timeout=6, allow_redirects=True)
            resultados[esquema] = {
                "status": r.status_code,
                "servidor": r.headers.get("Server", "N/D"),
                "url_final": r.url,
            }
        except Exception as e:
            resultados[esquema] = {"error": str(e)}
    return resultados


def mod_ssl_cert(target):
    print(f"{C.INFO}[*] Certificado SSL...{C.END}")
    host = target
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "emisor": dict(x[0] for x in cert.get("issuer", [])),
                    "sujeto": dict(x[0] for x in cert.get("subject", [])),
                    "valido_desde": cert.get("notBefore"),
                    "valido_hasta": cert.get("notAfter"),
                    "alt_names": cert.get("subjectAltName"),
                }
    except Exception as e:
        return {"error": str(e)}


def mod_shodan(target):
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return "[!] SHODAN_API_KEY no configurada (export SHODAN_API_KEY=...)"
    if requests is None:
        return "[!] requests no instalado"
    ip = target
    if not is_ip(target):
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            return {"error": "No se pudo resolver el dominio"}
    print(f"{C.INFO}[*] Shodan...{C.END}")
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=15)
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}", "detalle": r.text}
    except Exception as e:
        return {"error": str(e)}


def mod_virustotal(target):
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return "[!] VT_API_KEY no configurada (export VT_API_KEY=...)"
    if requests is None:
        return "[!] requests no instalado"
    print(f"{C.INFO}[*] VirusTotal...{C.END}")
    endpoint = "ip_addresses" if is_ip(target) else "domains"
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/{endpoint}/{target}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


MODULOS = {
    "whois": mod_whois,
    "dns": mod_dns,
    "geo": mod_geo,
    "ports": mod_ports,
    "subdomains": mod_subdomains,
    "http": mod_http,
    "ssl": mod_ssl_cert,
    "shodan": mod_shodan,
    "virustotal": mod_virustotal,
}


def analizar_target(target, modulos_activos, top_ports=100):
    print(f"\n{C.BOLD}{C.OK}=== Analizando: {target} ==={C.END}")
    resultado = {
        "target": target,
        "tipo": "ip" if is_ip(target) else "dominio",
        "timestamp": datetime.now().isoformat(),
    }
    for nombre in modulos_activos:
        fn = MODULOS[nombre]
        try:
            resultado[nombre] = fn(target, top_ports=top_ports) if nombre == "ports" else fn(target)
        except Exception as e:
            resultado[nombre] = {"error": str(e)}
    return resultado


def guardar_reporte(resultado, carpeta="reports"):
    os.makedirs(carpeta, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre = f"{resultado['target'].replace('/', '_')}_{ts}"
    ruta_json = os.path.join(carpeta, nombre + ".json")
    with open(ruta_json, "w", encoding="utf-8") as f:
        json.dump(resultado, f, indent=2, ensure_ascii=False, default=str)
    print(f"{C.OK}[+] Reporte guardado: {ruta_json}{C.END}")
    return ruta_json


def leer_targets_archivo(ruta):
    with open(ruta, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]


def main():
    parser = argparse.ArgumentParser(
        description="ReconX - herramienta de reconocimiento de dominios/IPs (agrega herramientas open source)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Ejemplos:
  python3 reconx.py -d example.com --all
  python3 reconx.py -i 8.8.8.8 --whois --dns --geo
  python3 reconx.py -f objetivos.txt --all --hilos 5
""",
    )
    grupo_target = parser.add_mutually_exclusive_group(required=True)
    grupo_target.add_argument("-d", "--domain", help="Dominio a analizar")
    grupo_target.add_argument("-i", "--ip", help="IP a analizar")
    grupo_target.add_argument("-f", "--file", help="Archivo .txt con dominios/IPs (uno por línea)")

    parser.add_argument("--all", action="store_true", help="Ejecutar todos los módulos")
    parser.add_argument("--whois", action="store_true")
    parser.add_argument("--dns", action="store_true")
    parser.add_argument("--geo", action="store_true")
    parser.add_argument("--ports", action="store_true")
    parser.add_argument("--subdomains", action="store_true")
    parser.add_argument("--http", action="store_true")
    parser.add_argument("--ssl", action="store_true")
    parser.add_argument("--shodan", action="store_true")
    parser.add_argument("--virustotal", action="store_true")
    parser.add_argument("--top-ports", type=int, default=100, help="Cantidad de puertos top a escanear (default 100)")
    parser.add_argument("--hilos", type=int, default=3, help="Targets en paralelo al usar -f (default 3)")
    parser.add_argument("--salida", default="reports", help="Carpeta de salida de reportes (default ./reports)")

    args = parser.parse_args()
    banner()

    if args.all:
        modulos_activos = list(MODULOS.keys())
    else:
        modulos_activos = [m for m in MODULOS if getattr(args, m)]
        if not modulos_activos:
            modulos_activos = ["whois", "dns", "geo", "http", "ssl"]
            print(f"{C.WARN}[!] No se especificaron módulos, usando set básico: {modulos_activos}{C.END}")

    if args.domain:
        targets = [args.domain]
    elif args.ip:
        targets = [args.ip]
    else:
        targets = leer_targets_archivo(args.file)
        print(f"{C.INFO}[*] {len(targets)} objetivos cargados desde {args.file}{C.END}")

    if len(targets) == 1:
        resultado = analizar_target(targets[0], modulos_activos, args.top_ports)
        guardar_reporte(resultado, args.salida)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.hilos) as executor:
            futuros = {
                executor.submit(analizar_target, t, modulos_activos, args.top_ports): t
                for t in targets
            }
            for fut in concurrent.futures.as_completed(futuros):
                resultado = fut.result()
                guardar_reporte(resultado, args.salida)

    print(f"\n{C.OK}{C.BOLD}[✓] Análisis completado.{C.END}")


if __name__ == "__main__":
    main()
