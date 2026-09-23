# ReconX

Herramienta local en Python para analizar **dominios o IPs**, agregando en una sola CLI
varias herramientas open source ya existentes:

| Módulo        | Herramienta que usa                          |
|---------------|-----------------------------------------------|
| `--whois`     | `whois` (paquete del sistema)                  |
| `--dns`       | `dnspython` o `dig`                            |
| `--geo`       | API pública `ip-api.com` (sin clave)           |
| `--ports`     | `nmap`                                         |
| `--subdomains`| `subfinder` (ProjectDiscovery)                 |
| `--http`      | `httpx` (ProjectDiscovery) o `requests`        |
| `--ssl`       | módulo `ssl` de Python (certificado del sitio) |
| `--shodan`    | API de Shodan (necesita `SHODAN_API_KEY`)      |
| `--virustotal`| API de VirusTotal (necesita `VT_API_KEY`)      |

Si alguna herramienta externa no está instalada, ese módulo simplemente avisa y
el resto sigue funcionando.

## Sintaxis rápida

```bash
# Un solo dominio, todos los módulos
python3 reconx.py -d example.com --all

# Una sola IP, módulos específicos
python3 reconx.py -i 8.8.8.8 --whois --dns --geo

# Lote de objetivos desde un .txt (uno por línea)
python3 reconx.py -f objetivos_ejemplo.txt --all

# Controlar concurrencia y cantidad de puertos escaneados
python3 reconx.py -f objetivos_ejemplo.txt --all --hilos 5 --top-ports 200
```

Cada objetivo genera un reporte JSON en `./reports/`.

Claves de API opcionales (Shodan / VirusTotal):

```bash
export SHODAN_API_KEY="tu_clave"
export VT_API_KEY="tu_clave"
```

---

## 1. Subir el proyecto a tu GitHub (desde donde estés ahora)

```bash
cd reconx
git init
git add .
git commit -m "ReconX: herramienta de recon para dominios e IPs"
git branch -M main
git remote add origin https://github.com/TU_USUARIO/reconx.git
git push -u origin main
```

(Crea antes el repositorio vacío en GitHub: botón **New repository**, nómbralo
`reconx`, sin README ni licencia para evitar conflictos con este `push`.)

## 2. Instalar y ejecutar en tu Kali

```bash
git clone https://github.com/TU_USUARIO/reconx.git
cd reconx
chmod +x install.sh
./install.sh
```

El instalador:
- instala `whois`, `dnsutils`, `nmap`, `golang-go` vía `apt`
- instala `requests` y `dnspython` vía `pip3`
- instala `subfinder` y `httpx` vía `go install` (opcional, mejora los módulos
  `--subdomains` y `--http`)

## 3. Actualizar más adelante

Cuando cambies algo del script en tu PC de trabajo:

```bash
git add .
git commit -m "Ajustes"
git push
```

Y en Kali, para traer los cambios:

```bash
cd reconx
git pull
```

## Uso responsable

Esta herramienta hace principalmente reconocimiento pasivo (WHOIS, DNS,
geolocalización, certificados) y un escaneo de puertos con `nmap`. Solo
analiza dominios/IPs sobre los que tengas autorización explícita.
