import nmap

print('''
o-''|\\_____/)
 \\_/|_)     )
    \\  __  /   SANDORCAN
    (_/ (_/
''')

def escanear_puertos(target_host):
    try:
        nm = nmap.PortScanner()
        nm.scan(target_host, arguments="-sS")  # Escaneo SYN-ACK
        return nm
    except nmap.nmap.PortScannerError:
        return None

def detectar_so(target_host):
    try:
        nm = nmap.PortScanner()
        nm.scan(target_host, arguments="-O")  # Escaneo de detección de SO
        os_info = nm[target_host]["osmatch"][0]["name"]
        return os_info
    except KeyError:
        return "No se pudo detectar el sistema operativo"

def main():
    while True:
        target_host = input("Introduce la dirección IP o la URL a escanear (o escribe 'salir' para finalizar): ")
        if target_host.lower() == 'salir':
            break

        # Realiza el escaneo de puertos
        resultados_puertos = escanear_puertos(target_host)
        if resultados_puertos:
            for host in resultados_puertos.all_hosts():
                print(f"Host: {host}")
                for port, info in resultados_puertos[host]["tcp"].items():
                    print(f"Port {port}: {info['state']} - {info['name']}")
        else:
            print("Error al escanear puertos. Verifica la dirección IP o la configuración de Nmap.")

        # Detecta el sistema operativo
        sistema_operativo = detectar_so(target_host)
        print(f"Sistema operativo detectado: {sistema_operativo}")

if __name__ == "__main__":
    main()