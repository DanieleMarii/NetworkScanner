import nmap
import csv
from datetime import datetime

def get_ip_range():
    """Solicita o range de IP ao usuário com validação básica"""
    while True:
        ip_range = input("Digite o range de IP para scan (ex: 192.168.1.0/24): ").strip()
        
        # Validação simples
        if '/' in ip_range and ip_range.count('.') == 3:
            return ip_range
        print("Formato inválido! Use como exemplo: 192.168.1.0/24\n")

def scan_network(network):
    scanner = nmap.PortScanner()
    print(f"\n🔍 Iniciando scan em {network}...")
    
    try:
        scanner.scan(hosts=network, arguments="-O -T4 --osscan-limit")
    except nmap.PortScannerError as e:
        print(f"Erro no scan: {e}")
        return []

    devices = []
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    for host in scanner.all_hosts():
        # Detecção robusta de OS
        os_info = "Desconhecido"
        if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
            os_match = scanner[host]['osmatch'][0]
            os_info = os_match['name']
            if 'osclass' in os_match and os_match['osclass']:
                os_info += f" ({os_match['osclass'][0]['osgen']})"
        
        devices.append({
            'IP': host,
            'Hostname': scanner[host].hostname() or 'N/A',
            'Ultima_Atividade': scan_time,
            'Sistema_Operacional': os_info,
            'Status': scanner[host].state()
        })
    
    return devices

def save_to_csv(data):
    if not data:
        print("Nenhum dispositivo encontrado!")
        return
    
    filename = f"scan_rede_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
    
    print(f"\n✅ Relatório salvo como '{filename}'")

if __name__ == "__main__":
    print("""\n
    ███████╗ ██████╗ █████╗ ███╗   ██╗███████╗
    ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝
    ███████╗██║     ███████║██╔██╗ ██║███████╗
    ╚════██║██║     ██╔══██║██║╚██╗██║╚════██║
    ███████║╚██████╗██║  ██║██║ ╚████║███████║
    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝
    """)
    
    # Solicita o range de IP
    ip_range = get_ip_range()
    
    # Executa com privilégios
    print("\n🛠️  A detecção de OS requer permissões elevadas (sudo)")
    hosts = scan_network(ip_range)
    
    # Resultados
    if hosts:
        save_to_csv(hosts)
        print("\n🔹 Resumo dos dispositivos:")
        for host in hosts[:3]:  # Mostra 3 exemplos
            print(f"• {host['IP']:15} | {host['Sistema_Operacional']:20} | {host['Hostname']}")
    else:
        print("\n❌ Nenhum host ativo encontrado ou erro no scan!")
