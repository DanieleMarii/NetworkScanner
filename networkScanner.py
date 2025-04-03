import nmap

def scan_network(network):
    scanner = nmap.PortScanner()
    print(f"Escaneando a rede {network}...")
 
    # Realiza o escaneamento na rede inteira
    scanner.scan(hosts=network, arguments="-O")  
 
    devices = []
 
    for host in scanner.all_hosts():
        device = {
            "IP": host,
            "Hostname": scanner[host].hostname(),
            "Sistema Operacional": "Desconhecido"
        }
 
        # Verifica se há informações sobre o sistema operacional
        if "osmatch" in scanner[host] and scanner[host]["osmatch"]:
            device["Sistema Operacional"] = scanner[host]["osmatch"][0]["name"]
 
        devices.append(device)
 
    return devices
 
if __name__ == "__main__":
rede = "192.168.1.0/24"  # Ajuste para a faixa de IP da sua rede
    resultados = scan_network(rede)
 
    print("\nDispositivos ativos na rede:")
    for dispositivo in resultados:
        print(f"IP: {dispositivo['IP']} | Hostname: {dispositivo['Hostname']} | SO: {dispositivo['Sistema Operacional']}")
