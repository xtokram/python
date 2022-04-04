#! /usr/bin/python3



###################################
#Programa desenvolvido por Tokram # 
#Instagram @tokram                #
#github xtokram                   #
#contato - xtokram@gmail.com      #
###################################

#CÓDIGO CRIADO APENAS PARA APRIMORAR MEUS CONHECIMENTOS SOBRE PACOTES ETHERNET / ARP
#USO APENAS ACADÊMICO
#NÃO ME RESPONSABILIZO POR MAL USO OU USO ILEGAL DO MESMO.

import socket

def strEthernet(ethernet: bytes):			
    ethernet = ethernet.hex().upper()
    strEthernet = ""
    for i in range(0, 10, 2):
        strEthernet += f"{ethernet[i:(i+2)]}:"
    strEthernet += ethernet[10:]
    return strEthernet

def parseEthernet(headers: bytes):
    etherDestino = headers[:6]
    etherFonte = headers[6:12]
    etherTipo = headers[12:]
    print("###[ ETHERNET ] ###")
    print(f"    Fonte:\t{strEthernet(etherFonte)}")
    print(f" Destino:\t {strEthernet(etherDestino)}")
    return etherTipo == b"\x08\x00"

def parseIP(headers: bytes):
    tipo = headers[9:10]
    ipFonte = headers[12:16]
    ipDestino = headers[16:20]
    print("###[ IP ] ###")
    print(f"    Fonte:\t {socket.inet_ntoa(ipFonte)}")
    print(f"    Destino:\t {socket.inet_ntoa(ipDestino)}")
    if tipo == b"\x06":
        return 'TCP'
    if tipo == b"\x11":
        return 'UDP'
    return ''

def parseTCP(headers: bytes):
    portaFonte = int.from_bytes(headers[:2], byteorder="big")
    portaDestino = int.from_bytes(headers[2:4], byteorder="big")
    print("###[TCP]###")
    print(f"    Porta fonte:\t{portaFonte}")
    print(f"    Porta destino:\t{portaDestino}")
    return portaFonte == 80

def parseUDP(headers: bytes):
    portaFonte = headers[:2]
    portaDestino = headers[2:4]
    print("### UDP ####")
    print(f"    Porta fonte:\t {int.from_bytes(portaFonte, byteorder='big')}")
    print(f"    Porta destino:\t {int.from_bytes(portaDestino, byteorder='big')}")

rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x800))
while True:
    rawPkt = rawSocket.recvfrom(2048)[0]
    print("\n\n\tPacote recebido: \n")
    if parseEthernet(rawPkt[:14]):	#Verificando o inicio do cabeçalho verificando o protrocolo Ethernet
        tipoPkt = parseIP(rawPkt[14:34]) 		#Apos isto, verificando o protocolo de cada pacote recebido
        if tipoPkt:
            if tipoPkt == 'UDP': 
                parseUDP(rawPkt[34:42])
            if tipoPkt == 'TCP':
                if parseTCP(rawPkt[34:54]):
                    print(rawPkt[54:])
