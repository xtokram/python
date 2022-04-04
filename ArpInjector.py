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
def formatMac(mac: str):
    return bytes.fromhex(mac.replace(':', ''))

def formatIP(ip: str):
    return socket.inet_aton(ip)

def makePkt():
    macSrc = formatMac("08:0e:ac:2f:aa:ab") ## ALTERE AQUI - Para mudar MAC FONTE do pacote ARP 
    macDst = formatMac("ff:ff:ff:ff:ff:ff") ## ALTERE AQUI - Para mudar MAC DESTINO do pacote ARP
    etherType = b'\x08\x06'        #Definindo EtherType para ARP (https://en.wikipedia.org/wiki/EtherType)
    arp_hType = b'\x00\x01' 	    #Definindo Tipo de ARP para Placa de Rede (Hardware)
    arp_pType = b'\x08\x00' 
    arp_hAddrLen = b'\x06' 		
    arp_pAddrLen = b'\x04'
    arp_op = b'\x00\x01'
    arp_ipSrc = formatIP("0.0.0.0.0") 
    arp_macDst = formatMac("00:00:00:00:00:00")
    arp_ipDst = formatIP("192.168.0.104")
    etherHeader = macDst+macSrc+etherType
    arpHeader = bytearray(                 #Criando Cabeçalho ARP
        arp_hType+arp_pType+\
        arp_hAddrLen+arp_pAddrLen+\
        arp_op+\
        macSrc+\
        arp_ipSrc+\
        arp_macDst+\
        arp_ipDst
    )
    arpHeader += b'\x00'*(46-len(arpHeader))
    return etherHeader+arpHeader

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x800))
sock.bind(("wlp2s0", socket.htons(0x800)))
sock.send(makePkt())
sock.close()
