from iputils import *
from ipaddress import ip_address as endereco_ip, ip_network as rede_ip
from socket import IPPROTO_ICMP as PROTO_ICMP, IPPROTO_TCP as PROTO_TCP
import struct


class CamadaRede:
    def __init__(self, meio):
        self.receptor = None
        self.meio = meio
        self.meio.registrar_recebedor(self.__tratar_entrada_bruta)
        self.ignore_checksum = self.meio.ignore_checksum
        self.endereco_local = None

    def __tratar_entrada_bruta(self, pacote):
        dscp, ecn, identificador, flags, deslocamento, tempo_vida, protocolo, origem, destino, carga = read_ipv4_header(pacote)

        if destino == self.endereco_local:
            if protocolo == PROTO_TCP and self.receptor:
                self.receptor(origem, destino, carga)
        else:
            proximo_salto = self._descobrir_proximo_salto(destino)
            tempo_vida -= 1

            if tempo_vida:
                novo_cabecalho = struct.pack('!BBHHHBBH', 0x45, 0, 20+len(carga), identificador, flags+deslocamento, tempo_vida, protocolo, 0)
                novo_cabecalho += str2addr(origem)
                novo_cabecalho += str2addr(destino)
                novo_checksum = calc_checksum(novo_cabecalho)
                pacote = struct.pack('!BBHHHBBH', 0x45, 0, 20+len(carga), identificador, flags+deslocamento, tempo_vida, protocolo, novo_checksum)
                pacote += str2addr(origem)
                pacote += str2addr(destino)
                pacote += carga
            else:
                protocolo = PROTO_ICMP
                dados_icmp = struct.pack('!BBHI', 0x0b, 0, 0, 0) + pacote[:28]
                chks_icmp = calc_checksum(dados_icmp)
                mensagem_icmp = struct.pack('!BBHI', 0x0b, 0, chks_icmp, 0) + pacote[:28]

                cabecalho_icmp = struct.pack('!BBHHHBBH', 0x45, 0, 20+len(mensagem_icmp), identificador, flags+deslocamento, 64, protocolo, 0)
                cabecalho_icmp += str2addr(self.endereco_local)
                cabecalho_icmp += str2addr(origem)
                chks_final = calc_checksum(cabecalho_icmp)
                pacote = struct.pack('!BBHHHBBH', 0x45, 0, 20+len(mensagem_icmp), identificador, flags+deslocamento, 64, protocolo, chks_final)
                pacote += str2addr(self.endereco_local)
                pacote += str2addr(origem)
                pacote += mensagem_icmp

                proximo_salto = self._descobrir_proximo_salto(self.endereco_local)

            self.meio.enviar(pacote, proximo_salto)

    def _descobrir_proximo_salto(self, destino):
        prox = None
        maior_match = 0
        ip_destino = endereco_ip(destino)
        for rede, salto in self.rotas:
            rede_convertida = rede_ip(rede)
            prefixo = int(rede.split('/')[1])
            if ip_destino in rede_convertida and prefixo >= maior_match:
                prox = salto
                maior_match = prefixo
        return prox

    def definir_endereco_host(self, meu_ip):
        self.endereco_local = meu_ip

    def definir_tabela_encaminhamento(self, tabela):
        self.rotas = tabela

    def registrar_recebedor(self, callback):
        self.receptor = callback

    def enviar(self, segmento, destino):
        salto = self._descobrir_proximo_salto(destino)
        vihl = 0x45
        tipo = 0
        tamanho_total = 20 + len(segmento)
        identificacao = 0
        flags_frag = 0
        ttl = 64
        protocolo = 6
        verificador = 0

        cabecalho_temp = struct.pack('!BBHHHBBH', vihl, tipo, tamanho_total, identificacao, flags_frag, ttl, protocolo, verificador)
        cabecalho_temp += str2addr(self.endereco_local)
        cabecalho_temp += str2addr(destino)
        verificador = calc_checksum(cabecalho_temp)

        pacote_final = struct.pack('!BBHHHBBH', vihl, tipo, tamanho_total, identificacao, flags_frag, ttl, protocolo, verificador)
        pacote_final += str2addr(self.endereco_local)
        pacote_final += str2addr(destino)
        pacote_final += segmento

        self.meio.enviar(pacote_final, salto)
