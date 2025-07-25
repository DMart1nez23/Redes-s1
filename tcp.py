import asyncio
from collections import deque
from math import ceil
import random
import time
from tcputils import *

class NucleoServidor:
    def __init__(self, enlace, porta_escuta):
        self.enlace = enlace
        self.porta_escuta = porta_escuta
        self.estados = {}
        self.gatilho_conexao = None
        self.enlace.registrar_recebedor(self._ouvir_segmento)

    def registrar_monitor(self, funcao):
        self.gatilho_conexao = funcao

    def _ouvir_segmento(self, origem, destino, pacote):
        src_porta, dst_porta, seq, ack, flags, janela, chksum, urg = read_header(pacote)

        if dst_porta != self.porta_escuta:
            return

        if not self.enlace.ignore_checksum and calc_checksum(pacote, origem, destino) != 0:
            print('Segmento inválido: checksum incorreto')
            return

        dados = pacote[4 * (flags >> 12):]
        chave_conexao = (origem, src_porta, destino, dst_porta)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.estados[chave_conexao] = NodoConexao(self, chave_conexao, seq, ack)
            novo_seq = random.randint(0, 0xffff)
            ack_para_envio = seq + 1
            cabecalho = make_header(dst_porta, src_porta, novo_seq, ack_para_envio, FLAGS_SYN | FLAGS_ACK)
            resposta = fix_checksum(cabecalho, destino, origem)
            self.enlace.enviar(resposta, origem)

            if self.gatilho_conexao:
                self.gatilho_conexao(conexao)
        elif chave_conexao in self.estados:
            self.estados[chave_conexao].processar_segmento(seq, ack, flags, dados)
        else:
            print(f'{origem}:{src_porta} -> {destino}:{dst_porta} (segmento sem conexão reconhecida)')


class NodoConexao:
    def __init__(self, nucleo, chave, seq, ack):
        self.nucleo = nucleo
        self.chave = chave
        self.ouvinte = None
        self.seq_atual = random.randint(0, 0xffff)
        self.seq_esperado = seq + 1
        self.ack_retorno = ack
        self.enviados = deque()
        self.pendentes = deque()
        self.ocupacao = 0
        self.limite_janela = MSS
        self.rtt_inicial = 1
        self.rtt_estimado = self.rtt_inicial
        self.rtt_variacao = self.rtt_inicial / 2
        self.tempo_limite = 1
        self.cronometro = None
        self.primeiro_rtt = False

    def _reenvio(self):
        self.cronometro = None
        self.limite_janela /= 2

        if self.enviados:
            _, segmento, destino, tamanho = self.enviados.popleft()
            self.enviados.appendleft((0, segmento, destino, tamanho))
            self.nucleo.enlace.enviar(segmento, destino)
            self.cronometro = asyncio.get_event_loop().call_later(self.tempo_limite, self._reenvio)

    def processar_segmento(self, seq, ack, flags, conteudo):
        if flags & FLAGS_FIN:
            if self.ouvinte:
                self.ouvinte(self, b'')
            self.ack_retorno = ack
            src_ip, src_p, dst_ip, dst_p = self.chave
            header = make_header(dst_p, src_p, self.seq_atual, self.seq_esperado + 1, flags)
            resposta = fix_checksum(header, dst_ip, src_ip)
            self.nucleo.enlace.enviar(resposta, src_ip)
        elif seq == self.seq_esperado:
            self.seq_esperado += len(conteudo) if conteudo else 0
            if self.ouvinte:
                self.ouvinte(self, conteudo)
            self.ack_retorno = ack

            if flags & FLAGS_ACK:
                if conteudo:
                    src_ip, src_p, dst_ip, dst_p = self.chave
                    header = make_header(dst_p, src_p, self.seq_atual, self.seq_esperado, flags)
                    resposta = fix_checksum(header, dst_ip, src_ip)
                    self.nucleo.enlace.enviar(resposta, src_ip)

                houve_envio = self.ocupacao > 0
                if self.cronometro:
                    self.cronometro.cancel()
                    self.cronometro = None
                while self.enviados:
                    tempo, segmento, _, tamanho = self.enviados.popleft()
                    self.ocupacao -= tamanho
                    if read_header(segmento)[2] == ack:
                        break

                if tempo:
                    tempo_decorrido = time.time() - tempo
                    if not self.primeiro_rtt:
                        self.rtt_estimado = tempo_decorrido
                        self.rtt_variacao = tempo_decorrido / 2
                        self.primeiro_rtt = True
                    else:
                        self.rtt_estimado = 0.875 * self.rtt_estimado + 0.125 * tempo_decorrido
                        self.rtt_variacao = 0.75 * self.rtt_variacao + 0.25 * abs(tempo_decorrido - self.rtt_estimado)
                    self.tempo_limite = self.rtt_estimado + 4 * self.rtt_variacao

                sem_ocupacao = self.ocupacao == 0
                if houve_envio and sem_ocupacao:
                    self.limite_janela += MSS

                while self.pendentes:
                    segmento, ip, tamanho = self.pendentes.popleft()
                    if self.ocupacao + tamanho > self.limite_janela:
                        self.pendentes.appendleft((segmento, ip, tamanho))
                        break
                    self.ocupacao += tamanho
                    self.nucleo.enlace.enviar(segmento, ip)
                    self.enviados.append((time.time(), segmento, ip, tamanho))

                if self.enviados:
                    self.cronometro = asyncio.get_event_loop().call_later(self.tempo_limite, self._reenvio)

    def registrar_recebedor(self, funcao):
        self.ouvinte = funcao

    def enviar(self, dados):
        src_ip, src_p, dst_ip, dst_p = self.chave
        partes = ceil(len(dados) / MSS)
        for i in range(partes):
            self.seq_atual = self.ack_retorno
            segmento = make_header(dst_p, src_p, self.seq_atual, self.seq_esperado, FLAGS_ACK)
            pedaço = dados[i * MSS: min((i + 1) * MSS, len(dados))]
            segmento += pedaço
            tam = len(pedaço)
            self.ack_retorno += tam
            resposta = fix_checksum(segmento, dst_ip, src_ip)

            if self.ocupacao + tam <= self.limite_janela:
                self.nucleo.enlace.enviar(resposta, src_ip)
                self.enviados.append((time.time(), resposta, src_ip, tam))
                self.ocupacao += tam
                if not self.cronometro:
                    self.cronometro = asyncio.get_event_loop().call_later(self.tempo_limite, self._reenvio)
            else:
                self.pendentes.append((resposta, src_ip, tam))

    def fechar(self):
        self.seq_atual = self.ack_retorno
        src_ip, src_p, dst_ip, dst_p = self.chave
        segmento = make_header(dst_p, src_p, self.seq_atual, self.seq_esperado + 1, FLAGS_FIN)
        resposta = fix_checksum(segmento, dst_ip, src_ip)
        self.nucleo.enlace.enviar(resposta, src_ip)
