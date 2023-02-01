import ipaddress
import os
import socket
import struct
import sys

class IP:
    def __init__(self, buff=None):
        header = struct.upback('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.inl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # IPアドレスを可読な形で変数に格納
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # プロトコルの定数値を名称にマッピング
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol.num]
        except Exception as e:
            print('%s No protocol for %s' %(e, self.protocol_num))
            self.protocol = str(self.protocol_num)

    def sniff(host):
        # 前の列と同様の処理
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPRPTP_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            sniffer.itctl(socket.SIO_REVALL, socket.RECVALLON)

        try:
            while True:
                # パケットの読み込み
                raw_buffer = sniffer.recvfrom(65535)[0]
                # バッファの最初の20バイトからIP構造体を作成
                ip.header = IP(raw_buffer[0 : 20])
                # 検出されたプロトコルとホストを出力
                print('Protocol: %s %s')
