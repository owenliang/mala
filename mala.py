import os
import hashlib
import asyncio
import binascii
import struct

from bencoder import bencode, bdecode

import math


class MessageType:
    REQUEST = 0
    DATA = 1
    REJECT = 2


BT_PROTOCOL = "BitTorrent protocol"
BT_PROTOCOL_LEN = len(BT_PROTOCOL)
EXT_ID = 20
EXT_HANDSHAKE_ID = 0
EXT_HANDSHAKE_MESSAGE = bytes([EXT_ID, EXT_HANDSHAKE_ID]) + bencode({"m": {"ut_metadata": 1}})

BLOCK = math.pow(2, 14)
MAX_SIZE = BLOCK * 1000
BT_HEADER = b'\x13BitTorrent protocol\x00\x00\x00\x00\x00\x10\x00\x01'


def random_id(size=20):
    return os.urandom(size)


def get_ut_metadata(data):
    ut_metadata = b"ut_metadata"
    index = data.index(ut_metadata)+len(ut_metadata) + 1
    data = data[index:]
    return int(data[:data.index(b'e')])


def get_metadata_size(data):
    metadata_size = b"metadata_size"
    start = data.index(metadata_size) + len(metadata_size) + 1
    data = data[start:]
    return int(data[:data.index(b"e")])


class WirePeerClient:
    def __init__(self, infohash):
        if isinstance(infohash, str):
            infohash = binascii.unhexlify(infohash.upper())
        self.infohash = infohash
        self.peer_id = random_id()

        self.writer = None
        self.reader = None

        self.ut_metadata = 0
        self.metadata_size = 0
        self.handshaked = False
        self.pieces_num = 0
        self.pieces_received_num = 0
        self.pieces = None

    async def connect(self, ip, port, loop):
        self.reader, self.writer = await asyncio.open_connection(
            ip, port, loop=loop
        )

    def close(self):
        try:
            self.writer.close()
        except:
            pass

    def check_handshake(self, data):
        # Check BT Protocol Prefix
        if data[:20] != BT_HEADER[:20]:
            return False
        # Check InfoHash
        if data[28:48] != self.infohash:
            return False
        # Check support metadata exchange
        if data[25] != 16:
            return False
        return True

    def write_message(self, message):
        length = struct.pack(">I", len(message))
        self.writer.write(length + message)

    def request_piece(self, piece):
        msg = bytes([EXT_ID, self.ut_metadata]) + bencode({"msg_type": 0, "piece": piece})
        self.write_message(msg)

    def pieces_complete(self):
        metainfo = b''.join(self.pieces)

        if len(metainfo) != self.metadata_size:
            # Wrong size
            return self.close()

        infohash = hashlib.sha1(metainfo).hexdigest()
        if binascii.unhexlify(infohash.upper()) != self.infohash:
            # Wrong infohash
            return self.close()

        return bdecode(metainfo)

    # 1, 先是peer wire协议是外层, 需要先双向握手（我主动）, 然后后续通讯外层都需要按照length,bitorrent message id(传20),payload，因此下来的extend扩展协议是包装在payload内部的。
    # 2, payload内依次放置extended message id标识extended message的类型, 传0表示握手, 那么后面紧随bencode编码字典携带ut_metadata字段告知对方在握手应答中携带meta基本信息。
    # 3, 对方会回复握手, extended message id也为0, 后面的bencode里会携带metadata_size, 我们就此可以算出metadata一共分成了几个16k的片段
    # 4, 接下来每次extend message id使用ut_metadata对应的数字id, 后面bencode编码字典中msg_type传0表示请求meta, piece传分片下标
    # 5, 对方回复的bencode中会有msg_type=1表示meta数据,piece下标, total_size表示分片大小, 在bencode之后就是二进制的meta片段数据.
    # 相关链接：http://blog.chinaunix.net/uid-14408083-id-2814554.html
    # http://www.aneasystone.com/archives/2015/05/analyze-magnet-protocol-using-wireshark.html
    async def work(self):
        self.writer.write(BT_HEADER + self.infohash + self.peer_id)
        while True:
            if not self.handshaked:
                if self.check_handshake(await self.reader.readexactly(68)):
                    self.handshaked = True
                    # Send EXT Handshake
                    self.write_message(EXT_HANDSHAKE_MESSAGE)
                else:
                    return self.close()

            total_message_length, msg_id = struct.unpack("!IB", await self.reader.readexactly(5))
            # Total message length contains message id length, remove it
            payload_length = total_message_length - 1
            payload = await self.reader.readexactly(payload_length)

            if msg_id != EXT_ID:
                continue
            extended_id, extend_payload = payload[0], payload[1:]
            if extended_id == 0 and not self.ut_metadata:
                # Extend handshake, receive ut_metadata and metadata_size
                try:
                    self.ut_metadata = get_ut_metadata(extend_payload)
                    self.metadata_size = get_metadata_size(extend_payload)
                except:
                    return self.close()
                self.pieces_num = math.ceil(self.metadata_size / BLOCK)
                self.pieces = [False] * self.pieces_num
                self.request_piece(0)
                continue

            try:
                split_index = extend_payload.index(b"ee")+2
                info = bdecode(extend_payload[:split_index])
                if info[b'msg_type'] != MessageType.DATA:
                    return self.close()
                if info[b'piece'] != self.pieces_received_num:
                    return self.close()
                self.pieces[info[b'piece']] = extend_payload[split_index:]
            except:
                return self.close()
            self.pieces_received_num += 1
            if self.pieces_received_num == self.pieces_num:
                return self.pieces_complete()
            else:
                self.request_piece(self.pieces_received_num)


async def get_metadata(infohash, ip, port, loop=None):
    if not loop:
        loop = asyncio.get_event_loop()

    client = WirePeerClient(infohash)
    try:
        await client.connect(ip, port, loop)
        return await client.work()
    except Exception as e:
        client.close()
        return False
