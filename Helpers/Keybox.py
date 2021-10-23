import io
import json
import struct
from base64 import b64decode, b64encode
from binascii import hexlify


def create_table():
    a = []
    for i in range(256):
        k = i << 24
        for _ in range(8):
            k = (k << 1) ^ 0x4c11db7 if k & 0x80000000 else k << 1
        a.append(k & 0xffffffff)
    return a


def crc32_mpeg(data, length):
    crc_val = 0xFFFFFFFF
    crctab = create_table()
    for i in range(length):
        crc_val = (crctab[(data[i] & 0xFF) ^ (crc_val >> 24)] ^ (crc_val << 8)) & 0xFFFFFFFF
    return crc_val


class Keybox:
    def __init__(self, keybox_data: any):
        if isinstance(keybox_data, str):
            self.__keybox = b64decode(keybox_data)
        elif isinstance(keybox_data, io.BufferedReader):
            self.__keybox = keybox_data.read()
        elif isinstance(keybox_data, dict):
            self.__keybox = self.__generate_crc(keybox_data)
        else:
            print(type(keybox_data))
            raise ValueError('unable to read the file/string, etc')

        self.__parse()

    @staticmethod
    def __generate_crc(keybox) -> bytes:
        device_id = keybox['device_id']
        device_token = keybox['device_token']
        device_key = keybox['device_key']
        key_box = bytes.fromhex(device_id) + bytes.fromhex(device_key) + bytes.fromhex(device_token) + b'kbox'
        crc = crc32_mpeg(key_box, len(key_box))
        key_box += struct.pack('>I', crc)
        key_box += keybox['security_level'].encode()
        return key_box

    def __parse(self):
        self.device_id = self.__keybox[0:32]
        # this is the aes key
        self.device_key = self.__keybox[32:48]
        self.device_token = self.__keybox[48:120]
        self.keybox_tag = self.__keybox[120:124]
        self.crc32 = struct.unpack('>I', self.__keybox[124:128])[0]
        self.crc32_raw = hexlify(self.__keybox[124:128])
        # this is optional, most likely not required
        self.level_tag = self.__keybox[128:132]
        self.flags = struct.unpack(">L", self.__keybox[48:120][0:4])[0]
        self.version = struct.unpack(">I", self.__keybox[48:52])[0]
        self.system_id = struct.unpack(">I", self.__keybox[52:56])[0]
        # or unique_id as in wv pdf, encrypted by pre-provisioning key
        self.provisioning_id = self.__keybox[56:72]
        # encrypted with unique id, contains device key, device key hash, and flags
        self.encrypted_bits = self.__keybox[72:120]

    def __repr__(self):
        return json.dumps({
            'device_id': b64encode(self.device_id).decode(),
            'device_id_size': len(self.device_id),
            'device_key': b64encode(self.device_key).decode(),
            'device_token': b64encode(self.device_token).decode(),
            'device_token_size': len(self.device_token),
            'kbox_tag': self.keybox_tag.decode(),
            'crc32': self.crc32,
            'crc32_raw': self.crc32_raw.decode(),
            'lvl1_tag': self.level_tag.decode(),
            'flags': self.flags,
            'released': True if self.flags & 2 == 2 else False,
            'version': self.version,
            'system_id': self.system_id,
            'provisioning_id': b64encode(self.provisioning_id).decode(),
            'encrypted_bits': b64encode(self.encrypted_bits).decode(),
            'keybox': b64encode(self.__keybox).decode()
        }, indent=4)

    def get_keybox(self):
        return self.__keybox
