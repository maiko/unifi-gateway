"""Encode UniFi inform messages and Gateway Enterprise multicast discovery."""

from binascii import a2b_hex
from ipaddress import IPv4Address
import json
import re
from struct import pack, unpack
import zlib

from Crypto import Random
from Crypto.Cipher import AES

from gateway_profiles.enterprise import MODEL, FIRMWARE, require_enterprise
from gateway_profiles.uxg import build_uxg_inform
from tlv import UnifiTLV

try:
    import snappy
except ImportError:
    snappy = None

MASTER_KEY = "ba86f2bbe107c7c57eb5f2690775c712"


def _gateway_mac(config):
    mac = config['gateway']['lan_mac']
    if re.fullmatch(r'[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}', mac) is None:
        raise ValueError("Gateway identity requires a six-octet MAC address")
    return bytes.fromhex(mac.replace(':', ''))


def encode_inform(config, data, encryption='CBC'):
    iv = Random.new().read(16)
    key = MASTER_KEY

    if config.getboolean('gateway', 'is_adopted'):
        key = config.get('gateway', 'key')
        if config.getboolean('gateway', 'use_aes_gcm'):
            encryption = 'GCM'
        else:
            encryption = 'CBC'

    mac = _gateway_mac(config)

    # Flags: bit 0 = encrypted, bit 1 = zlib, bit 2 = snappy, bit 3 = GCM
    flags = 0x01
    if encryption == 'GCM':
        flags |= 0x08

    if snappy is not None:
        payload = snappy.compress(data.encode('utf-8'))
        flags |= 0x04
    else:
        payload = zlib.compress(data.encode('utf-8'))
        flags |= 0x02

    encoded_data = b'TNBU'
    encoded_data += pack('>I', 1)
    encoded_data += mac
    encoded_data += pack('>H', flags)
    encoded_data += iv
    encoded_data += pack('>I', 1)

    if encryption == 'GCM':
        encoded_data += pack('>I', len(payload) + 16)
        _aes = AES.new(a2b_hex(key), AES.MODE_GCM, iv)
        _aes.update(encoded_data)
        payload, tag = _aes.encrypt_and_digest(payload)
        payload += tag
    elif encryption == 'CBC':
        pad_len = AES.block_size - (len(payload) % AES.block_size)
        payload += bytes([pad_len]) * pad_len
        payload = AES.new(a2b_hex(key), AES.MODE_CBC, iv).encrypt(payload)
        encoded_data += pack('>I', len(payload))

    encoded_data += payload
    return encoded_data


def decode_inform(config, encoded_data, *, require_gcm=False):
    magic = encoded_data[0:4]
    if magic != b'TNBU':
        raise Exception("Missing magic in response: '{}' instead of 'TNBU'".format(magic))

    header = encoded_data[:40]
    flags = unpack('>H', encoded_data[14:16])[0]
    iv = encoded_data[16:32]
    payload_len = unpack('>I', encoded_data[36:40])[0]
    payload = encoded_data[40:(40 + payload_len)]
    if require_gcm and ((flags & 0x09) != 0x09 or payload_len < 16 or len(encoded_data) != 40 + payload_len):
        raise ValueError('The controller response requires authenticated AES-GCM')

    flag = {
        'encrypted': bool(flags & 0x01),
        'zlibCompressed': bool(flags & 0x02),
        'SnappyCompression': bool(flags & 0x04),
        'encryptedGCM': bool(flags & 0x08),
    }

    key = MASTER_KEY
    if config.getboolean('gateway', 'is_adopted'):
        key = config.get('gateway', 'key')

    if flag['encrypted']:
        if flag['encryptedGCM']:
            tag = payload[-16:]
            payload = payload[:-16]
            _aes = AES.new(a2b_hex(key), AES.MODE_GCM, iv)
            _aes.update(header)
            payload = _aes.decrypt_and_verify(payload, tag)
        else:
            payload = AES.new(a2b_hex(key), AES.MODE_CBC, iv).decrypt(payload)
            pad_size = payload[-1]
            if pad_size > AES.block_size:
                raise Exception('Response not padded or padding is corrupt')
            payload = payload[:(len(payload) - pad_size)]

    if flag['SnappyCompression']:
        if snappy is not None:
            payload = snappy.decompress(payload)
        else:
            raise Exception(
                'Response is snappy-compressed but python-snappy is not installed'
            )
    elif flag['zlibCompressed']:
        payload = zlib.decompress(payload)

    return json.loads(payload)


def create_inform(config, dc):
    adopted = config.getboolean('gateway', 'is_adopted')
    return json.dumps(build_uxg_inform(config, dc, adopted=adopted))


def create_broadcast_message(config, index, *, router_uptime=None, version=2, command=6):
    require_enterprise(config)
    mac = _gateway_mac(config)
    ip = IPv4Address(config['gateway']['lan_ip']).packed

    tlv = UnifiTLV()
    tlv.add(1, mac)
    tlv.add(2, mac + ip)
    tlv.add(3, f"{MODEL}.v{FIRMWARE}".encode('ascii'))
    if router_uptime is not None:
        tlv.add(10, pack('!I', router_uptime))
    tlv.add(11, b'vyos')
    tlv.add(12, MODEL.encode('ascii'))
    tlv.add(19, mac)
    tlv.add(18, pack('!I', index))
    tlv.add(21, MODEL.encode('ascii'))
    tlv.add(27, FIRMWARE.encode('ascii'))
    tlv.add(22, FIRMWARE.encode('ascii'))
    return tlv.get(version=version, command=command)
