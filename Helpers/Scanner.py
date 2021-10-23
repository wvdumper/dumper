import os
import json
from Crypto.PublicKey import RSA
from google.protobuf import message
import logging
from Helpers.Keybox import Keybox
from Helpers.wv_proto2_pb2 import SignedLicenseRequest


class Scan:
    def __init__(self, device_name):
        self.logger = logging.getLogger(__name__)
        self.KEY_DUMP_LOC = 'keydump/'
        self.device_name = device_name
        self.saved_keys = {}
        self.frida_script = open('Helpers/script.js', 'r').read()
        self.device = {
            'device_id': None,
            'device_token': None,
            'device_key': os.urandom(16).hex(),
            'security_level': ''
        }
        self.widevine_libraries = [
            'libwvhidl.so',
            'libwvdrmengine.so',
            'liboemcrypto.so',
            'libmediadrm.so',
            'libwvdrm_L1.so',
            'libWVStreamControlAPI_L1.so',
            'libdrmwvmplugin.so',
            'libwvm.so'
        ]

    def export_key(self, k):
        root = SignedLicenseRequest()
        root.ParseFromString(k['id'])
        cid = root.Msg.ClientId
        system_id = cid.Token._DeviceCertificate.SystemId
        save_dir = os.path.join('key_dumps', f'{self.device_name}/private_keys/{system_id}/{str(k["key"].n)[:10]}')

        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        with open(os.path.join(save_dir, 'client_id.bin'), 'wb+') as writer:
            writer.write(cid.SerializeToString())

        with open(os.path.join(save_dir, 'private_key.pem'), 'wb+') as writer:
            writer.write(k['key'].exportKey('PEM'))
        self.logger.info('Key pairs saved at ' + save_dir)

    def on_message(self, msg, data):
        try:
            if msg['payload'] == 'priv':
                self.logger.debug('processing private key')
                self.private_key_message(msg, data)
            elif msg['payload'] == 'id':
                self.logger.debug('processing id')
                self.license_request_message(data)
            elif msg['payload'] == 'device_id':
                self.logger.debug('processing device id')
                self.device_id_message(data)
            elif msg['payload'] == 'device_token':
                self.logger.debug('processing device token')
                self.device_token_message(data)
            elif msg['payload'] == 'security_level':
                tag = data.decode()
                if tag == 'L1':
                    self.device['security_level'] = 'LVL1'
                else:
                    self.device['security_level'] = 'LVL3'
            elif msg['payload'] == 'aes_key':
                self.aes_key_message(data)
            elif msg['payload'] == 'message':
                payload = json.loads(data.decode())
                self.logger.debug(
                    json.dumps(
                        payload,
                        indent=4
                    )
                )
            elif msg['payload'] == 'message_info':
                self.logger.info(data.decode())

        except:
            self.logger.error('unable to process the message')
            self.logger.error(msg)
            self.logger.error(data)

    def private_key_message(self, private_key_message, data):
        try:
            try:
                key = RSA.importKey(data)
                cur = self.saved_keys.get(key.n, {})
                if 'id' in cur:
                    if 'key' not in cur:
                        cur['key'] = key
                        self.saved_keys[key.n] = cur
                        self.export_key(cur)
                else:
                    self.saved_keys[key.n] = {'key': key}
            except:
                self.logger.error('unable to load private key')
                self.logger.error(data)
                pass
        except:
            self.logger.error('payload of type priv failed')
            self.logger.error(private_key_message)

    def license_request_message(self, data):
        with open('license_request.bin', 'wb+') as f:
            f.write(data)
        root = SignedLicenseRequest()
        try:
            root.ParseFromString(data)
        except message.DecodeError:
            return
        try:
            key = RSA.importKey(root.Msg.ClientId.Token._DeviceCertificate.PublicKey)
            cur = self.saved_keys.get(key.n, {})
            if 'key' in cur:
                if 'id' not in cur:
                    cur['id'] = data
                    self.saved_keys[key.n] = cur
                    self.export_key(cur)
            else:
                self.saved_keys[key.n] = {'id': data}
        except Exception as error:
            self.logger.error(error)

    def device_id_message(self, data_buffer):
        if not self.device['device_id']:
            self.device['device_id'] = data_buffer.hex()
        if self.device['device_id'] and self.device['device_token'] and self.device['device_key']:
            self.save_key_box()

    def device_token_message(self, data_buffer):
        if not self.device['device_token']:
            self.device['device_token'] = data_buffer.hex()
        if self.device['device_id'] and self.device['device_token']:
            self.save_key_box()

    def aes_key_message(self, data_buffer):
        if not self.device['device_key']:
            self.device['device_key'] = data_buffer.hex()
        if self.device['device_id'] and self.device['device_token']:
            self.save_key_box()

    def find_widevine_process(self, dev, process_name):
        process = dev.attach(process_name)
        script = process.create_script(self.frida_script)
        script.load()
        loaded = []
        try:
            for lib in self.widevine_libraries:
                try:
                    loaded.append(script.exports.widevinelibrary(lib))
                except:
                    pass
        finally:
            process.detach()
            return loaded

    def hook_to_process(self, device, process, library):
        session = device.attach(process)
        script = session.create_script(self.frida_script)
        script.on('message', self.on_message)
        script.load()
        script.exports.inject(library, process)
        return session

    def save_key_box(self):
        try:
            if self.device['device_id'] is not None and self.device['device_token'] is not None:
                self.logger.info('saving key box')
                keybox = Keybox(self.device)
                box = os.path.join('key_dumps', f'{self.device_name}/key_boxes/{keybox.system_id}')
                self.logger.debug(f'saving to {box}')
                if not os.path.exists(box):
                    os.makedirs(box)
                with open(os.path.join(box, f'{keybox.system_id}.bin'), 'wb') as writer:
                    writer.write(keybox.get_keybox())
                with open(os.path.join(box, f'{keybox.system_id}.json'), 'w') as writer:
                    writer.write(keybox.__repr__())
                self.logger.info(f'saved keybox to {box}')
        except Exception as error:
            self.logger.error('unable to save keybox')
            self.logger.error(error)