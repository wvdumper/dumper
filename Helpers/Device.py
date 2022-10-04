import os
import logging
import base64
import frida
from Crypto.PublicKey import RSA
from Helpers.wv_proto2_pb2 import SignedLicenseRequest


class Device:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.saved_keys = {}
        self.frida_script = open(
            './Helpers/script.js',
            'r',
            encoding="utf_8"
        ).read()
        self.widevine_libraries = [
            'libwvhidl.so'
        ]
        self.usb_device = frida.get_usb_device()
        self.name = self.usb_device.name

    def export_key(self, key, client_id):
        system_id = client_id.Token._DeviceCertificate.SystemId
        save_dir = os.path.join(
            'key_dumps',
            f'{self.name}/private_keys/{system_id}/{str(key.n)[:10]}'
        )

        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        with open(os.path.join(save_dir, 'client_id.bin'), 'wb+') as writer:
            writer.write(client_id.SerializeToString())

        with open(os.path.join(save_dir, 'private_key.pem'), 'wb+') as writer:
            writer.write(key.exportKey('PEM'))
        self.logger.info('Key pairs saved at %s', save_dir)

    def on_message(self, msg, data):
        if msg['payload'] == 'private_key':
            key = RSA.import_key(data)
            if key.n not in self.saved_keys:
                encoded_key = base64.b64encode(data).decode('utf-8')
                self.logger.debug('Retrieved key: %s', encoded_key)
            self.saved_keys[key.n] = key
        elif msg['payload'] == 'device_info':
            self.license_request_message(data)
        elif msg['payload'] == 'message_info':
            self.logger.info(data.decode())

    def license_request_message(self, data):
        root = SignedLicenseRequest()
        root.ParseFromString(data)
        public_key = root.Msg.ClientId.Token._DeviceCertificate.PublicKey
        self.logger.debug(
            'Retrieved key: %s',
            base64.b64encode(public_key).decode('utf-8')
        )
        key = RSA.importKey(public_key)
        cur = self.saved_keys.get(key.n)
        self.export_key(cur, root.Msg.ClientId)

    def find_widevine_process(self, process_name):
        process = self.usb_device.attach(process_name)
        script = process.create_script(self.frida_script)
        script.load()
        loaded_modules = []
        try:
            for lib in self.widevine_libraries:
                loaded_modules.append(script.exports.getmodulebyname(lib))
        finally:
            process.detach()
            return loaded_modules

    def hook_to_process(self, process, library):
        session = self.usb_device.attach(process)
        script = session.create_script(self.frida_script)
        script.on('message', self.on_message)
        script.load()
        script.exports.hooklibfunctions(library)
        return session
