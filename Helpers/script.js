const KNOWN_DYNAMIC_FUNC = ['ulns', 'cwkfcplc', 'dnvffnze', 'kgaitijd', 'polorucp'];

function containsLib(library){
    return Process.getModuleByName(library);
}

function containsFunction(name, address) {
    var result = false;
    for (var i = 0; i < KNOWN_DYNAMIC_FUNC.length; i++) {
        result = KNOWN_DYNAMIC_FUNC[i] === name;
        if (result) {
            sender_payload({
                from: 'Dynamic Function',
                message: 'L3 RSA Key export function found: ' + name
            });
            return result;
        }
    }

    return result;

}


function inject(lib, process_name){
    // printer('Running ' + lib['name'] + ' at ' + lib['base'], 'Hook');
    sender_payload_info(
        'Running ' + lib['name'] + ' at ' + lib['base']
    );
    Hooker(lib, process_name)
}

function Hooker(lib, process_name) {
    const name = lib['name'];
    Module.enumerateExportsSync(name).forEach(function(exp){
        try {
            var module_address = exp.address;
            if (exp.name === '_lcc00' || exp.name === '_oecc00') {
                GetLevel3_IsInApp(module_address, process_name);
            } else if (exp.name === '_lcc01' || exp.name === '_oecc01') {
                GetLevel3_Initialize(module_address, process_name);
            } else if (exp.name === '_lcc49' || exp.name === '_oecc49') {
                GetLevel3_GetProvisioningMethod(module_address, process_name);
            } else if (exp.name === '_lcc38' || exp.name === '_oecc38') {
                GetLevel3_GetNumberOfOpenSessions(module_address, process_name);
            } else if (exp.name === '_lcc37' || exp.name === '_oecc37') {
                GetLevel3_GetMaxNumberOfSessions(module_address, process_name);
            } else if (exp.name === '_lcc22' || exp.name === '_oecc22') {
                GetApiVersion(module_address, process_name);
            } else if (exp.name === '_lcc46' || exp.name === '_oecc46') {
                GetSecurityPatchLevel(module_address, process_name);
            } else if (exp.name === '_lcc23' || exp.name === '_oecc23') {
                GetSecurityLevel(module_address, process_name);
            } else if (exp.name === '_lcc90' || exp.name === '_oecc90') {
                GetLevel3_BuildInformation(module_address, process_name);
            } else if (exp.name === '_lcc52' || exp.name === '_oecc52') {
                GetSupportedCertificates(module_address, process_name);
            } else if (exp.name === '_lcc02' || exp.name === '_oecc02') {
                GetLevel3_Terminate_Status(module_address, process_name);
            } else if (exp.name === '_lcc07' || exp.name === '_oecc07') {
                GetLevel3_GetDeviceID(module_address, process_name);
            } else if (exp.name === '_lcc04' || exp.name === '_oecc04') {
                GetLevel3_GetKeyData(module_address, process_name)
            } else if (exp.name === 'OEMCrypto_LoadKeys_Back_Compat') {
                GetLevel3_LoadKeys(module_address, process_name);
            } else if (exp.name === '_lcc12' || exp.name === '_oecc12') {
                GetLevel3_GenerateDerivedKeys(module_address, process_name);
            } else if (exp.name === '_lcc13' || exp.name === '_oecc13') {
                GetLevel3_GenerateSignature(module_address, process_name);
            } else if (exp.name === '_lcc50' || exp.name === '_oecc50') {
                GetLevel3_GetOEMPublicCertificate(module_address, process_name);
            } else if (exp.name === '_lcc19' || exp.name === '_oecc19') {
                GetLevel3_LoadDeviceRSAKey(module_address, process_name)
            } else if (exp.name === '_lcc18' || exp.name === '_oecc18') {
                GetLevel3_RewrapDeviceRSAKey(module_address, process_name);
            } else if (exp.name === 'AES_unwrap_key') {
                AES_unwrap_key(module_address, process_name)
            } else if (containsFunction(exp.name, exp.address)) {
                polorucp(module_address, process_name);
            } else if (exp.name.includes('UsePrivacyMode')) {
                UsePrivacyMode(module_address, process_name);
            } else if (exp.name === 'CdmInfo') {
                CdmInfo(module_address, process_name);
            } else if (exp.name.includes('PrepareKeyRequest')) {
                PrepareKeyRequest(module_address, process_name);
            } else if (exp.name.includes("_ZN14video_widevine25SignedProvisioningMessageC2Ev")) {
                SignedProvisioningMessage(module_address, process_name)
            } else if (exp.name === 'AES_set_encrypt_key') {
                AES_set_encrypt_key(module_address, process_name)
            }  else if (exp.name.includes('jnyxqs')) {
                // this needs to be changed to an array of methods since they all differ between oemcryptos for l1 and l3
                jnyxqs(module_address)
            } else if (exp.name === 'fwemrknr') {
                fwemrknr(module_address, process_name)
            } else if (exp.name === 'pbntpypb') {
                pbntpypb(module_address, process_name)
            }
        } catch (e) {
            console.log("Error: " + e + " at F: " + exp.name);
        }
});
}

function pbntpypb(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function(args) {
            this.data = {
                '1': args[0]
            }
        },
        onLeave: function(returnResult) {
            console.log(hexdump(returnResult));
            // console.log('onleave')
            // console.log('first parameter');
            // const data = Memory.readPointer(this.data['1']);
            // const param1 = hexdump(data);
            // console.log(param1);
            // console.log('ended')
        }
    });
}

function fwemrknr(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function(args) {
            this.data = {
                '0': args[0],
                '1': args[1],
                '2': args[2],
                '3': args[3],
                '4': args[4],
                '5': args[5],
                '6': args[6],
                '7': args[7],
                '8': args[8],
                '9': args[9],
                '10': args[10],
                '11': args[11],
                '12': args[12],
                '13': args[13],
                '14': args[14],
                '15': args[15],
                '16': args[16]
            }
        },
        onLeave: function(returnResult) {
            // console.log('onleave')
            // console.log('first parameter');
            // const data = Memory.readPointer(this.data['1']);
            // const param1 = hexdump(data);
            // console.log(param1);
            // console.log('ended')
        }
    });
}

function jnyxqs(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function(args) {
            this.data = {
                '1': args[0],
                '2': args[1]
            }
        },
        onLeave: function(returnResult) {
            printer('jnyxqs', process_name);
            console.log(hexdump(returnResult));
            console.log(Memory.readByteArray(this.data['1'], this.data['2'].toInt32()));
            console.log(this.data['2'].toInt32());
            send('aes_key', Memory.readByteArray(this.data['1'], this.data['2'].toInt32()))
        }
    });
}

function ithomqf(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function(args) {
            this.data = {
                '1': args[0],
                '2': args[1]
            }
        },
        onLeave: function(returnResult) {
            printer('ithomqf', process_name);
            console.log(hexdump(returnResult));
        }
    });
}

function AES_set_encrypt_key(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            // both of these are pointers
            this.data = {
                "userKey": args[0],
                "bits": args[1],
                'key': args[2]

            }
        },
        onLeave: function (returnResult) {
            const size = this.data['bits'].toInt32() / 8;
            const userKey = Memory.readByteArray(this.data['userKey'], size);
            const key = Memory.readByteArray(this.data['key'], size);
            printer('return result: ' + returnResult);
            const data = {
                from: process_name,
                message: 'AES_set_encrypt_key',
                payload: {
                    'size': size,
                    'user_key': byteArrayToHex(userKey),
                    'key':  byteArrayToHex(key)

                }
            }
            sender_payload(data)
        }
    });
}


function SignedProvisioningMessage(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            this.data = args[0]
        },
        onLeave: function () {
            printer('SignedProvisioningMessage', process_name);
            console.log(this.data);
            console.log(hexdump(this.data));
            console.log(hexdump(Memory.readPointer(this.data)));
            console.log(hexdump(Memory.readPointer(Memory.readPointer(this.data))));
            console.log(Memory.readByteArray(Memory.readPointer(Memory.readPointer(this.data)), 2000));

        }
    });
}

function readStdString(str) {
    const size = str.add(Process.pointerSize).readUInt();
    return str.add(Process.pointerSize * 2).readPointer().readByteArray(size);
}

function printer(message, origination){
    console.log('['+origination+']:[INFO]:', message)
}

function CdmInfo(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function(args) {
            console.log('CdmInfo');
            console.log(JSON.stringify(args))
        }
    });
}

function polorucp(address, process_name) {
    Interceptor.attach(ptr(address), {
       onEnter: function(args) {
           if (!args[6].isNull()) {
               const size = args[6].toInt32();
               if (size >= 1000 && size <= 2000 && !args[5].isNull()) {
                   const k = args[5].readByteArray(size);
                   const view = new Uint8Array(k);
                   if (view[0] === 0x30 && view[1] === 0x82) {
                       const data = {
                           from: process_name,
                           data: 'Captured Private Key'
                       };
                       sender_payload(data);
                       send('priv', k);
                   }
               }
           }
       }
    });
}

function PrepareKeyRequest(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            this.ret = args[4];
        },
        onLeave: function () {
            if (this.ret) {
                const message = readStdString(this.ret);
                const data = {
                    from: process_name,
                    message: 'PrepareKeyRequest, Captured License Request'
                };
                sender_payload(data);
                send('id', message);
            }
        }
    });
}

function UsePrivacyMode(address, process_name) {
    Interceptor.attach(address, {
        onLeave: function (retval) {
            const data = {
              from: process_name,
              message: 'Replacing PrivacyMode'
            };
            sender_payload(data);
            retval.replace(ptr(0));
        }
    });
}

function AES_unwrap_key(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            console.log('entering aes unwrap key')
        }
    })
}

function GetLevel3_Initialize(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function(args) {
            sender_payload(
                {
                    from: process_name,
                    message: 'OEMCrypto_Initialize'
                }
            )
        }
    })
}

function GetApiVersion(address, process_name) {
    Interceptor.attach(ptr(address), {
        onLeave: function (retval) {
            // const message = 'OEMCryptoVersion: ' + retval.toInt32();
            const data = {
                from: process_name,
                message: 'OEMCryptoVersion',
                payload: {
                    'Version': retval.toInt32()
                }
            };
            sender_payload(data)
        }
    });
}

function GetSecurityPatchLevel(address, process_name) {
    Interceptor.attach(ptr(address), {
        onLeave: function (retval) {
            sender_payload({
                from: process_name,
                message: 'OEMSecurityPatchLevel',
                payload:{
                    'Patch_Level': retval.toInt32()
                }
            })
        }
    });
}

function GetSecurityLevel(address, process_name) {
    Interceptor.attach(ptr(address), {
        onLeave: function (retval) {
            const level = Memory.readUtf8String(retval);
            sender_payload({
                from: process_name,
                message: 'OEMSecurityLevel',
                payload: {
                    'Level': level
                }
            });
            send('security_level', new TextEncoder().encode(level))
        }
    });
}

function GetLevel3_BuildInformation(address, process_name) {
    Interceptor.attach(ptr(address), {
        onLeave: function (retval) {
            const message = 'OEMCrypto_BuildInformation: ' + Memory.readUtf8String(retval);
            sender_payload({
                from: process_name,
                message: message
            });
        }
    });
}

function GetSupportedCertificates(address, process_name) {
    Interceptor.attach(ptr(address), {
        onLeave: function (retval) {
            const message = 'OEMSupportedCertificates: ' + OEMCrypto_RSA_Support[retval.toInt32()];
            sender_payload({
                from: process_name,
                message: message
            });
        }
    });
}

function GetLevel3_IsInApp(address, process_name) {
    Interceptor.attach(ptr(address), {
        onLeave: function (retval) {
            sender_payload({
                from: process_name,
                message: 'OEMCrypto_IsInApp',
                payload: {
                    'in_app': Boolean(retval)
                }
            });
        }
    });
}

function GetLevel3_GetProvisioningMethod(address, process_name) {
    Interceptor.attach(ptr(address), {
        onLeave: function (retval) {
            sender_payload({
                from: process_name,
                message: 'OEMCrypto_GetProvisioningMethod',
                payload: {
                    'Method': OEMCrypto_ProvisioningMethod[retval.toInt32()]
                }
            });
        }
    });
}

function GetLevel3_GetNumberOfOpenSessions(address, process_name) {
    Interceptor.attach(ptr(address), {
        onLeave: function (retval) {
            const message = 'OEMCrypto_GetNumberOfOpenSessions: ' + retval.toInt32();
            sender_payload({
                from: process_name,
                message: message
            });
        }
    });
}

function GetLevel3_GetMaxNumberOfSessions(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            this.maximum = args[0]
        },
        onLeave: function () {
            const message = 'OEMCrypto_GetMaxNumberOfSessions: ' + Memory.readPointer(this.maximum).toInt32();
            sender_payload({
                from: process_name,
                message: message
            });
        }
    });
}

function GetLevel3_Terminate_Status(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            this.maximum = args[0]
        },
        onLeave: function (retvalue) {
            const message = 'OEMCrypto_Terminate_Status: ' + OEMCryptoResult[retvalue.toInt32()];
            sender_payload({
                from: process_name,
                message: message
            });
        }
    });
}

function GetLevel3_GetDeviceID(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function(args) {
            this.deviceId = args[0];
            this.idLength = args[1]
        },
        onLeave: function (retval) {
            var idLength = Memory.readPointer(this.idLength).toInt32();
            const deviceIdArray = Memory.readByteArray(this.deviceId, idLength);
            const deviceId = byteArrayToHex(deviceIdArray);
            const data = {
                from: process_name,
                message: 'OEMCrypto_GetDeviceID',
                payload: {
                    'Status': OEMCryptoResult[retval.toInt32()],
                    'Length': idLength,
                    'DeviceId': deviceId
                }
            };
            sender_payload(data);
            send('device_id', deviceIdArray)
        }
    });
}



function GetLevel3_GetKeyData(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            this.keyData = args[0];
            this.keyDataLength = args[1];
        },
        onLeave: function (retvalue) {
            const keyDataLength = Memory.readPointer(this.keyDataLength).toInt32();
            const keyDataArray = Memory.readByteArray(this.keyData, keyDataLength);
            const device_token = byteArrayToHex(keyDataArray);
            const data = {
                from: process_name,
                message: 'OEMCrypto_GetKeyData',
                payload: {
                    'Status': OEMCryptoResult[retvalue.toInt32()],
                    'Size': keyDataLength,
                    'Device_Token': device_token
                }
            };
            sender_payload(data);
            send('device_token', keyDataArray)
        }
    });
}

function GetLevel3_LoadKeys(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            this.data = {
                'session': args[0],
                'message': args[1],
                'message_length': args[2],
                'signature': args[3],
                'signature_length': args[4],
                'ivs': args[5],
                'keys': args[6],
                'num_keys': args[7],
                'key_array': args[8],
                'pst': args[9],
                'srm_restriction_data': args[10],
                'license_type': args[11]
            }
        },
        onLeave: function (retvalue) {
            const message_length = this.data['message_length'].toInt32();
            const message = Memory.readByteArray(this.data['message'], message_length);
            const signature_length = this.data['signature_length'].toInt32();
            const signature = Memory.readByteArray(this.data['signature'], signature_length);
            // const ivs = this.data['ivs'];
            // const keys = Memory.readPointer(this.data['keys']);
            // const num_keys = this.data['num_keys'].toInt32();
            // const key_array = Memory.readPointer(this.data['key_array']);
            // const pst = this.data['pst'];
            // const srm_restriction_data = this.data['srm_restriction_data'];
            const license_type = OEMCrypto_LicenseType[this.data['license_type'].toInt32()];
            const data = {
                from: process_name,
                message: 'OEMCrypto_LoadKeys',
                payload: {
                    'Status': OEMCryptoResult[retvalue.toInt32()],
                    'Type': license_type,
                    'Message': byteArrayToHex(message),
                    'Signature': byteArrayToHex(signature)
                }
            };
            sender_payload(data)
        }
    });
}


function GetLevel3_GenerateDerivedKeys(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            this.data = {
                'session': args[0],
                'mac_key_context': args[1],
                'mac_key_context_length': args[2],
                'enc_key_context': args[3],
                'enc_key_context_length': args[4]
            }
        },
        onLeave: function (retvalue) {
            const mac_length = this.data['mac_key_context_length'].toInt32();
            const mac_context = Memory.readByteArray(this.data['mac_key_context'], mac_length);
            const enc_length = this.data['enc_key_context_length'].toInt32();
            const enc_context = Memory.readByteArray(this.data['enc_key_context'], enc_length);
            const data = {
                from: process_name,
                message: 'GetLevel3_GenerateDerivedKeys',
                payload: {
                    'Status': OEMCryptoResult[retvalue.toInt32()],
                    'Session': this.data['session'].toInt32(),
                    'Mac_Length': mac_length,
                    'Mac_Context': mac_context,
                    'Enc_Length': enc_length,
                    'Enc_Context': enc_context
                }
            };
            sender_payload(data)

        }
    });
}

function GetLevel3_GenerateSignature(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            this.data = {
                'session': args[0],
                'message': args[1],
                'message_length': args[2],
                'signature': args[3],
                'signature_lenght': args[4]
            }
        },
        onLeave: function (retvalue) {
            const message_length = this.data['message_length'].toInt32();
            const message = Memory.readByteArray(this.data['message'], message_length);
            const signature_lenght = Memory.readPointer(this.data['signature_lenght']).toInt32();
            const signature = Memory.readByteArray(this.data['signature'], signature_lenght);
            const data = {
                from: process_name,
                message: 'GetLevel3_GenerateSignature',
                payload: {
                    'Status': OEMCryptoResult[retvalue.toInt32()],
                    'Session': this.data['session'].toInt32(),
                    message: {
                        'length': message_length,
                        'context': byteArrayToHex(message)
                    },
                    signature: {
                        'length': signature_lenght,
                        'context': byteArrayToHex(signature)
                    }
                }
            };
            sender_payload(data)

        }
    });
}


function GetLevel3_GetOEMPublicCertificate(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            this.data = {
                'session': args[0],
                'public_cert': args[1],
                'public_cert_length': args[2]
            }
        },
        onLeave: function (retvalue) {
            const result = OEMCryptoResult[retvalue.toInt32()];
            const data = {
                from: process_name,
                message: 'GetLevel3_GetOEMPublicCertificate',
                payload: {
                    'Status': result
                }
            };
            sender_payload(data);
            if (result === OEMCryptoResult["0"]) {
                const public_cert_length = Memory.readPointer(this.data['public_cert_length']).toInt32();
                const public_cert = Memory.readByteArray(this.data['public_cert'], public_cert_length);
                const data2 = {
                    from: process_name,
                    message: 'GetLevel3_GetOEMPublicCertificate',
                    payload: {
                        'Session': this.data['session'].toInt32(),
                        'Public_Cert_Length': public_cert_length,
                        'Cert': public_cert
                    }
                };
                sender_payload(data2);
            }
        }
    });
}

function GetLevel3_LoadDeviceRSAKey(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            this.data = {
                'session': args[0],
                'wrapped_rsa_key': args[1],
                'wrapped_rsa_key_length': args[2]
            }
        },
        onLeave: function (retvalue) {
            const wrapped_rsa_key_length = this.data['wrapped_rsa_key_length'].toInt32();
            const wrapped_rsa_key = Memory.readByteArray(this.data['wrapped_rsa_key'], wrapped_rsa_key_length);
            const data = {
                from: process_name,
                message: 'GetLevel3_LoadDeviceRSAKey',
                payload: {
                    'Status': OEMCryptoResult[retvalue.toInt32()],
                    'Session': this.data['session'].toInt32(),
                    'Length': wrapped_rsa_key_length,
                    'Context': byteArrayToHex(wrapped_rsa_key)
                }
            };
            sender_payload(data)
        }
    });
}


function GetLevel3_RewrapDeviceRSAKey(address, process_name) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            this.data = {
                'session': args[0],
                'message': args[1],
                'message_length': args[2],
                'signature': args[3],
                'signature_length': args[4],
                'nonce': args[5],
                'enc_rsa_key': args[6],
                'enc_rsa_key_length': args[7],
                'enc_rsa_key_iv': args[8],
                'wrapped_rsa_key': args[9],
                'wrapped_rsa_key_length': args[10]
            }
        },
        onLeave: function (retvalue) {
            const status = OEMCryptoResult[retvalue.toInt32()];
            if (status === OEMCryptoResult["0"]) {
                const message_length = this.data['message_length'].toInt32();
                const message = Memory.readByteArray(this.data['message'], message_length);
                const signature_length = this.data['signature_length'].toInt32();
                const signature = Memory.readByteArray(this.data['signature'], signature_length);
                const enc_rsa_key_length = this.data['enc_rsa_key_length'].toInt32();
                const enc_rsa_key =  Memory.readByteArray(this.data['enc_rsa_key'], enc_rsa_key_length);
                const wrapped_rsa_key_length = Memory.readPointer(this.data['wrapped_rsa_key_length']).toInt32();
                const wrapped_rsa_key =  Memory.readByteArray(this.data['wrapped_rsa_key'], wrapped_rsa_key_length);
                const data = {
                    from: process_name,
                    message: 'GetLevel3_RewrapDeviceRSAKey',
                    status: status,
                    session: this.data['session'].toInt32(),
                    payload: {
                        enc_rsa_key: {
                            'length': enc_rsa_key_length,
                            'key': enc_rsa_key
                        },
                        wrapped_rsa_key: {
                            'length': wrapped_rsa_key_length,
                            'key': wrapped_rsa_key
                        },
                        signature: {
                            'length': signature_length,
                            'signature': signature
                        },
                        message: {
                            'lenght': message_length,
                            'message': message
                        }
                    }
                };
                sender_payload(data)
            }

        }
    });
}

function byteArrayToHex(data) {
    var array = new Uint8Array(data);
    var result = '';
    for (var i = 0; i < array.length; ++i)
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    return result;
}

function sender_payload(data) {
    var encoded = new TextEncoder().encode(JSON.stringify(data));
    send('message', encoded);
}

function sender_payload_info(message) {
    send('message_info', new TextEncoder().encode(message))
}

const OEMCrypto_ProvisioningMethod  = {
    0: 'OEMCrypto_ProvisioningError',  // Device cannot be provisioned.
    1: 'OEMCrypto_DrmCertificate',     // Device has baked in DRM certificate
    // (level 3 only)
    2: 'OEMCrypto_Keybox',        // Device has factory installed unique keybox.
    3: 'OEMCrypto_OEMCertificate' // Device has factory installed OEM certificate.
};

const OEMCrypto_RSA_Support = {
    1: 'OEMCrypto_Supports_RSA_2048bit',
    2: 'OEMCrypto_Supports_RSA_3072bit',
    10: 'OEMCrypto_Supports_RSA_CAST'
};

const OEMCryptoResult = {
    0: 'OEMCrypto_SUCCESS',
    1: 'OEMCrypto_ERROR_INIT_FAILED',
    2: 'OEMCrypto_ERROR_TERMINATE_FAILED',
    3: 'OEMCrypto_ERROR_OPEN_FAILURE',
    4: 'OEMCrypto_ERROR_CLOSE_FAILURE',
    5: 'OEMCrypto_ERROR_ENTER_SECURE_PLAYBACK_FAILED',  // deprecated
    6: 'OEMCrypto_ERROR_EXIT_SECURE_PLAYBACK_FAILED',  // deprecated
    7: 'OEMCrypto_ERROR_SHORT_BUFFER',
    8: 'OEMCrypto_ERROR_NO_DEVICE_KEY',  // no keybox device key.
    9: 'OEMCrypto_ERROR_NO_ASSET_KEY',
    10: 'OEMCrypto_ERROR_KEYBOX_INVALID',
    11: 'OEMCrypto_ERROR_NO_KEYDATA',
    12: 'OEMCrypto_ERROR_NO_CW',
    13: 'OEMCrypto_ERROR_DECRYPT_FAILED',
    14: 'OEMCrypto_ERROR_WRITE_KEYBOX',
    15: 'OEMCrypto_ERROR_WRAP_KEYBOX',
    16: 'OEMCrypto_ERROR_BAD_MAGIC',
    17: 'OEMCrypto_ERROR_BAD_CRC',
    18: 'OEMCrypto_ERROR_NO_DEVICEID',
    19: 'OEMCrypto_ERROR_RNG_FAILED',
    20: 'OEMCrypto_ERROR_RNG_NOT_SUPPORTED',
    21: 'OEMCrypto_ERROR_SETUP',
    22: 'OEMCrypto_ERROR_OPEN_SESSION_FAILED',
    23: 'OEMCrypto_ERROR_CLOSE_SESSION_FAILED',
    24: 'OEMCrypto_ERROR_INVALID_SESSION',
    25: 'OEMCrypto_ERROR_NOT_IMPLEMENTED',
    26: 'OEMCrypto_ERROR_NO_CONTENT_KEY',
    27: 'OEMCrypto_ERROR_CONTROL_INVALID',
    28: 'OEMCrypto_ERROR_UNKNOWN_FAILURE',
    29: 'OEMCrypto_ERROR_INVALID_CONTEXT',
    30: 'OEMCrypto_ERROR_SIGNATURE_FAILURE',
    31: 'OEMCrypto_ERROR_TOO_MANY_SESSIONS',
    32: 'OEMCrypto_ERROR_INVALID_NONCE',
    33: 'OEMCrypto_ERROR_TOO_MANY_KEYS',
    34: 'OEMCrypto_ERROR_DEVICE_NOT_RSA_PROVISIONED',
    35: 'OEMCrypto_ERROR_INVALID_RSA_KEY',
    36: 'OEMCrypto_ERROR_KEY_EXPIRED',
    37: 'OEMCrypto_ERROR_INSUFFICIENT_RESOURCES',
    38: 'OEMCrypto_ERROR_INSUFFICIENT_HDCP',
    39: 'OEMCrypto_ERROR_BUFFER_TOO_LARGE',
    40: 'OEMCrypto_WARNING_GENERATION_SKEW',  // Warning, not an error.
    41: 'OEMCrypto_ERROR_GENERATION_SKEW',
    42: 'OEMCrypto_LOCAL_DISPLAY_ONLY',
    43: 'OEMCrypto_ERROR_ANALOG_OUTPUT',
    44: 'OEMCrypto_ERROR_WRONG_PST',
    45: 'OEMCrypto_ERROR_WRONG_KEYS',
    46: 'OEMCrypto_ERROR_MISSING_MASTER',
    47: 'OEMCrypto_ERROR_LICENSE_INACTIVE',
    48: 'OEMCrypto_ERROR_ENTRY_NEEDS_UPDATE',
    49: 'OEMCrypto_ERROR_ENTRY_IN_USE',
    50: 'OEMCrypto_ERROR_USAGE_TABLE_UNRECOVERABLE',  // Reserved. Do not use.
    51: 'OEMCrypto_KEY_NOT_LOADED',  // obsolete. use error 26.
    52: 'OEMCrypto_KEY_NOT_ENTITLED',
    53: 'OEMCrypto_ERROR_BAD_HASH',
    54: 'OEMCrypto_ERROR_OUTPUT_TOO_LARGE',
    55: 'OEMCrypto_ERROR_SESSION_LOST_STATE',
    56:'OEMCrypto_ERROR_SYSTEM_INVALIDATED',
};

const OEMCrypto_LicenseType = {
    0: 'OEMCrypto_ContentLicense',
    1: 'OEMCrypto_EntitlementLicense'
};

rpc.exports.inject = inject;

rpc.exports.widevinelibrary = containsLib;