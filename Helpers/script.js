const DYNAMIC_FUNCTION_NAME = '${DYNAMIC_FUNCTION_NAME}';
const CDM_VERSION = '${CDM_VERSION}';

// These strings are function names that have been succesfully dumped.
const KNOWN_DYNAMIC_FUNCTION_NAMES = [
    'rnmsglvj',
    'polorucp',
    'kqzqahjq',
    'pldrclfq',
    'kgaitijd',
    'dnvffnze',
    'cwkfcplc',
    'crhqcdet'
];

// The TextEncoder/Decoder API isn't supported so it has to be polyfilled.
// Taken from https://gist.github.com/Yaffle/5458286#file-textencodertextdecoder-js
function TextEncoder() {
}

TextEncoder.prototype.encode = function (string) {
    var octets = [];
    var length = string.length;
    var i = 0;
    while (i < length) {
        var codePoint = string.codePointAt(i);
        var c = 0;
        var bits = 0;
        if (codePoint <= 0x0000007F) {
            c = 0;
            bits = 0x00;
        } else if (codePoint <= 0x000007FF) {
            c = 6;
            bits = 0xC0;
        } else if (codePoint <= 0x0000FFFF) {
            c = 12;
            bits = 0xE0;
        } else if (codePoint <= 0x001FFFFF) {
            c = 18;
            bits = 0xF0;
        }
        octets.push(bits | (codePoint >> c));
        c -= 6;
        while (c >= 0) {
            octets.push(0x80 | ((codePoint >> c) & 0x3F));
            c -= 6;
        }
        i += codePoint >= 0x10000 ? 2 : 1;
    }
    return octets;
}

function getPrivateKey(address) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            if (!args[6].isNull()) {
                const size = args[6].toInt32();
                if (size >= 1000 && size <= 2000 && !args[5].isNull()) {
                    const buf = args[5].readByteArray(size);
                    const bytes = new Uint8Array(buf);
                    // The first two bytes of the DER encoding are 0x30 and 0x82 (MII).
                    if (bytes[0] === 0x30 && bytes[1] === 0x82) {
                        try {
                            const binaryString = a2bs(bytes)
                            const keyLength = getKeyLength(binaryString);
                            const key = bytes.slice(0, keyLength);
                            send('private_key', key);
                        } catch (error) {
                            console.log(error)
                        }
                    }
                }
            }
        }
    });
}

// nop privacy mode.
// PrivacyMode encrypts the payload with the public key returned by the license server which we don't want.
function disablePrivacyMode(address) {
    Interceptor.attach(address, {
        onLeave: function (retval) {
            retval.replace(ptr(0));
        }
    });
}

function prepareKeyRequest(address) {
    Interceptor.attach(ptr(address), {
        onEnter: function (args) {
            switch (CDM_VERSION) {
                case '14.0.0':
                case '15.0.0':
                case '16.0.0':
                    this.ret = args[4];
                    break;
                case '16.1.0':
                case '17.0.0':
                    this.ret = args[5];
                    break;
                default:
                    const message = 'Defaulting to args[4] for PrepareKeyRequest.'
                    send('message_info', new TextEncoder().encode(message));
                    this.ret = args[4];
                    break;
            }
        },
        onLeave: function () {
            if (this.ret) {
                const size = Memory.readU32(ptr(this.ret).add(Process.pointerSize))
                const arr = Memory.readByteArray(this.ret.add(Process.pointerSize * 2).readPointer(), size)
                send('device_info', arr);
            }
        }
    });
}

function hookLibFunctions(lib) {
    const name = lib['name'];
    const baseAddr = lib['base'];
    let message = 'Hooking ' + name + ' at ' + baseAddr;
    let hookedProvidedModule = false;
    let funcNames = [];

    send('message_info', new TextEncoder().encode(message));

    Module.enumerateExportsSync(name).forEach(function (module) {
        try {
            let hookedModule;
            if (module.name.includes('UsePrivacyMode')) {
                disablePrivacyMode(module.address);
                hookedModule = module.name;
            } else if (module.name.includes('PrepareKeyRequest')) {
                prepareKeyRequest(module.address);
                hookedModule = module.name;
            } else if (DYNAMIC_FUNCTION_NAME !== '' && module.name.includes(DYNAMIC_FUNCTION_NAME)) {
                getPrivateKey(module.address);
                hookedModule = module.name;
                hookedProvidedModule = true;
            } else if (DYNAMIC_FUNCTION_NAME === '' && module.name.match(/^[a-z]+$/)) {
                getPrivateKey(module.address);
                hookedModule = module.name;
                funcNames.push(hookedModule);
            }

            if (hookedModule) {
                const message = 'Hooked ' + hookedModule + ' at ' + module.address;
                send('message_info', new TextEncoder().encode(message));
            }
        } catch (e) {
            console.log("Error: " + e + " at F: " + module.name);
        }
    });

    if (DYNAMIC_FUNCTION_NAME !== '' && !hookedProvidedModule) {
        const message = "Unable to find '" + DYNAMIC_FUNCTION_NAME + "'";
        send('message_info', new TextEncoder().encode(message));
    }

    if (DYNAMIC_FUNCTION_NAME === '') {
        const possibleFuncNames = KNOWN_DYNAMIC_FUNCTION_NAMES.filter(x => funcNames.includes(x));
        if (possibleFuncNames.length) {
            message = "Your function name is most likely: " + "'" + possibleFuncNames.join('\', \'') + "'";
            send('message_info', new TextEncoder().encode(message));
        }
    }
}

function getModuleByName(lib) {
    return Process.getModuleByName(lib);
}

function a2bs(bytes) {
    let b = '';
    for (let i = 0; i < bytes.byteLength; i++)
        b += String.fromCharCode(bytes[i]);
    return b
}

function getKeyLength(key) {
    let pos = 1 // Skip the tag
    let buf = key.charCodeAt(pos++);
    let len = buf & 0x7F; // Short tag length

    buf = 0;
    for (let i = 0; i < len; ++i)
        buf = (buf * 256) + key.charCodeAt(pos++);
    return pos + Math.abs(buf);
}

rpc.exports.hooklibfunctions = hookLibFunctions;
rpc.exports.getmodulebyname = getModuleByName;
