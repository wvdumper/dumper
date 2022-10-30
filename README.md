# Dumper

Dumper is a Frida script to dump L3 CDMs from any Android device.

## ** IMPORTANT **
The function parameters can differ between CDM versions. The default is [4] but you may have to change this for your specific version.

* `CDM_VERSION` can be retrieved using a DRM Info app.

## Requirements:
Use pip to install the dependencies:

`pip3 install -r requirements.txt`

## Usage:

* Enable USB debugging
* Start frida-server on the device
* Execute dump_keys.py
* Start streaming some DRM-protected content

The script will hook every function in your 'libwvhidl.so' module by default, effectively brute forcing the private key function name.
```
python3 .\dump_keys.py [OPTIONS]
```

You can pass the function name to hook using the `--function-name` argument.
```
python3 .\dump_keys.py --function-name 'polorucp'
```

The script defaults to `args[4]` if no `--cdm-version` is provided. This will only have an effect if your version is `16.1.0`.

```
python3 .\dump_keys.py --cdm-version '16.1.0'
```

## Options:
```
    -h, --help                      Print this help text and exit.
    --cdm-version                   The CDM version of the device e.g. '16.1.0'.
    --function-name                 The name of the function to hook to retrieve the private key.
```

## Known Working Versions:
* Android 9
    * CDM 14.0.0
* Android 10
    * CDM 15.0.0
* Android 11
    * CDM 16.0.0
* Android 12
    * CDM 16.1.0

## Temporary disabling L1 to use L3 instead
A few phone brands let us use the L1 keybox even after unlocking the bootloader (like Xiaomi). In this case, installation of a Magisk module called [liboemcrypto-disabler](https://github.com/umylive/liboemcrypto-disabler) is necessary.

## Credits
Thanks to the original author of the code.
