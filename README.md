# Dumper

Dumper is a Frida script to dump L3 CDMs from any Android device.

## ** IMPORTANT **
The function parameters can differ between CDM versions. The default is [4] but you may have to change this for your specific version in the [script.js](./Helpers/script.js).

## Prerequisites
- Rooted Android device
- [Installed Frida server on the Android device]((https://frida.re/docs/android/))
- Installed [platform-tools ADB/Fastboot](https://developer.android.com/studio/releases/platform-tools) on the PC
- Installed [Python 3](https://www.python.org/downloads/) on the PC
- `CDM_VERSION` retrieved from the [DRM Info app](https://play.google.com/store/apps/details?id=com.androidfung.drminfo).

## Requirements:
Use pip to install the dependencies:

`pip3 install -r requirements.txt`

## Usage:

* Enable USB debugging on the Android device and connect it to the PC
* [Start frida-server on the Android device](https://frida.re/docs/android/)
* Execute dump_keys.py on the PC
* Start streaming some DRM-protected content on the Android device e.g. [Bitmovin](https://bitmovin.com/demos/drm)

The script will hook every function in your widevine 'libwvhidl.so'/'libwvaidl.so' modules by default, effectively brute forcing the private key function name.
```
python3 dump_keys.py
```

You can pass the function name to hook using the `--function-name` argument. You can use [this post](https://forum.videohelp.com/threads/404219-How-To-Dump-L3-CDM-From-Android-Device-s-(ONLY-Talk-About-Dumping-L3-CDMS)/page6#post2646150) to retrive it by yourself.
```
python3 dump_keys.py --function-name 'polorucp'
```

The script defaults to `args[4]` if no `--cdm-version` is provided. This will only have an effect if your version is `16.1.0` or `17.0.0`.

```
python3 dump_keys.py --cdm-version '16.1.0'
```

You can pass the `.so` -module name using the `--module-name` argument. By default it looks in the `libwvhidl.so` and `libwvaidl.so` files. It can have multiple values. Its name can change depending on the version and SoC including but not limited to: `libwvaidl.so`, `libwvhidl.so`, `libwvdrmengine.so`, `libwvm.so`, `libdrmwvmplugin.so` [source](https://arxiv.org/abs/2204.09298). You can find your module name in the /vendor/lib64/ or /vendor/lib/ directories using an ADB shell.

```
python3 dump_keys.py --module-name 'libwvhidl.so' --module-name 'libwvaidl.so'
```


## Options:
```
    -h, --help                      Print this help text and exit.
    --cdm-version                   The CDM version of the device e.g. '16.1.0'.
    --function-name                 The name of the function to hook to retrieve the private key.
    --module-name                   The name of the widevine `.so` modules.
```

## Scenario:
1. You've got the function name
2. You've got the private key
3. Client ID extracted
4. Script closed

The following files will be created after a successful dump:
- `client_id.bin` - Device identification
- `private_key.pem` - RSA private key

## Known Working Versions:
* Android 9
    * CDM 14.0.0
* Android 10
    * CDM 15.0.0
* Android 11
    * CDM 16.0.0
* Android 12
    * CDM 16.1.0
* Android 13
    * CDM 17.0.0

## Temporary disabling L1 to use L3 instead
A few phone brands let us use the L1 keybox even after unlocking the bootloader (like Xiaomi). In this case, installation of a Magisk module called [liboemcrypto-disabler](https://github.com/umylive/liboemcrypto-disabler) is necessary.

## Credits
Thanks to the original author of the code.
