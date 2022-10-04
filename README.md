# Dumper

Dumper is a Frida script to dump L3 CDMs from any Android device.

## ** IMPORTANT **
You MUST update `DYNAMIC_FUNCTION_NAME` and `CDM_VERSION` in `script.js` to the relevant values for your device.

* `CDM_VERSION` can be retrieved using a DRM Info app.
* `DYNAMIC_FUNCTION_NAME` value is unique to your device and can be found in the file `libwvhidl.so` on your device.

If you've managed to get as far as updating `DYNAMIC_FUNCTION_NAME` but can't find your function name, create an issue and provide me with your `libwvhidl.so` file and I will give you the function name you need.

## Requirements
Use pip to install the dependencies:

`pip3 install -r requirements.txt`

## Usage

* Enable USB debugging
* Start frida-server on the device
* Execute dump_keys.py
* Start streaming some DRM-protected content

## Known Working Versions
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
