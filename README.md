# Dumper

Dumper is a Frida script to dump L3 CDMs from any Android device.

## ** IMPORTANT **
The function parameters can differ between CDM versions. The default is [4] but you may have to change this for your specific version.

* `CDM_VERSION` can be retrieved using a DRM Info app.

## Requirements
Use pip to install the dependencies:

`pip3 install -r requirements.txt`

## Usage

* Enable USB debugging
* Start frida-server on the device
* Execute dump_keys.py
* Start streaming some DRM-protected content

## Known Working Versions
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
