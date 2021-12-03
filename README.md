# Dumper

Dumper is a Frida script to dump L3 CDMs from any Android device.

## Dependencies

Use pip to install the dependencies:

`pip3 install -r requirements.txt`

## Usage

* Enable USB debugging
* Start frida-server on the device
* Execute dump_keys.py
* Start streaming some DRM-protected content

## Temporary disabling L1 to use L3 instead
A few phone brands let us use the L1 keybox even after unlocking the bootloader (like Xiaomi). In this case, installation of a Magisk module called [liboemcrypto-disabler](https://github.com/umylive/liboemcrypto-disabler) is necessary.

## Known issues
It seems like Google made some changes in their OEMCrypto library and it broke the script. Further investigation is needed to make it work on Android 11+, feel free to open PRs.

## Credits
Thanks to the original author of the code.
