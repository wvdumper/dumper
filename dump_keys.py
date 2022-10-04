#!/usr/bin/env python3

import time
import logging
from Helpers.Device import Device

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %I:%M:%S %p',
    level=logging.DEBUG,
)


def main():
    logger = logging.getLogger("main")
    device = Device()
    logger.info('Connected to %s', device.name)
    logger.info('Scanning all processes')

    for process in device.usb_device.enumerate_processes():
        if 'drm' in process.name:
            for library in device.find_widevine_process(process.name):
                device.hook_to_process(process.name, library)
    logger.info('Functions Hooked, load the DRM stream test on Bitmovin!')


if __name__ == '__main__':
    main()
    while True:
        time.sleep(1000)
