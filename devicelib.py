from __future__ import unicode_literals
import json
from netdevice import NetDevice

__version__ = '1.0.0'
__author__ = 'halfmetaljacket'


class __CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, NetDevice):
            return obj.__dict__
        return json.JSONEncoder.default(self, obj)


def build_device_library(device_list='device_list.cfg'):
    if not device_list:
        device_list = 'device_list.cfg'
    try:
        # print 'opening file...'
        with open(device_list, 'r') as f:
            # print 'json loading...'
            json_list = json.load(f)
    except IOError as e:
        # print 'File open or json load failed:\n:{}'.format(str(e))
        return None
    else:
        # print 'Building device library...'
        device_list = [NetDevice(**item) for item in json_list]
        return device_list

if __name__ == '__main__':
    print 'running build_dev_lib() with default parameters'
    l = build_device_library()
    assert isinstance(l, list)
