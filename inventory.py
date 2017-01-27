"""Main Inventory Package"""
import yaml
import json
# TODO: yaml supersets json, so adjust to always yaml.load() instead of deciding
"""
Notes: ansible is top-down (groups define their hosts). I want to be the other way around.
The critical aspect of this is that almost all work is done on the host,
but that means that the host needs to get all group data any time it looks for something.
Need to figure out how to implement var_cache for this. Or do I?
Need to seriously consider to permanantly specialize group types (site/role/etc) and if so, how to handle var collision when multiple parents of the same type are selected
Need to figure out the best method for handling when a device or group comfig changes.
Need to figure out how to dump inventory files after changes are made.
"""

class Inventory(object):
    def __init__(self, inventory_file, file_type='yaml'):
        self.file_type = file_type
        if file_type == 'yaml':
            with open(inventory_file) as f:
                self.inventory_file = yaml.load(f)

        self.groups = {}
        self.devices = {}

        for device_name, device_config in self.inventory_file['devices'].items():
            self.load_device(device_name, device_config)

    def load_device(self, name, device_init):
        device_group_names = []
        device_config_lines = []
        device_config_variables = []
        device_name = name
        if 'device_file' in device_init:
            # parse device file here and return information
            pass
        device_group_names.extend(device_init['member of'])
        device_config_variables.extend(device_init['config variables'])
        device_config_lines.extend(device_init['config lines'])

        for group_name in device_group_names:
            group = self.load_group(group_name, self.inventory_file['groups'][group_name])

    def load_group(self, group_name, group_init):
        group_file = group_init['group_file']
        with open('group_file') as f:
            group_config = yaml.load(f)
        # handle nested groups
        if 'member of' in group_config:
            for nested_group_name in group_config['member of']:
                parent_group = self.load_group(nested_group_name, self.inventory_file['groups'][nested_group_name])
        group = Group(group_name, group_config)
        self.groups[group_name] = group
        return group


class Group(object):
    def __init__(self, name, group_config):
        self.name = name
        self.group_type = group_config['group type']
        self.config_variables = group_config['config variables']
        self.vars = group_config['vars'] if 'vars' in group_config else {}
        self.config_lines = group_config['config lines'] if 'config lines' in group_config else []
        self.member_of = group_config['key'] if 'key' in group_config else {}

        self.my_devices = {}
        self.devices_cache = {}
        self.child_groups = {}