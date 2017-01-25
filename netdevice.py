"""
This module defines my NetDevice Class, offering inventory mgmt and wrappers for NetMiko functions
"""
from __future__ import unicode_literals
import logging
import sanitize
from getpass import getpass
from netmiko import ConnectHandler, NetmikoAuthError, NetmikoTimeoutError
import os
import errno
from contextlib import contextmanager
import traceback

# Module-level variables will go here
__version__ = '0.5.1'
__author__ = 'halfmetaljacket'
NM_AUTH_ERROR_LOG = 'Authentication error for device {}. Unable to connect.'
TIMEOUT_ERROR_LOG = 'Connection to {} timed out during {}.'
UNHANDLED_ERROR_LOG = 'Unhandled exception during {} {}.'
CONNECT_FIRST_WARNING = '.get_config() should only be called after .connect()'
CONNECT = 'Connecting to {}.'
SUCCESS_CONNECT = 'Connected to {} successfully.'
CONFIG_RETRIEVE = 'Retrieving config from {}.'
SUCCESS_RETRIEVE = 'Successfully retrieved config from {}.'
ENABLE = 'Entering {} enable mode.'
SUCCESS_ENABLE = 'Successfully entered {} enable mode.'
SEND_CMD = 'Sending command {} to {}.'
SUCCESS_SEND_CMD = 'Command successfully sent to {}.'
CONFIG_SAVE = 'Saving {} config.'
SUCCESS_CONFIG_SAVE = 'Successfully saved {} config.'
DISCONNECT = 'Disconnecting from {}.'
SUCCESS_DISCONNECT = 'Successfully disconnected from {}.'
DISCO_ERROR_IO = 'IOError while disconnecting from {}.'
DISCO_ERROR_UNKNOWN = 'Unknown error while disconnecting from {}.\n{}'
CONFIG_APPLY = 'Applying config to {}.'
SUCCESS_CONFIG_APPLY = 'Successfully applied config to {}.'
PARSE_CONFIG = 'Parsing {} config.'
SUCCESS_PARSE_CONFIG = 'Successfully parsed {} config.'
SITE_DIRECTORY_ERROR = 'Unable to create device {} site {} directory.\n{}'
CONFIG_ERROR = 'Exiting {} configuration with error'
OUTPUT_FILE_WRITE_ERROR = 'Unable to write {} output to file.\r\nFilename: {}\r\n{}'


class DeviceConnectionError(IOError):
    """Catch-all error for any exceptions thrown by NetMiko or Paramiko"""
    def __init__(self, msg, logger=None, log_trace=False):
        """exc_msg should be sys.exc_info from the source exception"""
        if log_trace:
            self.error = '{}\n{}'.format(msg, traceback.format_exc())
        else:
            self.error = msg
        if logger:
            logger.error(self.error)

    def __str__(self):
        return repr(self.error)


class DeviceAuthenticationError(DeviceConnectionError):
    """
    Sub-class of DeviceConnectionError. Can be used when a different action is necessary for authentication errors
    """


class NetDevice(object):
    """
    This class can be loaded for inventory mgmt and device CLI access, using the Netmiko library
    """
    def __init__(self, name, hostname='', ip='', site='', roles=None, user='', device_type='cisco_ios_ssh',
                 global_delay_factor=1, conn=None):
        """NetDevice is used when initializing a device from an inventory file, and is used for device CLI
        access via SSH, using the Netmiko library.

        Typical usage:
            json_attributes = json.load(attributes_from_file) # Use an inventory file to obtain parameters)
            device = NetDevice(**json_attributes)
            device.build_logger(my_module_logger, True, 'log-folder-path')
            try:
                device.connect(user, password, secret)
            except (DeviceConnectionError, NetmikoAuthError) as e:
                # do something with error
            try:
                output = device.get_config()
            except DeviceConnectionError as e:
                # do something with error
            finally:
                device.disconnect()
            # do stuff with output

        :param name str|unicode: Device Name
        :param hostname str|unicode: Device hostname
        :param ip str|unicode: Device IP Address
        :param site str|unicode: Site Name
        :param roles list|tuple: with elements of type str|unicode. Should be any of the following: ['access',
            'core', 'wan', 'datacenter'] (more to be added)
        :param user str|unicode: Optional Device login username
        :param device_type str|unicode: Netmiko device type, defaults to 'cisco_ios_ssh'. See Netmiko documentation
            for acceptable device types.
        :param global_delay_factor int: Positive integer passed to Netmiko global_delay_factor
        :param conn Netmiko ConnectClass|None: Optional existing Netmiko connection object
        :returns self:
        :raises DeviceConnectionError, NetmikoAuthError, TypeError: Raises NetmikoAuthError if authentication
            error during connect(), raises TypeError if invalid parameter passed to __init__(),
            raises DeviceConnectionError for all other Netmiko or connection-related errors
        """

        if type(name) == str or type(name) == unicode:
            self.name = name
        else:
            raise TypeError('name parameter has unexpected type. Got {}'.format(type(name)))
        if type(hostname) == str or type(hostname) == unicode:
            self.hostname = hostname
        else:
            raise TypeError('hostname parameter has unexpected type. Got {}'.format(type(name)))
        if type(ip) == str or type(ip) == unicode:
            self.ip = ip
        else:
            raise TypeError('ip parameter has unexpected type. Got {}'.format(type(name)))
        if type(site) == str or type(site) == unicode:
            self.site = site
        else:
            raise TypeError('site parameter has unexpected type. Got {}'.format(type(name)))
        if type(roles) == list:
            self.roles = roles
        else:
            self.roles = []
        if type(user) == str or type(user) == unicode:
            self.user = user
        else:
            self.user = ''
        self.device_type = device_type
        self.global_delay_factor = global_delay_factor
        self.directory_path = ''
        self.logger = None
        self.log_file_path = None
        self.conn = conn
        self.debug = False
        self.config_cache = None
        self.password = self.secret = None
        self._miko_dict = {}
        self._fh = self._sh = None

    def _build_miko_dict(self, user=None, passwd=None, secret=None):
        self._miko_dict['device_type'] = self.device_type
        if self.hostname:
            self._miko_dict['ip'] = self.hostname
        elif self.ip:
            self._miko_dict['ip'] = self.ip
        else:
            self.ip = sanitize.ip_address('Please enter the IP for {}: '.format(self.name))
            self._miko_dict['ip'] = self.ip
        if user:
            self._miko_dict['username'] = user
        elif self.user:
            self._miko_dict['username'] = self.user
        else:
            self._miko_dict['username'] = sanitize.username('Please enter the username for {}: '.format(self.name))
        if passwd:
            self._miko_dict['password'] = passwd
        elif self.password:
            self._miko_dict['password'] = self.password
        else:
            self._miko_dict['password'] = getpass('Please enter the password for {}: '.format(self.name))
        if secret:
            self._miko_dict['secret'] = secret
        elif self.secret:
            self._miko_dict['secret'] = self.secret
        else:
            self._miko_dict['secret'] = getpass('Please enter the secret for {}: '.format(self.name))
        self._miko_dict['timeout'] = 32

    def _select_delay_factor(self, delay_factor):
        if delay_factor >= self.global_delay_factor:
            return delay_factor
        else:
            return self.global_delay_factor

    def _check_conn(self):
        if not self.conn:
            raise UserWarning(CONNECT_FIRST_WARNING)

    def initialize(self, user, password, secret, parent_path=None, parent_logger=None, phase='initial_connection'):
        self.build_directory_path(parent_path)
        self.build_logger(parent_logger)
        self.connect(user, password, secret, phase)

    def build_directory_path(self, parent_path=None):
        if parent_path:
            site_path = os.path.join(parent_path, self.site)
        else:
            site_path = os.path.join(self.site)

        try:
            os.makedirs(site_path)
        except WindowsError as we:
            if we.winerror != 183:
                self.write_to_log(SITE_DIRECTORY_ERROR.format(self.name, site_path, traceback.format_exc()))
                self.directory_path = ''
                return
        except OSError:
            self.write_to_log(SITE_DIRECTORY_ERROR.format(self.name, site_path, traceback.format_exc()))
            self.directory_path = ''
            return
        self.directory_path = site_path

    def build_logger(self, parent_logger=None, file_handler=True, fh_path=None,
                     fh_level='DEBUG', log_format=None, stdout_handler=None, sh_level='INFO'):

        if parent_logger:
            self.logger = parent_logger.getChild(self.name.upper())
        else:
            self.logger = logging.getLogger(self.name.upper())
        self.logger.setLevel(logging.DEBUG)

        if log_format:
            lf = logging.Formatter(log_format)
        else:
            lf = logging.Formatter('%(asctime)s: %(levelname)-6s %(name)s:  %(message)s')

        if file_handler:
            if fh_path:
                self.log_file_path = os.path.join(fh_path, '{}_log.txt'.format(self.name))
            else:
                self.log_file_path = os.path.join(self.directory_path, '{}_log.txt'.format(self.name))
            self._fh = logging.FileHandler(self.log_file_path)
            self._fh.setFormatter(lf)
            try:
                self._fh.setLevel(getattr(logging, fh_level.upper()))
            except AttributeError:
                raise ValueError('Invalid log level: {}'.format(fh_level))
            self.logger.addHandler(self._fh)

        if stdout_handler:
            self._sh = logging.StreamHandler()
            self._sh.setFormatter(lf)
            try:
                self._sh.setLevel(getattr(logging, sh_level.upper()))
            except AttributeError:
                raise ValueError('Invalid log level: {}'.format(sh_level))
            self.logger.addHandler(self._sh)

        return self.logger

    def write_to_log(self, msg, level='DEBUG'):
        if self.logger:
            self.logger.log(getattr(logging, level.upper()), msg)

    def connect(self, user=None, password=None, secret=None, phase='initial_connection'):
        if not self.conn:
            if not self._miko_dict:
                self._build_miko_dict(user, password, secret)
            self.write_to_log(CONNECT.format(self.name))
            try:
                self.conn = ConnectHandler(**self._miko_dict)
                self.write_to_log(SUCCESS_CONNECT.format(self.name), 'INFO')
                return self.conn
            except NetmikoAuthError as e:
                raise DeviceAuthenticationError(NM_AUTH_ERROR_LOG.format(self.name), self.logger)
            except (NetmikoTimeoutError, IOError):
                raise DeviceConnectionError(TIMEOUT_ERROR_LOG.format(self.name, phase), self.logger)
            except:
                # Handle unknown errors as DeviceConnectionError
                raise DeviceConnectionError(UNHANDLED_ERROR_LOG.format(self.name, phase), self.logger, log_trace=True)

    def enable(self):
        phase = 'entering enable mode'
        if not self.conn:
            raise UserWarning(CONNECT_FIRST_WARNING)
        try:
            # Enter enable mode if not already there, raise error if unable to do so
            if not self.conn.check_enable_mode():
                self.write_to_log(ENABLE.format(self.name))
                self.conn.enable()
                self.write_to_log(SUCCESS_ENABLE.format(self.name))
        except ValueError:
            # Invalid creds is the most likely, but not only, cause.
            # Netmiko's .enable() error handling needs to be improved.
            raise DeviceConnectionError('Invalid enable secret credentials for {}'.format(self.name), self.logger)
        except IOError:
            raise DeviceConnectionError(TIMEOUT_ERROR_LOG.format(self.name, phase), self.logger)

    def send_command(self, cmd, enable=True, delay_factor=1, phase='send_command', disco_on_fail=True, **kwargs):
        delay_factor = self._select_delay_factor(delay_factor)
        self._check_conn()
        self.write_to_log(SEND_CMD.format(cmd, self.name))
        if enable:
            self.enable()
        try:
            output = self.conn.send_command(command_string=cmd, delay_factor=delay_factor, **kwargs)
            self.write_to_log(SUCCESS_SEND_CMD.format(self.name))
            return output
        except IOError:
            if disco_on_fail:
                self.disconnect()
            raise DeviceConnectionError(TIMEOUT_ERROR_LOG.format(self.name, phase), self.logger)

    def get_config(self, cmd='show run', delay_factor=4, phase='config retrieval',
                   use_cache=False, disco_on_fail=True, **kwargs):
        delay_factor = self._select_delay_factor(delay_factor)
        if use_cache and self.config_cache:
            return self.config_cache
        self._check_conn()
        self.write_to_log(CONFIG_RETRIEVE.format(self.name))
        self.enable()
        try:
            # Now retrieve the config with extra delay factor, raise error if unable to do so
            self.config_cache = self.conn.send_command(command_string=cmd, delay_factor=delay_factor, **kwargs)
            self.write_to_log(SUCCESS_RETRIEVE.format(self.name), 'INFO')
            return self.config_cache
        except IOError:
            if disco_on_fail:
                self.disconnect()
            raise DeviceConnectionError(TIMEOUT_ERROR_LOG.format(self.name, phase), self.logger)

    def save_config(self, cmd='copy running-config startup-config\n\n', delay_factor=4,
                    phase='config save', disco_on_fail=True, **kwargs):
        delay_factor = self._select_delay_factor(delay_factor)
        self._check_conn()
        self.write_to_log(CONFIG_SAVE.format(self.name))
        self.enable()
        try:
            output = self.conn.base_prompt + '#'
            output += self.conn.send_command_timing(command_string=cmd, delay_factor=1, max_loops=2,
                                                    strip_prompt=False, strip_command=False, **kwargs)
            output += self.conn.send_command(command_string='\n\n', delay_factor=delay_factor, auto_find_prompt=False,
                                             strip_prompt=False, strip_command=False)
            self.write_to_log(SUCCESS_CONFIG_SAVE.format(self.name), 'INFO')
            return output
        except IOError:
            if disco_on_fail:
                self.disconnect()
            raise DeviceConnectionError(TIMEOUT_ERROR_LOG.format(self.name, phase), self.logger, True)

    def apply_config(self, config_commands, save_config=False, phase='applying config', disco_on_fail=True, **kwargs):
        self._check_conn()
        self.write_to_log(CONFIG_APPLY.format(self.name))
        try:
            output = self.conn.send_config_set(config_commands, **kwargs)
            self.write_to_log(SUCCESS_CONFIG_APPLY.format(self.name))
        except IOError:
            if disco_on_fail:
                self.disconnect()
            raise DeviceConnectionError(TIMEOUT_ERROR_LOG.format(self.name, phase), self.logger, True)
        if save_config:
            output += self.save_config()
        return output

    def parse_config(self, force_get_config=False):
        from ciscoconfparse import CiscoConfParse
        if not self.config_cache or force_get_config:
            config = self.get_config()
        else:
            config = self.config_cache
        self.write_to_log(PARSE_CONFIG.format(self.name))
        cisco_config = CiscoConfParse(unicode(config).splitlines(True))
        self.write_to_log(SUCCESS_PARSE_CONFIG.format(self.name))
        return cisco_config

    @contextmanager
    def quick_connect(self, user=None, password=None, secret=None):
        """Executes self.connect, returning the Netmiko object, disconnecting when finished"""
        self.build_logger(file_handler=True, fh_level='DEBUG', stdout_handler=True, sh_level='DEBUG')
        self.connect(user, password, secret)
        yield self
        self.disconnect()

    def disconnect(self):
        """NOTE: This method suppresses all exceptions"""
        if self.conn:
            try:
                self.write_to_log(DISCONNECT.format(self.name))
                self.conn.disconnect()
                self.write_to_log(SUCCESS_DISCONNECT.format(self.name), 'INFO')
            except IOError:
                self.write_to_log(DISCO_ERROR_IO.format(self.name))
            except StandardError:
                self.write_to_log(DISCO_ERROR_UNKNOWN.format(self.name, traceback.format_exc()))


def test_net_device(name='SGH-Spare.phs.org', hostname='sgh-spare.phs.org', ip='10.131.250.16',
                    site='SGH', roles=('access',), user='mrose3'):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--password', default=None)
    parser.add_argument('-s', '--secret', default=None)
    args = parser.parse_args()
    my_device = NetDevice(name, hostname, ip, site, roles, user)
    my_device.password = args.password
    my_device.secret = args.secret

    with my_device.quick_connect(user, args.password, args.secret) as device:
        device.enable()
        output = device.save_config()
        print output

if __name__ == '__main__':
    test_net_device()
