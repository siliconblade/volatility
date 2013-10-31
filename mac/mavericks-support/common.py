# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""

import volatility.commands as commands
import volatility.utils as utils
import volatility.obj as obj

def set_plugin_members(obj_ref):
    obj_ref.addr_space = utils.load_as(obj_ref._config)

class AbstractMacCommand(commands.Command):
    def __init__(self, *args, **kwargs):
        self.addr_space = None
        commands.Command.__init__(self, *args, **kwargs)

    @property
    def profile(self):
        if self.addr_space:
            return self.addr_space.profile
        return None

    def execute(self, *args, **kwargs):
        commands.Command.execute(self, *args, **kwargs)

    @staticmethod
    def register_options(config):
        config.add_option("SHIFT", type = 'int', default = 0, help = "Mac KASLR shift address")

    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'Unknown').lower() == 'mac'

def is_known_address(handler, kernel_symbol_addresses, kmods):
    # see if this handler is in a known location
    good = 0 

    handler = handler.v()

    if handler in kernel_symbol_addresses:
        good = 1     
    else:
        # see if the address fits in any of the known modules
        for (start, end, name) in kmods:
            if start <= handler <= end:
                good = 1
                break
    return good

def is_64bit_capable(addr_space):
    """Test if the AS is capable of doing 64-bits. 

    @returns True if 64-bit capable. 
    """
    # OS X MAVERICKS
    model = addr_space.profile.metadata.get('memory_model', 0)
    return model == '64bit'

def get_kernel_addrs(obj_ref):
    import volatility.plugins.mac.lsmod as lsmod
    # all the known addresses in the kernel
    # TODO -- make more stringent and get only symbols from .text
    kernel_symbol_addresses = obj_ref.profile.get_all_addresses()
    
    # module addresses, tuple of (start, end)
    # TODO -- make sure more stringent and parse each kext in-memory so we only allow whitelist from .text
    kmods = [(kmod.address, kmod.address + kmod.m('size'), kmod.name) for kmod in lsmod.mac_lsmod(obj_ref._config).calculate()] 

    return (kernel_symbol_addresses, kmods)

## FIXME: remove this function after all references from plugins are removed
def get_string(addr, addr_space, maxlen = 256):

    name = addr_space.read(addr, maxlen)
    ret = ""

    for n in name:
        if ord(n) == 0:
            break
        ret = ret + n 

    return ret 

# account for c++ symbol name mangling
def get_cpp_sym(name, profile):
    for (cppname, addr) in profile.get_all_symbols():
        if cppname.find(name) != -1:
            return addr

    return None
