# Volatility
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

"""
@author:       Cem Gurkok
@license:      GNU General Public License 2.0 or later
@contact:      cemgurkok@gmail.com
"""

import binascii
import volatility.obj as obj
import common
import volatility.plugins.mac.check_trap_table as trap

class mac_check_dtrace(common.AbstractMacCommand):
    """ Checks to see if dtrace probes are present """

    def calculate(self):
        args = ()
        common.set_plugin_members(self)

        sym_addrs = self.profile.get_all_addresses()

        nsysent = obj.Object("int", offset = self.addr_space.profile.get_symbol("_nsysent"), vm = self.addr_space)
        sysents = obj.Object(theType = "Array", offset = self.addr_space.profile.get_symbol("_sysent"), vm = self.addr_space, count = nsysent, targetType = "sysent")

        for (i, sysent) in enumerate(sysents):
            hooked = False
            ent_addr = sysent.sy_call.v()
            syscall_name = self.profile.get_symbol_by_address("kernel", ent_addr)
            if 'dtrace' in syscall_name:
                # syscall probes: http://siliconblade.blogspot.com/2013/04/hunting-d-trace-rootkits-with.html
                hooked = "syscall_probe"
            else:
                # fbt probes: http://reverse.put.as/2013/05/07/syscan13-revisiting-mac-os-x-rootkits-presentation/
                data = sysent.obj_vm.zread(ent_addr + 1, 2)
                if binascii.hexlify(data) == 'f089':
                    hooked = 'fbt_probe'
                 
            if hooked != False:
                yield ('Syscall_Table', i, ent_addr, syscall_name, hooked)

        # mach_trap probes: http://felinemenace.org/~nemo/dtrace-infiltrate.pdf
        t = trap.mac_check_trap_table(self._config, args)
        for (table_addr, table_name, index, call_addr, sym_name, other_hooked) in t.calculate():
            if other_hooked == True:
                sym_name = "HOOKED"

            if 'dtrace' in sym_name:
                hooked = "mach_trap_probe"
                yield ('Trap_Table', index, call_addr, sym_name, hooked)
 
    def render_text(self, outfd, data):
        self.table_header(outfd, [("Table Name", "15"), ("Index", "<6"), ("Address", "[addrpad]"), ("Symbol", "<30"), ("D-Trace Probe", "<15")])
        for (table_name, i, call_addr, sym_name, hooked) in data:
            self.table_row(outfd, table_name, i, call_addr, sym_name, hooked)



