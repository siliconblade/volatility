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
@organization: 
"""

import volatility.obj as obj
import volatility.commands as commands
import common
import distorm3

class mac_check_shadow_trustedbsd(common.AbstractMacCommand):
    """ Checks to see if trustedbsd policy is shadowed """

    def __init__(self, config, *args, **kwargs):
        self.addr_space = None
        commands.Command.__init__(self, config, *args, **kwargs)
        
    def calculate(self):
        common.set_plugin_members(self)

        model = self.addr_space.profile.metadata.get('memory_model', 0)
        if model == '32bit':
            distorm_mode = distorm3.Decode32Bits
        else:
            distorm_mode = distorm3.Decode64Bits

        # get kernel start, end
        kp = self.addr_space.profile.get_symbol("_g_kernel_kmod_info")
        kmodk = obj.Object("kmod_info", offset = kp, vm = self.addr_space)
        k_start = kmodk.address
        k_end = k_start + kmodk.m('size')
  
        # check if trustedbsd mac_policy_list is shadowed
        is_shadowed = False
        shadow_addr = None

        # some functions with MAC_CHECK/mac_policy_list references: mac_proc_check_get_task_name, mac_proc_check_get_task, mac_proc_check_fork, mac_cred_check_label_update, mac_cred_check_visible, mac_proc_check_debug, mac_proc_check_run_cs_invalid, mac_proc_check_sched, mac_proc_check_signal, mac_proc_check_wait, mac_proc_check_setlcid, mac_proc_check_getlcid, mac_lctx_check_label_update, mac_proc_check_suspend_resume, mac_port_check_service, mac_port_label_compute, mac_file_check_create, mac_file_check_dup, mac_file_check_fcntl, mac_file_check_ioctl, mac_file_check_inherit, mac_file_check_receive, mac_file_check_get_offset, mac_file_check_change_offset, mac_file_check_get, mac_file_check_set, mac_file_check_lock, mac_file_check_mmap
        original_mpl_addr = self.addr_space.profile.get_symbol("_mac_policy_list")
        original_mpl = obj.Object("mac_policy_list", offset = original_mpl_addr, vm = self.addr_space)

        # to get the disassembly of MAC_CHECK, disassemble mac_proc_check_get_task since targeted by REX [http://reverse.put.as/2014/03/18/teaching-rex-another-trustedbsd-trick-to-hide-from-volatility/]
        func_addr = self.addr_space.profile.get_symbol('_mac_proc_check_get_task')
        content = self.addr_space.read(func_addr, 1024)
        op_prev = None
        for op in distorm3.Decompose(func_addr, content, distorm_mode):
            if not op.valid or (op.mnemonic == 'NOP' and op_prev.mnemonic == "RET"):
                break

            if model == "64bit":
                if op.mnemonic == 'LEA' and op.operands[0].type == 'Register' and op.operands[0].name in ['RDI','RAX','R13','RSP','RBX','R12','R13','R14','R15']:
                    curr_mpl_addr = op.address + op.operands[1].disp + op.size
                    curr_mpl = obj.Object("mac_policy_list", offset = curr_mpl_addr, vm = self.addr_space)
                    # check if mac_policy_list address and mac_policy_list.entries address have changed
                    if curr_mpl_addr != original_mpl_addr or original_mpl.entries.v() != curr_mpl.entries.v():
                        is_shadowed = True
                        shadow_addr = curr_mpl_addr
                        yield(original_mpl_addr, shadow_addr, op.address)
                        print "mac_policy_address is shadowed! Original Address: {0:#10x}, Shadow Address: {1:#10x}, Modification at: {2:#10x}".format(original_mpl_addr, shadow_addr, op.address)
                        break
            elif model == "32bit":
                if op.mnemonic == 'MOV' and op.operands[0].type == 'Register' and op.operands[0].name in ['EAX'] and op.operands[1].type == 'AbsoluteMemoryAddress':
                    curr_mpl_entries_addr = op.operands[1].disp
                    # check if mac_policy_list.entries address has changed
                    if curr_mpl_entries_addr != original_mpl.entries.v():
                        is_shadowed = True
                        shadow_addr = curr_mpl_entries_addr
			yield (original_mpl.entries.v(), shadow_addr, op.address)
                        print "mac_policy_address is shadowed! Original Entries Address: {0:#10x}, Shadow Entries Address: {1:#10x}, Modification at: {2:#10x}".format(original_mpl.entries.v(), shadow_addr, op.address)
                        break              
            op_prev = op

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Table Name", "<50"), ("Original Address", "[addrpad]"), ("Shadow Address", "[addrpad]"), ("OP Code Address", "[addrpad]")])
        for (original_mpl_addr, shadow_addr, op_address) in data:
            self.table_row(outfd, "TrustedBSD", original_mpl_addr, shadow_addr, op_address)



