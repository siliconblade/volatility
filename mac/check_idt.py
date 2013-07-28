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
import sys
import volatility.obj as obj
import volatility.plugins.mac.lsmod as modules
import common
import distorm3, binascii

# Kernel descriptors for MACH xnu-1504.9.26/osfmk/i386/seg.h
dict_seg64 = {0x08: "KERNEL64_CS", 0x0b: "SYSENTER_CS", 0x1b: "USER_CS", 0x2b: "USER64_CS", 0x50: "KERNEL32_CS", 0x8f: "SYSCALL_CS", 0x80: "KERNEL_DS"}

class mac_check_idt(common.AbstractMacCommand):
    """ Checks to see if IDT entries are hooked """

    def findKextWithAddress(self, addr):
        # function to find what kext the given address lies within
        kexts = []
        #get kernel kext
        kp = self.addr_space.profile.get_symbol("_g_kernel_kmod_info")
        kmodk = obj.Object("kmod_info", offset = kp, vm = self.addr_space)
        kexts.append(kmodk)

        # get other kexts
        p = self.addr_space.profile.get_symbol("_kmod")
        kmodaddr = obj.Object("Pointer", offset = p, vm = self.addr_space)
        kmod = kmodaddr.dereference_as("kmod_info")
        while kmod.is_valid():
            kexts.append(kmod)
            kmod = kmod.next

        for kext in kexts:
            if addr >= kext.address and addr <= (kext.address + kext.m('size')):
                return kext.name
        return "UNKNOWN"

    def calculate(self):
        common.set_plugin_members(self)
        args = ()

        memory_model = self.addr_space.profile.metadata.get('memory_model', 0)
        if memory_model == '32bit':
            distorm_mode = distorm3.Decode32Bits
            master_idt_type = "_master_idt64"
            idt_type = "real_gate64"
        else:
            idt_type = "real_gate64"
            distorm_mode = distorm3.Decode64Bits
            master_idt_type = "_master_idt64"

        sym_addrs = self.profile.get_all_addresses()

        # size of idt table is 256 so far
        IDTSZ = 256

        # get number of cpus
        real_ncpus = obj.Object("int", offset = self.addr_space.profile.get_symbol("_real_ncpus"), vm = self.addr_space)

        # get cpu_data_ptr/cpu_data array addresses
	cpu_data_ptrs = obj.Object(theType = 'Array', offset = self.addr_space.profile.get_symbol("_cpu_data_ptr"), vm = self.addr_space, targetType = "unsigned long long", count = real_ncpus)

        # master_idt not in cpu_desc_table so use the symbol instead: http://www.opensource.apple.com/source/xnu/xnu-1699.24.8/osfmk/i386/mp_desc.c
        master_idt_addr = self.addr_space.profile.get_symbol(master_idt_type)

        for i in range(0, real_ncpus -1):
            # for master cpu, use master_idt_addr
            if i == 0:
                idt_addr = master_idt_addr
            else:
                if memory_model == "32bit":
                    break

                cpu_data = obj.Object('cpu_data', offset = cpu_data_ptrs[i], vm = self.addr_space)
                # get idt addr which is at the beginning of the cpu_desc_table
                idt_addr = cpu_data.cpu_desc_tablep.v()

            idt_table = obj.Object(theType = 'Array', offset = idt_addr, vm = self.addr_space, targetType = idt_type, count = IDTSZ)

            for j in range(0, IDTSZ):
                hooked = False
                inlined = True

                ent = idt_table[j]

                if memory_model == '32bit':
                    idt32_nums = [0,1,255] + range(3,32) + range(127, 132)
                    if j not in idt32_nums:
                        continue
                    stub_addr = ent.offset_low16 + (ent.offset_high16 << 16) 
                else:
                    stub_addr = ent.offset_low16 + (ent.offset_high16 << 16) + (ent.offset_top32 << 32)

                selector = dict_seg64.get(int(ent.selector16), 'UNKNOWN')

                # 6th and 7th bits are for dpl
                # http://www.logix.cz/michal/doc/i386/chp06-03.htm
                dpl = (ent.access8 >> 5) & 0x3
            
                if stub_addr in sym_addrs:
                    idt_name = self.profile.get_symbol_by_address("kernel", stub_addr)
                    # symbols file has same address for both _hi64_text_base and _t64_zero_div, proper name is _t64_zero_div
                    if memory_model == "32bit" and idt_name == "_hi64_text_base":
                        idt_name = "_t64_zero_div"
                else:
                    idt_name = "UNKNOWN"

                module_name = self.findKextWithAddress(stub_addr)

                # check if idt stub is within the kernel OR function/idt name is somewhat known idt entry
                if str(module_name) == "__kernel__" and idt_name[:4] in ['_idt', '__in', '_t64', '_hi6', '_a64', '_mc6'] and idt_name != "UNKNOWN":
                    hooked = False
                else:
                    hooked = True

                # check if handler has been tampered with
                if self.hasValidHandler(stub_addr, memory_model, distorm_mode):
                    inlined = False

                # uncomment the next line and comment the following to use the module in the script as described at: http://siliconblade.blogspot.com/ 
                # yield(i, j, stub_addr, idt_name, dpl, selector, module_name, hooked, inlined, ent)
                yield(i, j, stub_addr, idt_name, dpl, selector, module_name, hooked, inlined)
 
    def hasValidHandler(self, idt_stub_addr, model, distorm_mode):
        # check if idt entry contains a valid handler
        op_cnt = 0
        valid_handler = False
        known_idt_hndlrs64 = ['_hndl_allintrs', '_hndl_alltraps', '_hndl_unix_scall', '_hndl_mach_scall', '_hndl_mdep_scall', '_hndl_sysenter', '_hndl_syscall', '_hndl_diag_scall', '_hndl_double_fault', '_hndl_machine_check']
        known_idt_hndlrs32 = ['_lo_allintrs', '_lo_alltraps', '_lo_diag_scall', '_lo_mach_scall', '_lo_mc64', '_lo_mdep_scall', '_lo_syscall', '_lo_sysenter', '_lo_unix_scall', '_lo_df64']
        exits = ['trap_check_kernel_exit']

        buf = self.addr_space.read(idt_stub_addr, 30)
        for op in distorm3.Decompose(idt_stub_addr, buf, distorm_mode):
            if op_cnt > 4:
                break
            # for x64, LEA RAX, [RIP+0x1602]
            if model == "64bit" and op.mnemonic == "LEA" and 'FLAG_RIP_RELATIVE' in op.flags and op.operands[0].type == 'Register':
                hndlr_addr = op.address + op.operands[1].disp + op.size
                hndlr_name = self.addr_space.profile.get_symbol_by_address('kernel', hndlr_addr)
                if hndlr_name != '' and hndlr_name in known_idt_hndlrs64:
                    valid_handler = True
                    break
            # for MOV DWORD [ESP+0x4], 0x2a17b0
            elif model == "32bit" and op.mnemonic == "MOV":
                hndlr_addr = op.operands[1].value
                hndlr_name = self.addr_space.profile.get_symbol_by_address('kernel', hndlr_addr)
                if hndlr_name != '' and hndlr_name in known_idt_hndlrs32:
                    valid_handler = True
                    break
            # for last exit JMP
            elif model == "32bit" and op.mnemonic == "JMP":
                exit_addr = op.operands[0].value
                exit_name = self.addr_space.profile.get_symbol_by_address('kernel', exit_addr)
                if exit_name != '' and exit_name in exits:
                    valid_handler = True
                    break
            op_cnt += 1
        return valid_handler

    def render_text(self, outfd, data):
        self.table_header(outfd, [("CPU#", "<4"), ("Index", "<5"), ("Address", "[addrpad]"), ("Symbol", "<25"), ("Ring", "<4"), ("Selector", "<12"), ("Module","<50"), ("Hooked","<4"), ("Inlined","<4")])
        for (cpu_number, idt_index, stub_addr, idt_name, dpl, selector, module, hooked, inlined) in data:
            if hooked == True:
                strhooked = "Yes"
            else:
                strhooked = "No"
            if inlined == True:
                strinlined = "Yes"
            else:
                strinlined = "No"
            self.table_row(outfd, cpu_number, idt_index, stub_addr, idt_name, dpl, selector, module, strhooked, strinlined)
