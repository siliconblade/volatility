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
import common
import volatility.commands as commands
import distorm3
import volatility.plugins.mac.check_sysctl as check_sysctl
import volatility.plugins.mac.check_trap_table as check_trap_table

class mac_check_call_reference(common.AbstractMacCommand):
    """ Checks to see if system call and kernel functions are hooked """

    def __init__(self, config, *args, **kwargs):
        self.addr_space = None
        commands.Command.__init__(self, config, *args, **kwargs)
        
        self._config.add_option("CHECKKEXTS", short_option = 'X', default = False,
                          cache_invalidator = False, help = "Check all kext functions in the kext's symbol table for hooking, including kernel symbol table", action = "store_true")
        self._config.add_option("CHECKKERNEL", short_option = 'K', default = False,
                          cache_invalidator = False, help = "Check only kernel symbol table functions for hooking", action = "store_true")
        config.add_option('DISPLAYSYMBOLS', short_option = 'I', default = False,
                          help = 'Show symbols for given kext',
                          action = 'store', type = 'str')

    def getKextSymbols(self, kext_obj = None, kext_name = None, kext_addr = 0, onlyFunctions = False, fmodel = '64bit'):
        # get symbol table based on https://github.com/gdbinit/hydra/blob/master/hydra/hydra/kernel_info.c (works)
        # and https://github.com/snarez/KernelResolver/blob/master/KernelResolver/KernelResolver.c (http://ho.ax/tag/kexts/, almost works)
        # return only functions if requested, this is done by checking if symbol entry points to the __TEXT segment's __text section, which contains executable code

        mach_header_struct = 'macho64_header'
        segment_command_struct = 'macho64_segment_command'
        section_struct = 'macho64_section'
        nlist_struct = 'macho64_nlist'
        LC_SEGMENT = 0x19 # x64
    
        if fmodel == '32bit':
            mach_header_struct = 'macho32_header'
            segment_command_struct = 'macho32_segment_command'
            section_struct = 'macho32_section'
            nlist_struct = 'macho32_nlist'
            LC_SEGMENT = 0x1

        # if kext_name is given get kext_address based on name
        if kext_name != None:
            if kext_name in ["kernel", "__kernel__"]:
                kext_addr = self.addr_space.profile.get_symbol("_g_kernel_kmod_info")
            else:
                # get list of kexts and loop thru them to find match
                kmodaddr = obj.Object("Pointer", offset = self.addr_space.profile.get_symbol("_kmod"), vm = self.addr_space)
                kmod = kmodaddr.dereference_as("kmod_info")
                while kmod.is_valid():
                    if str(kmod.name) == kext_name:
                        kext_addr = kmod.address
                        break
                    kmod = kmod.next
                if kext_addr == None:
                    yield
        elif kext_obj != None:
            kext_addr = kext_obj.adddress

        # get Mach-O header to get start of segments
        mh = obj.Object(mach_header_struct, offset = kext_addr, vm=self.addr_space)
        seg_offset = mh.obj_offset + self.addr_space.profile.get_obj_size(mach_header_struct)

        linkedit_vmaddr = 0 # the first struct nlist is here
        symtab_symoff = 0 # specifies the offset in the file to the symbol table 
        symtab_stroff = 0 # specifies the offset in the file to the string table
        symbol_cnt = 0
        linkedit_fileoffset = 0
        linkedit_size = 0
        text_sect_num = 0
        sect_cnt = 0

        for i in xrange(0, mh.ncmds):
            seg = obj.Object(segment_command_struct, offset = seg_offset, vm = self.addr_space)
            if seg.cmd == 0x19 and seg.segname and str(seg.segname) == "__LINKEDIT":
                linkedit_vmaddr = seg.vmaddr
                linkedit_fileoffset = seg.fileoff
                linkedit_size = seg.filesize
            elif seg.cmd == 0x02: #SYMTAB
                symtab = obj.Object('symtab_command', offset = seg_offset, vm = self.addr_space)
                symtab_symoff = symtab.symoff
                symtab_stroff = symtab.stroff
                symbol_cnt = symtab.nsyms

            # only looking at LC_SEGMENT for sections
            if seg.cmd == LC_SEGMENT:
                # loop thru segment's sections to locate __TEXT segment's __text section number, used to determine executable code
                for j in xrange(0, seg.nsects):
                    sect_cnt += 1
                    sect = obj.Object(section_struct, offset = seg_offset + self.addr_space.profile.get_obj_size(segment_command_struct) + (self.addr_space.profile.get_obj_size(section_struct) * j), vm = self.addr_space)
                    sect_name = "".join(map(str, str(sect.sectname))).strip(' \t\r\n\0')
                    # find __TEXT segment's __text section since all executable code is here
                    if seg.cmd == 0x19 and seg.segname and str(seg.segname) == "__TEXT" and sect_name == "__text":
                        text_sect_num = sect_cnt
            seg_offset += seg.cmdsize

        symbol_offset = symtab_symoff - linkedit_fileoffset
        string_offset = symtab_stroff- linkedit_fileoffset

        # loop thru symbols within __LINKEDIT given offset
        for i in range(0, symbol_cnt-1):
            sym = obj.Object(nlist_struct, offset = linkedit_vmaddr + symbol_offset  + (i * self.addr_space.profile.get_obj_size(nlist_struct)), vm = self.addr_space)
            sym_addr = sym.n_strx + linkedit_vmaddr + string_offset
            sym_name = obj.Object('String', offset = sym_addr, vm = self.addr_space, length = 256)
            
            if sym_name.is_valid():
                if onlyFunctions:
                    if sym.n_sect == text_sect_num:
                        yield (sym_name, sym.n_value)
                else:
                    yield (sym_name, sym.n_value)

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

    def isCallReferenceModified(self, model, distorm_mode, func_addr, mod_start, mod_end):
        # check if CALL targets are within the kernel/kext range to detect possible call reference modification

        modified = False

        #modified malware/apihooks.py/check_inline function
        data = self.addr_space.read(func_addr, 750)

        # Number of instructions disassembled so far
        n = 0
        # Destination address of hooks
        d = None
        # Save the last PUSH before a CALL
        push_val = None
        # Save the general purpose registers
        regs = {}
        ops = []
        # save the address of the instruction
        op_addr = 0

        for op in distorm3.Decompose(func_addr, data, distorm_mode):
            ops.append(op)

        for op in distorm3.Decompose(func_addr, data, distorm_mode):
            # Quit when a decomposition error is encountered
            # or when reach function end
            if not op.valid or op.mnemonic == "NOP":
                break

            if op.flowControl == 'FC_CALL':
                # Clear the push value
                if push_val:
                    push_val = None
                if op.mnemonic == "CALL" and op.operands[0].type == 'AbsoluteMemoryAddress':
                    # Check for CALL [ADDR]
                    if model == '32bit':
                        const = op.operands[0].disp & 0xFFFFFFFF
                        d = obj.Object("unsigned int", offset = const, vm = addr_space)
                        op_addr = op.address
                    else: 
                        const = op.operands[0].disp
                        d = obj.Object("unsigned long long", offset = const, vm = addr_space)
                        op_addr = op.address
                    if self.outside_module(d, mod_start, mod_end):
                        break
                elif op.operands[0].type == 'Immediate':
                    # Check for CALL ADDR
                    d = op.operands[0].value
                    op_addr = op.address
                    if self.outside_module(d, mod_start, mod_end):
                        break
                elif op.operands[0].type == 'Register':
                    # Check for CALL REG
                    d = regs.get(op.operands[0].name)
                    op_addr = op.address
                    if d and self.outside_module(d, mod_start, mod_end):
                        break
            n += 1

        # filtering out false positives due to structs, you can tweak this as needed 
        if d and self.outside_module(d, mod_start, mod_end) == True and str(ops[n+1].mnemonic) not in ["DB 0xff", "ADD", "XCHG", "OUTS"]:
            modified = True

        return (modified, d, op_addr)

    def outside_module(self, addr, mod_start, mod_end):
        if addr != None and (addr < mod_start or addr > mod_end):
            return True
        else:
            return False

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
        kernel_start = kmodk.address
        kernel_end = kernel_start + kmodk.m('size')
  
        # check if kext functions are modified, including kernel symbols
        if self._config.CHECKKEXTS  or self._config.CHECKKERNEL:
            # get symbols from kext __TEXT in memory rather than file
            kext_addr_list = []

            # get kernel address
            kmod = obj.Object("kmod_info", offset = self.addr_space.profile.get_symbol("_g_kernel_kmod_info"), vm = self.addr_space)
            kext_addr_list.append(('__kernel__', kmod.address, kmod.m('size')))
            
            # get all kexts
            if self._config.CHECKKERNEL == False:
                # get other kext addresses 
                p = self.addr_space.profile.get_symbol("_kmod")
                kmodaddr = obj.Object("Pointer", offset = p, vm = self.addr_space)
                kmod = kmodaddr.dereference_as("kmod_info")
                while kmod.is_valid():
                    kext_addr_list.append((kmod.name, kmod.address, kmod.m('size')))
                    kmod = kmod.next

            # loop thru kexts
            for kext_name, kext_address, kext_size in kext_addr_list:
                k_start = kext_address
                k_end  = kext_address + kext_size

                #loop thru kext functions
                for func_name, func_addr in self.getKextSymbols(kext_addr = kext_address, onlyFunctions = True, fmodel = model):

                    # false positive, remove if needed
                    if func_name in ["pthreads_dummy_symbol"]:
                        continue

                    # check if function's been modified
                    modified, dst_addr, op_addr = self.isCallReferenceModified(model, distorm_mode, func_addr, k_start, k_end)
                    if modified:
                        if dst_addr != None:
                            hook_kext = self.findKextWithAddress(dst_addr)
                        else:
                            hook_kext = kext_name
                        yield (func_addr, func_name, op_addr, dst_addr, hook_kext)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Function Addr", "[addrpad]"), ("Function Name", "<50"), ("OP Address", "[addrpad]"), ("CALL Ref", "[addrpad]"), ("Hook In", "<50")])
        for (func_addr, func_name, call_addr, dst_addr, kext) in data:
            self.table_row(outfd, func_addr, func_name, call_addr, dst_addr, kext)



