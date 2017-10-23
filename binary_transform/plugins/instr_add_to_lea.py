#!/usr/bin/env python

from capstone import *
from capstone.x86 import *
import binascii
import pefile
import re

class Tranform(object):
    """
    Replaces the instruction ADD <register/memory>,<value>
    with LEA <register>, DWORD [<register>+<value>]
    """
    def __init__(self, pe, arch, mode):
        self.pe = pe
        self.arch = arch
        self.mode = mode
        pass

    def transform(self):
        md = Cs(self.arch, self.mode)
        md.detail = True

        # TODO: find by capstone const value X86_INS_ADD
        pat1 = re.compile(r'^83c0.{1}')
        pats = [pat1]

        instrs = []
        pat_index = 0
        entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        code_section = self.pe.get_section_by_rva(entry_point)
        for i in md.disasm(code_section.get_data(), 0):
            mtch = pats[pat_index].search(binascii.hexlify(i.bytes))
            if mtch is not None:
                instrs.append(i)
                pat_index += 1
                if pat_index >= len(pats):
                    newBytes = '\x8d\x40' + chr(i.bytes[2])
                    self.pe.set_bytes_at_offset(instrs[0].address+code_section.get_offset_from_rva(code_section.VirtualAddress), bytes(newBytes))
                    pat_index = 0
                    instrs = []
            else:
                pat_index = 0
                instrs = []

    def finalize(self):
        pass