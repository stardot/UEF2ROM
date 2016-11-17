#!/usr/bin/env python

"""
Copyright (C) 2016 David Boddie <david@boddie.org.uk>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

__author__ = "David Boddie <david@boddie.org.uk>"
__date__ = "2016-11-17"
__version__ = "0.1"
__license__ = "GNU General Public License (version 3 or later)"

import struct, sys
from tools import UEFfile

def read_block(rom, ptr):

    gap = 0

    # Read the alignment character.
    align = rom[ptr]
    
    if align == "+":
        return None
    
    elif align == "#":
        ptr += 1
        data = rom[ptr:ptr + 256]
        ptr += 256 + 2
        return data, ptr
    
    elif align != "*":
        sys.stderr.write("Unexpected data at 0x%x in %s.\n" % (rom_ptr, rom_file_name))
        sys.exit(1)
    
    ptr += 1
    
    # Read the name.
    name = ""
    
    while ptr < len(rom):
    
        c = rom[ptr]
        ptr += 1
        
        if c == "\x00":
            break
        else:
            name += c
    
    # Load address
    load_address = struct.unpack("<I", rom[ptr:ptr+4])[0]
    ptr += 4

    # Execution address
    exec_address = struct.unpack("<I", rom[ptr:ptr+4])[0]
    ptr += 4

    # Block number
    number = struct.unpack("<H", rom[ptr:ptr+2])[0]
    ptr += 2
    
    # Block length
    length = struct.unpack("<H", rom[ptr:ptr+2])[0]
    ptr += 2

    # Block flags
    flags = ord(rom[ptr])
    ptr += 1

    # Next address
    next = struct.unpack("<H", rom[ptr:ptr+2])[0] - 0x8000
    ptr += 2

    ptr += 2

    # Header CRC
    ptr += 2
    
    if length == 0:
        data = ""
    else:
        data = rom[ptr:ptr + length]
        ptr += length
        
        # Block CRC
        ptr += 2
    
    return name, number, load_address, exec_address, flags, data, next, ptr


if __name__ == "__main__":

    if len(sys.argv) < 3:
        sys.stderr.write("Usage: %s <ROM file> ... <UEF file>\n" % sys.argv[0])
        sys.exit(1)
    
    rom_file_names = sys.argv[1:-1]
    
    files = []
    
    for rom_file_name in rom_file_names:
    
        # Find the code that sets the ROM pointer.
        rom = open(rom_file_name).read()
        
        try:
            sta_f6 = rom.index("\x85\xf6")
            if rom[sta_f6 - 2] == "\xa9":
                ptr_low = ord(rom[sta_f6 - 1])
            else:
                raise IndexError
            
            sta_f7 = rom.find("\x85\xf7")
            if rom[sta_f7 - 2] == "\xa9":
                ptr_high = ord(rom[sta_f7 - 1])
            else:
                raise IndexError
        
        except IndexError:
            sys.stderr.write("Failed to find the start of the ROMFS data.\n")
            sys.exit(1)
        
        rom_ptr = ((ptr_high << 8) | ptr_low) - 0x8000
        
        current = ""
        
        while rom_ptr < len(rom):
        
            result = read_block(rom, rom_ptr)
            
            if result is None:
                # End of ROM marker found.
                break
            
            elif len(result) == 2:
                # Not the first or last block in a file.
                data, next_ptr = result
                number += 1
                current += data
            
            else:
                # First or last block in a file.
                name, number, load_address, exec_address, flags, data, next_file_address, next_ptr = result
                current += data
                
                if number == 0:
                    info = (name, load_address, exec_address)
                    if not name.startswith("*"):
                        print repr(name), hex(load_address), hex(exec_address),
                
                if flags & 0x80:
                    # Last block - add the file to the files list.
                    if not name.startswith("*"):
                        files.append(info + (current,))
                        print hex(len(current))
                    current = ""
            
            rom_ptr = next_ptr
    
    u = UEFfile.UEFfile(creator = "ROM2UEF.py " + __version__)
    u.minor = 6
    u.target_machine = "Electron"
    u.import_files(0, files, gap = True)
    
    u.write(sys.argv[-1], write_emulator_info = False)
    sys.exit()
