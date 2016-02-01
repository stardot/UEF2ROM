#!/usr/bin/env python

"""
Copyright (C) 2015 David Boddie <david@boddie.org.uk>

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

import commands, os, stat, struct, sys, tempfile
import UEFfile

# Header based on the one in 11.6 of the Acorn Electron Advanced User Guide.
header_template_file = "romfs-template.oph"
minimal_header_template_file = "romfs-minimal-template.oph"

def format_data(data):

    s = ""
    i = 0
    while i < len(data):
        s += ".byte " + ",".join(map(lambda c: "$%02x" % ord(c), data[i:i+24])) + "\n"
        i += 24
    
    return s

def read_block(chunk):

    chunk_id, block = chunk
    
    # Read the block
    name = ''
    a = 1
    while 1:
        c = block[a]
        if ord(c) != 0:     # was > 32:
            name = name + c
        a = a + 1
        if ord(c) == 0:
            break

    load = struct.unpack("<I", block[a:a+4])[0]
    exec_addr = struct.unpack("<I", block[a+4:a+8])[0]
    block_number = struct.unpack("<H", block[a+8:a+10])[0]
    flags = struct.unpack("<B", block[a+12])[0]
    
    return (name, load, exec_addr, block[a+19:-2], block_number, flags)

def write_block(u, name, load, exec_, data, n, flags, address):

    out = ""
    
    # Write the alignment character
    out = "*"+name[:10]+"\000"
    
    # Load address
    out = out + struct.pack("<I", load)
    
    # Execution address
    out = out + struct.pack("<I", exec_)
    
    # Block number
    out = out + struct.pack("<H", n)
    
    # Block length
    out = out + struct.pack("<H", len(data))
    
    # Block flags
    out = out + struct.pack("<B", flags)
    
    # Next address
    out = out + struct.pack("<I", address)
    
    # Header CRC
    out = out + struct.pack("<H", u.crc(out[1:]))
    
    # Block data
    out = out + data
    
    # Block CRC
    out = out + struct.pack("<H", u.crc(data))
    
    return out

def convert_chunks(u, indices, data_addresses, headers, rom_files):

    uef_files = []
    chunks = []
    
    for chunk in u.chunks:
    
        n, data = chunk
        
        if (n == 0x100 or n == 0x102) and data and data[0] == "\x2a":
        
            name, load, exec_, block_data, this, flags = info = read_block(chunk)
            chunks.append(chunk)
            
            last = flags & 0x80
            if last:
                uef_files.append(chunks)
                chunks = []
    
    roms = []
    files = []
    file_addresses = []
    blocks = []
    
    r = 0
    address = data_addresses[r]
    
    if not indices:
        indices = range(len(uef_files))
    
    for index in indices:
    
        for chunk in uef_files[index]:
        
            n, data = chunk
            
            if (n == 0x100 or n == 0x102) and data and data[0] == "\x2a":
            
                name, load, exec_, block_data, this, flags = info = read_block(chunk)
                
                last = flags & 0x80
                
                if this == 0 or last:
                    # The next block follows the normal header and block data.
                    block = data
                else:
                    # The next block follows the continuation marker, raw block data
                    # and the block checksum.
                    block = "\x23" + block_data + struct.pack("<H", u.crc(block_data))
                
                if this == 0:
                    file_addresses.append(address)
                
                if address + len(block) >= 0xc000:
                
                    # The block won't fit into the current ROM. Start a new one
                    # and add it there along with the other blocks in the file.
                    
                    if split_files:
                        files.append(blocks)
                        file_addresses.append(address)
                        blocks = []
                    
                    roms.append((files, file_addresses))
                    
                    files = []
                    file_addresses = []
                    
                    r += 1
                    if r >= len(data_addresses):
                        sys.stderr.write("Not enough ROM files specified.\n")
                        sys.exit(1)
                    
                    # Update the data address from the start of the new ROM's data
                    # area, adding the lengths of the blocks that need to be
                    # transferred to the next ROM.
                    address = data_addresses[r]
                    file_addresses.append(address)
                    
                    if split_files:
                        print "Splitting %s." % repr(name)
                        block = data
                    else:
                        print "Moving %s to the next ROM." % repr(name)
                        for old_block, info in blocks:
                            address += len(old_block)
                
                address += len(block)
                blocks.append((block, info))
                
                if last:
                    files.append(blocks)
                    blocks = []
                    
                    end = load + (this * 256) + len(block_data)
                    if workspace != workspace_end and \
                        (load <= workspace < end or load < workspace_end <= end):
                        print "Warning: file %s [$%x,$%x) may overwrite ROM workspace: [$%x,$%x)" % (
                            repr(name), load, end, workspace, workspace_end)
    
    if blocks:
        files.append(blocks)
    
    if files:
        # Record the address of the byte after the last file.
        file_addresses.append(address)
        roms.append((files, file_addresses))
    
    if len(roms) > len(rom_files):
        sys.stderr.write("Not enough ROM files specified.\n")
        sys.exit(1)
    
    for header, rom_file, rom in zip(headers, rom_files, roms):
    
        tf, temp_file = tempfile.mkstemp(suffix=os.extsep+'oph')
        os.write(tf, header)
        
        files, file_addresses = rom
        
        # Discard the address of the first file.
        address = file_addresses.pop(0)
        print rom_file
        
        first_block = True
            
        for blocks in files:
        
            for block, info in blocks:
            
                name, load, exec_, block_data, this, flags = info
                last = flags & 0x80
                
                if this == 0 or last or first_block:
                    os.write(tf, "; %s %i\n" % (name, this))
                    
                    if last:
                        next_address = file_addresses.pop(0)
                        if this == 0:
                            print " %s starts at $%x and ends at $%x, next file at $%x" % (
                                repr(name), address, address + len(block),
                                next_address)
                    
                    elif this == 0:
                        next_address = file_addresses[0]
                        print " %s starts at $%x, next file at $%x" % (
                            repr(name), address, next_address)
                    
                    else:
                        next_address = file_addresses[0]
                        print " %s continues at $%x, next file at $%x" % (
                            repr(name), address, next_address)
                    
                    first_block = False
                    os.write(tf, format_data(
                        write_block(u, name, load, exec_, block_data, this, flags, next_address)))
                else:
                    os.write(tf, "; %s %i\n" % (name, this))
                    os.write(tf, format_data(block))
                
                address += len(block)
        
        write_end_marker(tf)
        
        os.close(tf)
        os.system("ophis -o " + commands.mkarg(rom_file) + " " + commands.mkarg(temp_file))
        os.remove(temp_file)

def write_end_marker(tf):

    os.write(tf, ".byte $2b\n")

def get_data_address(header_file, rom_file):

    tf, temp_file = tempfile.mkstemp(suffix=os.extsep+'oph')
    os.write(tf, header_file)
    os.close(tf)
    
    os.system("ophis -o " + commands.mkarg(rom_file) + " " + commands.mkarg(temp_file))
    data_address = 0x8000 + os.stat(rom_file)[stat.ST_SIZE]
    os.remove(temp_file)
    
    return data_address


class ArgumentError(Exception):
    pass

def find_option(args, label, number = 0):

    try:
        i = args.index(label)
    except ValueError:
        if number == 0:
            return False
        else:
            return False, None
    
    values = args[i + 1:i + number + 1]
    args[:] = args[:i] + args[i + number + 1:]
    
    if number == 0:
        return True
    
    if len(values) < number:
        raise ArgumentError, "Not enough values for argument '%s': %s" % (label, repr(values))
    
    if number == 1:
        values = values[0]
    
    return True, values

def usage():
    sys.stderr.write("Usage: %s [-f <file indices>] [-m | ([-t] [-w <workspace>])] [-s] <UEF file> <ROM file> [<ROM file>]\n\n" % sys.argv[0])
    sys.stderr.write(
        "The file indices can be given as a comma-separated list and can include\n"
        "hyphen-separated ranges of indices.\n\n"
        "A minimal ROM image can be specified with the -m option.\n"
        "If a minimal ROM image is not used, the -t option can be used to specify\n"
        "that code to override *TAPE calls should be used.\n\n"
        "The workspace for the ROM can be given as a hexadecimal value and specifies\n"
        "the address in memory where the persistent ROM pointer will be stored, and\n"
        "also the code and old BYTEV vector address for *TAPE interception (if used).\n"
        "The workspace defaults to a00.\n\n"
        "If the -s option is specified, files may be split between ROMs.\n"
        )
    sys.exit(1)

if __name__ == "__main__":

    args = sys.argv[:]
    indices = []
    
    minimal = False
    tape_override = False
    workspace = 0xa00
    
    details = {"title": "Test ROM",
               "version string": "1.0",
               "version": 1,
               "copyright": "(C) Original author",
               "tape init": "pla\npla\nlda #0\nrts\n",
               "first rom bank init code": "",
               "first rom bank check code": "",
               "second rom bank init code": ""}
    
    try:
        f, files = find_option(args, "-f", 1)
        if f:
            pieces = files.split(",")
            for piece in pieces:
                if "-" in piece:
                    begin, end = piece.split("-")
                else:
                    begin = end = piece
                
                indices += range(int(begin), int(end) + 1)
        
        minimal = find_option(args, "-m", 0)
        if minimal:
            header_template = open(minimal_header_template_file).read()
        else:
            header_template = open(header_template_file).read()
        
        if not minimal:
            tape_override = find_option(args, "-t", 0)
            
            w, workspace = find_option(args, "-w", 1)
            if w:
                workspace = int(workspace, 16)
            else:
                workspace = 0xa00
        else:
            if find_option(args, "-t", 0):
                sys.stderr.write("Cannot override *TAPE in minimal ROMs.\n")
                sys.exit(1)
        
        split_files = find_option(args, "-s", 0)
    
    except (IndexError, ValueError):
        usage()
    
    if not 3 <= len(args) <= 4:
        usage()
    
    uef_file = args[1]
    rom_files = args[2:]
    
    # The size of the workspace is determined in the romfs-template.oph file
    # and includes the two byte address for the BYTEV vector and an eight byte
    # routine to suppress *TAPE commands.
    workspace_end = workspace
    
    details["rom pointer"] = workspace
    
    if minimal:
        # Both ROM files are minimal. Do not use workspace for a persistent ROM
        # pointer or bank number.
        details["rom bank"] = workspace_end
    else:
        # For non-minimal single ROMs we use two bytes for the persistent ROM
        # pointer.
        workspace_end += 2
        details["rom bank"] = workspace_end
        
        if len(rom_files) > 1:
            # For two ROMs we use an additional byte for the bank number.
            workspace_end += 1
            
            details["first rom bank init code"] = open("first_rom_bank_init.oph").read()
            details["first rom bank check code"] = open("first_rom_bank_check.oph").read()
            details["second rom bank init code"] = open("second_rom_bank_init.oph").read()
    
    # Add entries for tape interception, even if they are unused.
    details["bytev"] = workspace_end
    details["tape workspace"] = workspace_end + 2
    
    if tape_override:
        details["tape init"] = open("tape_init.oph").read()
        workspace_end += 10
    
    # Calculate the starting address of the ROM data by assembling the ROM
    # template files.
    minimal_header_template = open(minimal_header_template_file).read()
    
    data_address = get_data_address(header_template % details, rom_files[0])
    minimal_data_address = get_data_address(minimal_header_template % details,
        rom_files[0])
    
    u = UEFfile.UEFfile(uef_file)
    
    convert_chunks(u, indices, [data_address, minimal_data_address],
        [header_template % details, minimal_header_template % details], rom_files)
    
    for rom_file in rom_files:
    
        length = os.stat(rom_file)[stat.ST_SIZE]
        remainder = length % 16384
        if remainder != 0:
            data = open(rom_file, "rb").read()
            open(rom_file, "wb").write(data + ("\xff" * (16384 - remainder))) 
    
    sys.exit()
