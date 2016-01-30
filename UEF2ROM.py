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

def write_header(tf, details):

    os.write(tf, header_template % details)

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

def convert_chunks(u, indices, data_address, tf):

    blocks = []
    files = []
    address = data_address
    file_number = -1
    
    for chunk in u.chunks:
    
        n, data = chunk
        
        if (n == 0x100 or n == 0x102) and data and data[0] == "\x2a":
        
            name, load, exec_, block, this, flags = read_block(chunk)
            
            if this == 0:
                file_number += 1
                
            if indices and file_number not in indices:
                continue
            
            if this == 0:
                # Record the starting addresses of each file.
                files.append(address)
            
            blocks.append(chunk)
            
            last = flags & 0x80
            
            if this == 0 or last:
                # The next block follows the normal header and block data.
                address += len(data)
            else:
                # The next block follows the continuation marker, raw block data
                # and the block checksum.
                address += len(block) + 3
            
            if last:
                length = address - files[-1]
                load = load & 0xffff
                end = load + length
                print repr(name), "[$%x,$%x) length %i" % (load, end, length)
                
                if not minimal and \
                   (load <= workspace < end or load < workspace_end <= end):
                    print "Warning: file may overwrite ROM workspace."
                    print "Workspace: [$%x,$%x)" % (workspace, workspace_end)
                
                if address > 0xc000:
                    print "File crosses ROM end."
    
    # Record the address of the byte after the last file.
    files.append(address)
    
    # Discard the first file address.
    files.pop(0)
    
    for chunk in blocks:
    
        name, load, exec_, block, this, flags = read_block(chunk)
        last = flags & 0x80
        if this == 0 or last:
            os.write(tf, "; %s %i\n" % (name, this))
            
            if last:
                address = files.pop(0)
            else:
                address = files[0]
            
            os.write(tf, format_data(
                write_block(u, name, load, exec_, block, this, flags, address)))
        else:
            os.write(tf, "; %s %i\n" % (name, this))
            os.write(tf, format_data("\x23"))
            os.write(tf, format_data(block))
            os.write(tf, format_data(struct.pack("<H", u.crc(block))))

def write_end_marker(tf):

    os.write(tf, ".byte $2b\n")


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
    sys.stderr.write("Usage: %s [-w <workspace>] [-f <file indices>] [-m] <UEF file> <ROM file> [<ROM file>]\n" % sys.argv[0])
    sys.stderr.write(
        "The workspace is given as a hexadecimal value and specifies the address\n"
        "in memory where working data for each ROM is stored. (Defaults to a00.)\n"
        "The file indices can be given as a comma-separated list and can include\n"
        "hyphen-separated ranges of indices.\n"
        "A minimal ROM image can be specified with the -m option.\n"
        )
    sys.exit(1)

if __name__ == "__main__":

    args = sys.argv[:]
    indices = []
    
    try:
        w, workspace = find_option(args, "-w", 1)
        if w:
            workspace = int(workspace, 16)
        else:
            workspace = 0xa00
        
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
        
        tape_override = find_option(args, "-t", 0)
        if tape_override:
            tape_init = open("tape_init.oph").read()
        else:
            tape_init = "rts\n"
    
    except (IndexError, ValueError):
        usage()
    
    # The size of the workspace is determined in the romfs-template.oph file
    # and includes the two byte address for the BYTEV vector, the two byte
    # ROM file address and an eight byte routine to suppress *TAPE commands.
    workspace_end = workspace + 12
    
    if not 3 <= len(args) <= 4:
        usage()
    
    uef_file = args[1]
    rom_file = args[2]
    tf, temp_file = tempfile.mkstemp(suffix=os.extsep+'oph')
    
    details = {"title": "Test ROM",
               "version string": "1.0",
               "version": 1,
               "copyright": "(C) Original author",
               "rom pointer": workspace,
               "bytev": workspace + 2,
               "workspace": workspace + 4,
               "tape init": tape_init}
    
    u = UEFfile.UEFfile(uef_file)
    
    write_header(tf, details)
    os.system("ophis -o " + commands.mkarg(rom_file) + " " + commands.mkarg(temp_file))
    data_address = 0x8000 + os.stat(rom_file)[stat.ST_SIZE]
    convert_chunks(u, indices, data_address, tf)
    write_end_marker(tf)
    
    os.close(tf)
    os.system("ophis -o " + commands.mkarg(rom_file) + " " + commands.mkarg(temp_file))
    os.remove(temp_file)
    
    length = os.stat(rom_file)[stat.ST_SIZE]
    remainder = length % 16384
    if remainder != 0:
        data = open(rom_file, "rb").read()
        open(rom_file, "wb").write(data + ("\x00" * (16384 - remainder))) 
    
    sys.exit()
