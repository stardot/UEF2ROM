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
from tools import UEFfile
from compressors.distance_pair import compress, decompress

header_template_file = "asm/romfs-template.oph"
minimal_header_template_file = "asm/romfs-minimal-template.oph"

boot_code = [
    "\xa9\x8a",     # lda #$8a
    "\xa2\x00",     # ldx #0    (keyboard buffer)
    "\xa0\x89",     # ldy #$89  (fn key 9)
    "\x20\xf4\xff", # jsr $fff4 (OSBYTE 8a - insert character into buffer)
    "\xa2\x29",     # ldx #$1d
    "\xa0\x19",     # ldy #$19
    "\x20\xf7\xff", # jsr $fff7 (OSCLI - KEY9 <command>|M)
    "\xa2\x24",     # ldx #$17  
    "\xa0\x19",     # ldy #$19
    "\x20\xf7\xff", # jsr $fff7 (OSCLI - ROM)
    "\xa2\x1e",     # ldx #$17  
    "\xa0\x19",     # ldy #$19
    "\x4c\xf7\xff", # jmp $fff7 (OSCLI - BASIC)
    "BASIC\r",
    "*ROM\r",
    'KEY9 %s|M\r',
    ]

class Block:

    def __init__(self, data, info):
        self.data = data
        self.info = info

class Compressed(Block):

    def __init__(self, data, info, raw_length):
        Block.__init__(self, data, info)
        self.raw_length = raw_length

def format_data(data):

    s = ""
    i = 0
    while i < len(data):
        s += ".byte " + ",".join(map(lambda c: "$%02x" % ord(c), data[i:i+24])) + "\n"
        i += 24
    
    return s

def read_block(block):

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
    
    if data:
        # Block data
        out = out + data
        
        # Block CRC
        out = out + struct.pack("<H", u.crc(data))
    
    return out

def convert_chunks(u, indices, decomp_addrs, data_addresses, headers, rom_files):

    uef_files = []
    chunks = []
    names = []
    
    for n, chunk in u.chunks:
    
        if (n == 0x100 or n == 0x102) and chunk and chunk[0] == "\x2a":
        
            name, load, exec_, block_data, this, flags = info = read_block(chunk)
            
            if this == 0:
                names.append(name)
                if chunks:
                    uef_files.append(chunks)
                chunks = []
            
            chunks.append(chunk)
    
    if chunks:
        uef_files.append(chunks)
    
    # If file indices were not specified, obtain the indices of all files.
    if not indices:
        indices = range(len(uef_files))
    
    # Insert a !BOOT file at the start.
    if bootable:
    
        # Ideally, we could drop the !BOOT file if the first file should be
        # *RUN, but it seems that we may need to select the ROM filing system
        # again after entering BASIC.
        if star_run:
            code = ''.join(boot_code) % ("*/%s" % names[indices[0]])
        elif star_exec:
            code = ''.join(boot_code) % ('*EXEC"%s"' % names[indices[0]])
        else:
            code = ''.join(boot_code) % ('CHAIN"%s"' % names[indices[0]])
        
        if code:
            uef_files.insert(0, [write_block(u, "!BOOT", 0x1900, 0x1900, code, 0, 0x80, 0)])
            
            # If we inserted a !BOOT file, increment all the indices by 1 and
            # insert the !BOOT file at the start.
            indices = [0] + map(lambda i: i + 1, indices)
            decomp_addrs[0].insert(0, "x")
    
    roms = []
    files = []
    file_addresses = []
    blocks = []
    
    # Start adding files to the first ROM at the address following the code.
    r = 0
    address = data_addresses[r]
    end_address = 0xc000
    
    # Create a list of trigger addresses.
    triggers = []
    
    # Examine the files at the given indices in the UEF file.
    
    for i, index in enumerate(indices):
    
        if decomp_addrs[r]:
            decomp_addr = decomp_addrs[r].pop(0)
        else:
            decomp_addr = None
        
        if decomp_addr != "x":
        
            # When compressing, for all files other than the initial boot file,
            # insert a header with no block data into the stream followed by
            # compressed data and skip all other blocks in the file.
            
            chunk = uef_files[index][0]
            name, load, exec_, block_data, this, flags = info = read_block(chunk)
            load = load & 0xffff
            
            if decomp_addr is not None:
                load = decomp_addr
            
            # Concatenate the raw data from all the chunks in the file.
            raw_data = ""
            for chunk in uef_files[index]:
                raw_data += read_block(chunk)[3]
            
            this = 0
            
            while raw_data:
            
                # Create a block with only a header and no data.
                info = (name, load, exec_, "", this, 0x80)
                header = write_block(u, name, load, exec_, "", this, 0x80, 0)
                
                # Compress the raw data.
                cdata = "".join(map(chr, compress(map(ord, raw_data))))
                print "Compressed %s from %i to %i bytes." % (repr(name)[1:-1],
                    len(raw_data), len(cdata))
                
                remaining = end_address - address - 1
                
                if remaining <= len(header) + 8 + len(cdata):
                
                    # The file won't fit into the current ROM. Either put it in a
                    # new one, or split it and put the rest of the file there.
                    print "File %s won't fit in the current ROM - %i bytes too long." % (
                        repr(name), len(header) + 8 + len(cdata) - remaining)
                    
                    # Try to fit the block header, 8 byte address entries and
                    # part of the compressed file in the remaining space.
                    if split_files and (remaining >= 8 + len(header) + 256):
                    
                        # Decompress the truncated compressed data to find out
                        # how much raw data needs to be moved to the next ROM.
                        # Avoid truncating the data in the middle of a special
                        # byte sequence - this can be two bytes in length
                        # following a special byte.
                        
                        special = cdata[0]
                        end = remaining - 8 - len(header)
                        while end > 2 and special in cdata[end-2:end]:
                            end -= 1
                        
                        cdata = cdata[:end]
                        raw_data_written = decompress(map(ord, cdata))
                        
                        # Discard the raw data that has been handled.
                        raw_data = raw_data[len(raw_data_written):]
                        print "Writing %i bytes, leaving %i to be written." % (
                            len(raw_data_written), len(raw_data))
                        
                        # Update the header to indicate that this block is not
                        # the last.
                        info = (name, load, exec_, "", this, 0)
                        header = write_block(u, name, load, exec_, "", this, 0, 0)
                        
                        if this == 0:
                            file_addresses.append(address)
                        
                        # Add information about the truncated block to the list
                        # of blocks, update the block number and record the
                        # trigger address.
                        blocks.append(Compressed(cdata, info, len(raw_data_written)))
                        this += 1
                        triggers.append(address + len(header) - 1)
                        
                        address += len(header)
                        
                        # Adjust the load address for the rest of the file.
                        load += len(raw_data_written)
                    
                    # Add pending blocks to the list of files, add an address
                    # for the end of ROMFS marker, and clear the list of blocks.
                    files.append(blocks)
                    file_addresses.append(address)
                    blocks = []
                    
                    roms.append((files, file_addresses, triggers))
                    
                    # Start a new ROM.
                    files = []
                    file_addresses = []
                    triggers = []
                    end_address = 0xc000
                    
                    r += 1
                    if r >= len(data_addresses):
                        sys.stderr.write("Not enough ROM files specified.\n")
                        sys.exit(1)
                    
                    # Update the data address from the start of the new ROM's
                    # data area.
                    address = data_addresses[r]
                    
                    if split_files:
                        print "Splitting %s - moving %i bytes to the next ROM." % (
                            repr(name), len(raw_data))
                        # Ensure that the first block in the new ROM is treated
                        # as the start of a file.
                        file_addresses.append(address)
                    else:
                        print "Moving %s to the next ROM." % repr(name)
                else:
                    # Reserve space for the ROM address, decompression start
                    # and finish addresses, source address and compressed data.
                    end_address -= 8 + len(cdata)
                    
                    if this == 0:
                        file_addresses.append(address)
                    
                    blocks.append(Compressed(cdata, info, len(raw_data)))
                    triggers.append(address + len(header) - 1)
                    
                    address += len(header)
                    raw_data = ""
            
            # Examine the next file.
            continue
        
        # For uncompressed data, handle each chunk from the UEF file separately.
        
        for i, chunk in enumerate(uef_files[index]):
        
            name, load, exec_, block_data, this, flags = info = read_block(chunk)
            
            last = (i == len(uef_files[index]) - 1)
            
            # Encode the full header and data, or continuation byte and data.
            if this == 0 or last:
                # The next block follows the normal header and block data.
                block = chunk
            else:
                # The next block follows the continuation marker, raw block data
                # and the block checksum.
                block = "\x23" + block_data + struct.pack("<H", u.crc(block_data))
            
            if this == 0:
                file_addresses.append(address)
            
            if address + len(block) >= end_address:
            
                # The block won't fit into the current ROM. Start a new one
                # and add it there along with the other blocks in the file.
                print "Block $%x in %s won't fit in the current ROM." % (this, repr(name))
                
                if split_files:
                    files.append(blocks)
                    file_addresses.append(address)
                    blocks = []
                
                roms.append((files, file_addresses, triggers))
                
                files = []
                file_addresses = []
                triggers = []
                end_address = 0xc000
                
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
                    print "Splitting %s - moving block $%x to the next ROM." % (repr(name), this)
                    # Ensure that the first block in the new ROM has a full
                    # header.
                    block = chunk
                else:
                    print "Moving %s to the next ROM." % repr(name)
                    for old_block_info in blocks:
                        address += len(old_block_info.data)
            
            address += len(block)
            blocks.append(Block(block, info))
        
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
        roms.append((files, file_addresses, triggers))
    
    if len(roms) > len(rom_files):
        sys.stderr.write("Not enough ROM files specified.\n")
        sys.exit(1)
    
    # Write the source for each ROM file, containing the appropriate ROM header
    # and the files it contains in its ROMFS structure.
    
    for header, rom_file, rom in zip(headers, rom_files, roms):
    
        tf, temp_file = tempfile.mkstemp(suffix=os.extsep+'oph')
        os.write(tf, header)
        
        files, file_addresses, triggers = rom
        
        # Discard the address of the first file.
        address = file_addresses.pop(0)
        print rom_file
        
        first_block = True
        file_details = []
        
        for blocks in files:
        
            file_name = ""
            load_addr = 0
            length = 0
            
            for b, block_info in enumerate(blocks):
            
                name, load, exec_, block_data, this, flags = block_info.info
                length += len(block_data)
                last = (b == len(blocks) - 1) and block_info.data[0] != "\x23"
                
                # Potential flag modifications:
                #
                #if flags & 0x40 and len(block_data) != 0:
                #    flags = flags & 0xbf
                #if flags & 0x80 and not last:
                #    flags = flags & 0x7f
                
                if isinstance(block_info, Compressed):
                
                    os.write(tf, "; %s %x\n" % (repr(name)[1:-1], this))
                    
                    next_address = file_addresses.pop(0)
                    file_details.append((name, load, block_info))
                    length = 0
                    
                    data = write_block(u, name, load, exec_, block_data, this, flags, next_address)
                    os.write(tf, format_data(data))
                    
                    print " %s starts at $%x and ends at $%x, next file at $%x" % (
                        repr(name), address, address + len(data),
                        next_address)
                
                elif this == 0 or last or first_block:
                    os.write(tf, "; %s %x\n" % (repr(name)[1:-1], this))
                    
                    if last:
                        next_address = file_addresses.pop(0)
                        block_info.raw_length = length
                        length = 0
                        
                        if this == 0:
                            print " %s starts at $%x and ends at $%x, next file at $%x" % (
                                repr(name), address, address + len(block_info.data),
                                next_address)
                    
                    elif this == 0:
                        file_name = name
                        load_addr = load
                        next_address = file_addresses[0]
                        print " %s starts at $%x, next file at $%x" % (
                            repr(name), address, next_address)
                    
                    else:
                        next_address = file_addresses[0]
                        print " %s continues at $%x, next file at $%x" % (
                            repr(name), address, next_address)
                    
                    first_block = False
                    
                    data = write_block(u, name, load, exec_, block_data, this, flags, next_address)
                    os.write(tf, format_data(data))
                
                else:
                    os.write(tf, "; %s %x\n" % (repr(name)[1:-1], this))
                    data = block_info.data
                    os.write(tf, format_data(data))
                
                address += len(data)
        
        write_end_marker(tf)
        
        # If a list of triggers was compiled, write the compressed data after
        # the ROMFS data, and write the associated addresses at the end of the
        # ROM file.
        
        if triggers:
        
            os.write(tf, "\n; Compressed data\n")
            
            addresses = []
            for info in file_details:
            
                # Unpack the file information.
                name, decomp_addr, block_info = info
                
                src_label = "src_%x" % id(block_info)
                
                if decomp_addr != "x":
                
                    addr = triggers.pop(0)
                    decomp_addr = decomp_addr & 0xffff
                    addresses.append((name, addr, src_label, decomp_addr, decomp_addr + block_info.raw_length))
                    
                    os.write(tf, "\n; %s\n" % repr(name)[1:-1])
                    os.write(tf, src_label + ":\n")
                    os.write(tf, format_data(block_info.data))
            
            #os.write(tf, "\n.alias debug %i" % (49 + roms.index(rom)))
            os.write(tf, "\n.alias after_triggers %i\n" % (len(triggers) * 2))
            os.write(tf, "\ntriggers:\n")
            
            for name, addr, src_label, decomp_addr, decomp_end_addr in addresses:
                if decomp_addr != "x":
                    os.write(tf, ".byte $%02x, $%02x ; %s\n" % (addr & 0xff, addr >> 8, repr(name)[1:-1]))
            
            os.write(tf, "\nsrc_addresses:\n")
            
            for name, addr, src_label, decomp_addr, decomp_end_addr in addresses:
                if decomp_addr != "x":
                    os.write(tf, ".byte <%s, >%s ; source address\n" % (src_label, src_label))
            
            os.write(tf, "\ndest_addresses:\n")
            
            for name, addr, src_label, decomp_addr, decomp_end_addr in addresses:
                if decomp_addr != "x":
                    os.write(tf, ".byte $%02x, $%02x ; decompression start address\n" % (decomp_addr & 0xff, decomp_addr >> 8))
            
            os.write(tf, "\ndest_end_addresses:\n")
            
            for name, addr, src_label, decomp_addr, decomp_end_addr in addresses:
                if decomp_addr != "x":
                    os.write(tf, ".byte $%02x, $%02x ; decompression end address\n" % (decomp_end_addr & 0xff, decomp_end_addr >> 8))
            
            os.write(tf, "\n")
            
            decomp_addrs = decomp_addrs[len(file_details):]
        
        os.close(tf)
        if os.system("ophis -o " + commands.mkarg(rom_file) + " " + commands.mkarg(temp_file)) != 0:
            sys.exit(1)
        
        os.remove(temp_file)

def write_end_marker(tf):

    os.write(tf, ".byte $2b\n")

def get_data_address(header_file, rom_file):

    tf, temp_file = tempfile.mkstemp(suffix=os.extsep+'oph')
    os.write(tf, header_file)
    # Include placeholder values.
    os.write(tf, ".alias after_triggers 0\n")
    #os.write(tf, ".alias debug 48\n")
    os.write(tf, "triggers:\n")
    os.write(tf, "src_addresses:\n")
    os.write(tf, "dest_addresses:\n")
    os.write(tf, "dest_end_addresses:\n")
    os.close(tf)
    
    if os.system("ophis -o " + commands.mkarg(rom_file) + " " + commands.mkarg(temp_file)):
        sys.exit(1)
    
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
    sys.stderr.write("Usage: %s [-f <file indices>] [-m | ([-p] [-t] [-w <workspace>] [-l])] [-s] [-b [-a] [-r|-x]] [-c1] [-c2] <UEF file> <ROM file> [<ROM file>]\n\n" % sys.argv[0])
    sys.stderr.write(
        "The file indices can be given as a comma-separated list and can include\n"
        "hyphen-separated ranges of indices.\n\n"
        "The first ROM image can be specified to be a minimal ROM with the -m option.\n"
        "Otherwise, it will contain code to use a persistent ROM pointer.\n"
        "The second ROM image will always be minimal, but can be specified to use a\n"
        "persistent ROM pointer if the -p option is given and the first ROM is not a\n"
        "minimal ROM.\n\n"
        "If a minimal ROM image is not used, the -t option can be used to specify\n"
        "that code to override *TAPE calls should be used.\n"
        "The workspace for the ROM can be given as a hexadecimal value with the -w option\n"
        "and specifies the address in memory where the persistent ROM pointer will be\n"
        "stored and also the code and old BYTEV vector address for *TAPE interception (if\n"
        "used). The workspace defaults to a00.\n\n"
        "If you specify a pair of addresses separated by a colon (e.g, d3f:ef97) then the\n"
        "second address will be used for the BYTEV vector address.\n\n"
        "The -l option determines whether the first ROM will be read again after the\n"
        "second ROM has been accessed. By default, the first ROM will not be readable\n"
        "to ensure that files on the second ROM following a split file can be read.\n\n"
        "If the -s option is specified, files may be split between ROMs.\n\n"
        "If the -b option is specified, the first ROM will be run when selected.\n"
        "Additionally, if the -a option is given, the ROM will be made auto-bootable.\n\n"
        "The -r option is used to specify that the first file must be executed with *RUN.\n"
        "The -x option indicates that *EXEC is used to execute the first file.\n\n"
        "The -c option is used to indicate that files should be compressed, and is used\n"
        "to supply information about the location in memory where they should be\n"
        "decompressed. This is followed by colon-separated lists of load addresses,\n"
        "themselves separated using slashes.\n\n"
        )
    sys.exit(1)

if __name__ == "__main__":

    args = sys.argv[:]
    indices = []
    
    minimal = False
    tape_override = False
    workspace = 0xa00
    
    details = [
        {"title": "Test ROM",
         "version string": "1.0",
         "version": 1,
         "copyright": "(C) Original author",
         "service entry command code": "",
         "service command code": "",
         "service boot code": "",
         "boot code": "",
         "init romfs code": "",
         "call tape init": "",
         "tape init": "",
         "first rom bank init code": "",
         "first rom bank check code": "",
         "first rom bank behaviour code": "",
         "second rom bank check code": "",
         "second rom bank init code": "",
         "second rom bank pointer sync code": "",
         "decode code": "",
         "trigger check": "",
         "trigger routine": ""},
        {"title": "Test ROM",
         "version string": "1.0",
         "version": 1,
         "copyright": "(C) Original author",
         "service boot code": "",
         "boot code": "",
         "init romfs code": "",
         "second rom bank check code": "",
         "second rom bank init code": "",
         "second rom bank pointer sync code": "",
         "decode code": "",
         "trigger check": "",
         "trigger routine": ""},
        ]
    
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
                if ":" in workspace:
                    pieces = workspace.split(":")
                    workspace = int(pieces[0], 16)
                    tape_workspace_call_address = int(pieces[1], 16)
                else:
                    workspace = int(workspace, 16)
                    tape_workspace_call_address = None
            else:
                workspace = 0xa00
                tape_workspace_call_address = None
            
            # Non-minimal ROMs always need to call *ROM explicitly.
            details[0]["init romfs code"] = open("asm/init_romfs.oph").read()
            
            # The second ROM can use a persistent ROM pointer.
            if find_option(args, "-p", 0):
                details[1]["second rom bank check code"] = open("asm/second_rom_bank_check.oph").read()
                details[1]["second rom bank pointer sync code"] = open("asm/second_rom_bank_sync.oph").read()
            
            loop = find_option(args, "-l", 0)
        
        else:
            if find_option(args, "-t", 0):
                sys.stderr.write("Cannot override *TAPE in minimal ROMs.\n")
                sys.exit(1)
        
        split_files = find_option(args, "-s", 0)
        
        autobootable = find_option(args, "-a", 0)
        bootable = find_option(args, "-b", 0)
        star_run = find_option(args, "-r", 0)
        star_exec = find_option(args, "-x", 0)
        compress_files, hints = find_option(args, "-c", 1)
        
        if compress_files:
            # -c [<addr0>]:[<addr1>]:...:[<addrN>];[<addrN+1>]:...:[<addrM>]
            decomp_addrs = []
            for i, addr_list in enumerate(hints.split("/")):
            
                decomp_addrs.append([])
                
                for addr in addr_list.split(":"):
                    if addr == "x":
                        decomp_addrs[-1].append("x")
                    elif addr:
                        decomp_addrs[-1].append(int(addr, 16))
                    else:
                        decomp_addrs[-1].append(None)
                
                details[i]["decode code"] = open("asm/dp_decode.oph").read()
                details[i]["trigger check"] = "jsr trigger_check\n"
                details[i]["trigger routine"] = open("asm/trigger_check.oph").read()
        else:
            decomp_addrs = []
        
        if autobootable:
            details[0]["service boot code"] = open("asm/service_boot.oph").read()
            if minimal:
                # Minimal ROMs only need to call *ROM if they are auto-bootable.
                details[0]["init romfs code"] = open("asm/init_romfs.oph").read()
            bootable = True
        else:
            if minimal:
                if bootable:
                    sys.stderr.write("Bootable minimal ROMs must also be auto-bootable.\n")
                    sys.exit(1)
            else:
                # Not auto-bootable or minimal, so include code to allow
                # the ROM to be initialised.
                details[0]["service entry command code"] = open("asm/service_entry_command.oph").read()
                details[0]["service command code"] = open("asm/service_command.oph").read()
        
        if bootable:
            details[0]["boot code"] = open("asm/boot_code.oph").read()
        else:
            details[0]["boot code"] = "pla\npla\nlda #0\nrts"
    
    except (IndexError, ValueError):
        usage()
    
    # Check that we have suitable input and output files.
    if not 3 <= len(args) <= 4:
        usage()
    
    uef_file = args[1]
    rom_files = args[2:]
    
    # Create directories as required.
    for rom_file in rom_files:
        dir_name, file_name = os.path.split(rom_file)
        if dir_name and not os.path.exists(dir_name):
            os.mkdir(dir_name)
    
    # The size of the workspace is determined in the romfs-template.oph file
    # and includes the two byte address for the BYTEV vector and an eight byte
    # routine to suppress *TAPE commands.
    workspace_end = workspace
    
    details[0]["rom pointer"] = details[1]["rom pointer"] = workspace
    
    if minimal:
        # Both ROM files are minimal. Do not use workspace for a persistent ROM
        # pointer or bank number.
        details[0]["rom bank"] = details[1]["rom bank"] = workspace_end
    else:
        # For non-minimal single ROMs we use two bytes for the persistent ROM
        # pointer.
        workspace_end += 2
        details[0]["rom bank"] = details[1]["rom bank"] = workspace_end
        
        if len(rom_files) > 1:
            # For two ROMs we use an additional byte for the bank number.
            workspace_end += 1
            
            details[0]["first rom bank init code"] = open("asm/first_rom_bank_init.oph").read()
            details[0]["first rom bank check code"] = open("asm/first_rom_bank_check.oph").read()
            if loop:
                details[0]["first rom bank behaviour code"] = "jsr reset_pointer"
            else:
                details[0]["first rom bank behaviour code"] = "bne exit"
            
            details[0]["second rom bank init code"] = \
                details[1]["second rom bank init code"] = open("asm/second_rom_bank_init.oph").read()
    
    # Add entries for tape interception, even if they are unused.
    details[0]["bytev"] = workspace_end
    details[0]["tape workspace"] = workspace_end + 2
    
    if tape_override:
        details[0]["tape init"] = open("asm/tape_init.oph").read()
        details[0]["call tape init"] = "    jsr tape_init"
        workspace_end += 10
        
        # Allow the vector to point to somewhere other than the code itself. This
        # enables us to borrow a JMP instruction elsewhere in memory to hide the
        # true location of our code.
        if tape_workspace_call_address is None:
            tape_workspace_call_address = details[0]["tape workspace"]
        
        details[0]["tape workspace call address"] = tape_workspace_call_address
    else:
        details[0]["tape workspace call address"] = details[0]["tape workspace"]
    
    print (workspace_end - workspace), "bytes of workspace used."
    
    # Calculate the starting address of the ROM data by assembling the ROM
    # template files.
    minimal_header_template = open(minimal_header_template_file).read()
    
    data_address = get_data_address(header_template % details[0], rom_files[0])
    minimal_data_address = get_data_address(minimal_header_template % details[1],
        rom_files[0])
    
    u = UEFfile.UEFfile(uef_file)
    
    convert_chunks(u, indices, decomp_addrs, [data_address, minimal_data_address],
        [header_template % details[0], minimal_header_template % details[1]],
        rom_files)
    
    for rom_file in rom_files:
    
        if not os.path.exists(rom_file):
            continue
        
        length = os.stat(rom_file)[stat.ST_SIZE]
        remainder = length % 16384
        if remainder != 0:
            data = open(rom_file, "rb").read()
            open(rom_file, "wb").write(data + ("\xff" * (16384 - remainder))) 
    
    sys.exit()
