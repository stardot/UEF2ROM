#!/usr/bin/env python3

"""
Copyright (C) 2022 David Boddie <david@boddie.org.uk>

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

import os, shlex, stat, struct, sys, tempfile
from tools import format_data, joystick, patcher, UEFfile
from compressors import distance_pair

header_template_file = "asm/romfs-template.oph"
minimal_header_template_file = "asm/romfs-minimal-template.oph"

# Each compressed file entry is
#   trigger address (2) + source address (2) + destination address (2)
# + destination end address (2) + count mask (1) + offset bits (1) = 10
compressed_entry_size = 10

res_dir = os.path.split(__file__)[0]

__usage__ = \
"""Usage: %s [-f <file indices>]
          [(-m [-M <custom routine oph file> <custom routine label>]
               [-I <custom routine oph file> <custom routine label>])
           | ([-p] [-t] [-T] [-w <workspace>] [-l])]
          [-p1]
          [-s] [-b [-a] [-r|-x] [-B <boot page>]]
          [-c <load addresses>] [-cbits <compression bits>]
          [-pf <patch file>]
          [-P <bank info address> <ROM index>]
          <UEF file> <ROM file> [<ROM file>]

"""

__description__ = \
"""The file indices can be given as a colon-separated list and can include
hyphen-separated ranges of indices. Additionally, a special value of 's' can
be used to indicate the end of a ROM, so that files following this will be
added to a new ROM.

The first ROM image can be specified to be a minimal ROM with the -m option.
Otherwise, it will contain code to use a persistent ROM pointer.
The second ROM image will always be minimal, but can be specified to use a
persistent ROM pointer if the -p option is given and the first ROM is not a
minimal ROM.

If a minimal ROM image is not used, the -t option can be used to specify
that code to override *TAPE calls should be used. Additionally, the -T option
can be used to add code to trap filing system checks and always report that
the cassette filing system is in use.

The workspace for the ROM can be given as a hexadecimal value with the -w option
and specifies the address in memory where the persistent ROM pointer will be
stored; also the code and old BYTEV vector address for *TAPE interception (if
used) and the code and old ARGSV vector address is filing system checks are
intercepted. The workspace defaults to a00.

If you specify a pair of addresses separated by a colon (e.g, d3f:ef97) then the
second address will be used for the BYTEV vector address.

The -p1 option causes code to be inserted into the boot sequence that disables
the Plus 1 before loading any files.

The -l option determines whether the first ROM will be read again after the
second ROM has been accessed. By default, the first ROM will not be readable
to ensure that files on the second ROM following a split file can be read.

If the -s option is specified, files may be split between ROMs.

If the -b option is specified, the first ROM will be run when selected.
Additionally, if the -a option is given, the ROM will be made auto-bootable.
If the -B option is also specified, the PAGE for subsequent BASIC programs
can be specified as a hexadecimal number.

The -r option is used to specify that the first file must be executed with *RUN.
The -x option indicates that *EXEC is used to execute the first file.

The -c option is used to indicate that files should be compressed, and is used
to supply information about the location in memory where they should be
decompressed. This is followed by colon-separated lists of load addresses,
themselves separated using slashes.
Additionally, the compression algorithm can be tuned by specifying the number
of bits to use to store offsets in the compression data, using the -cbits option
to do this. The default value of 4 is reasonable for most files.

The -P option causes code to be included that writes to the paging register
at 0xfc00. The code reads from the bank info address specified to obtain a base
page number and adds the specified ROM index (base 10) to it in order to swap
in the ROM from the resulting bank number.

The -M option allows a custom piece of code to be used to respond to the star
command that is otherwise not used for minimal ROMs.
The -I option is like the -M option except that the custom code is not tied to
a star command and will be run before any other initialisation
code that may also be inserted into the ROM by other options.

The -L option allows a custom piece of code to be run after the last file has
been read, accepting the name of the Ophis file to assemble and the name of
the label in the file that is the start of the subroutine to call.

The -pf option allows a set of patches to be applied to files in the UEF before
they are encoded in a ROM.
"""

def _open(file_name):

    return open(os.path.join(res_dir, file_name))

def _write(file_name, data):

    os.write(file_name, data.encode("latin1"))

def plural_str(n, singular, plural):
    if n == 1:
        return singular
    else:
        return plural

class AddressInfo:

    def __init__(self, name, addr, src_label, decomp_addr, decomp_end_addr,
                       offset_bits):
    
        self.name = name
        self.addr = addr
        self.src_label = src_label
        self.decomp_addr = decomp_addr
        self.decomp_end_addr = decomp_end_addr
        self.offset_bits = offset_bits

class Block:

    def __init__(self, data, info):
        self.data = data
        self.info = info

class Compressed(Block):

    def __init__(self, data, info, raw_length, offset_bits, first_block,
                       short_header):
    
        Block.__init__(self, data, info)
        
        self.raw_length = raw_length
        self.offset_bits = offset_bits
        self.first_block = first_block
        self.short_header = short_header

def format_data(data):

    s = ""
    i = 0
    while i < len(data):
        s += ".byte " + ",".join(map(lambda c: "$%02x" % c, data[i:i+16])) + "\n"
        i += 16
    
    return s

def read_block(block):

    # Read the block
    name = ''
    a = 1
    while 1:
        c = block[a]
        if c != 0:     # was > 32:
            name = name + chr(c)
        a = a + 1
        if c == 0:
            break

    load = struct.unpack("<I", block[a:a+4])[0]
    exec_addr = struct.unpack("<I", block[a+4:a+8])[0]
    block_number = struct.unpack("<H", block[a+8:a+10])[0]
    flags = block[a+12]
    
    data = block[a+19:-2]
    if len(data) > 256:
        data = data[:256]
    
    return (name, load, exec_addr, data, block_number, flags)

def write_block(u, name, load, exec_, data, n, flags, address):

    # Write the alignment character
    out = b"*"+name[:10].encode("latin1")+b"\000"
    
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
        out += data
        
        # Block CRC
        out += struct.pack("<H", u.crc(data))
    
    return out


def compress_file_or_blocks(encoded_raw_data, compress_offset_bits, block_size):

    if compress_file_blocks:
    
        # Obtain a list of pieces for processing.
        new_compressed_pieces = distance_pair.compress_blocks(
            encoded_raw_data, block_size)
        
        decoded_raw_data = distance_pair.decompress_blocks(new_compressed_pieces)
    else:
        
        if compress_offset_bits != None:
            cdata = distance_pair.compress_file(encoded_raw_data,
                offset_bits = compress_offset_bits)
        else:
            # Construct a list of tuples containing the length of compressed
            # data, the number of offset bits used to compress it and the data
            # itself.
            
            dlength = len(encoded_raw_data)
            compression_results = []
            # Put a default entry in the list corresponding to uncompressed
            # data.
            #compression_results.append((dlength, 0, encoded_raw_data))
            
            for compress_offset_bits in range(3, 8):
                cdata = distance_pair.compress_file(encoded_raw_data,
                    offset_bits = compress_offset_bits)
                
                l = len(cdata)
                
                #if l >= dlength:
                #    continue
                
                compression_results.append((l, compress_offset_bits, cdata))
            
            compression_results.sort()
            l, compress_offset_bits, cdata = compression_results[0]
        
        # If returning a compressed file, create a list containing only one
        # piece for processing.
        new_compressed_pieces = [[compress_offset_bits, encoded_raw_data, cdata]]
        
        if compress_offset_bits == 0:
            # If the uncompressed data was shortest then return it instead of
            # compressed data. This is currently unused but handled in the
            # compress_file function.
            decoded_raw_data = encoded_raw_data
        else:
            decoded_raw_data = distance_pair.decompress(cdata, compress_offset_bits)
    
    return decoded_raw_data, new_compressed_pieces


def compress_file(uef_files, index, decomp_addr, execution_addr, details, roms,
                  r, address, end_address, file_addresses, data_addresses,
                  files, triggers):

    # When compressing, for all files other than the initial boot file,
    # insert a header with no block data into the stream followed by
    # compressed data and skip all other blocks in the file.
    
    chunk = uef_files[index][0]
    name, load, exec_, block_data, this, flags = info = read_block(chunk)
    load = load & 0xffff
    
    if decomp_addr is not None:
        load = decomp_addr
    
    if execution_addr is not None:
        exec_ = execution_addr
    
    # Concatenate the raw data from all the chunks in the file.
    raw_data = b""
    for chunk in uef_files[index]:
        raw_data += read_block(chunk)[3]
    
    encoded_raw_data = raw_data
    
    this = 0
    compressed_pieces = []
    blocks = []
    
    while encoded_raw_data or compressed_pieces:
    
        # Compress the raw data.
        compress_offset_bits = details[r]["compress offset bits"]
        
        decoded_raw_data, new_compressed_pieces = compress_file_or_blocks(
            encoded_raw_data, compress_offset_bits, compress_block_size)
        
        if bytes(decoded_raw_data) != encoded_raw_data:
            sys.stderr.write("Error when compressing file %s. "
                "Decompressed data did not match the original data.\n" % name)
            sys.exit(1)
        
        # Insert new compressed data before any already queued. This handles
        # the case where the end of a ROM was encountered and the remaining
        # data needed to be compressed again.
        compressed_pieces = new_compressed_pieces + compressed_pieces
        
        print("Attempted to compress %s from %i bytes to %i %s of compressed data:" % (
            repr(name)[1:-1], len(encoded_raw_data), len(compressed_pieces),
            plural_str(len(compressed_pieces), "piece", "pieces")))
        
        first_block = True
        
        while compressed_pieces:
        
            compress_offset_bits, enc_raw_data, encoded_compressed_data = \
                compressed_pieces.pop(0)
            
            clength = len(encoded_compressed_data)
            
            if compress_offset_bits != 0:
                print(" %02x: %i bytes with %i-bit offset at load address $%x." % (
                    this, clength, compress_offset_bits, load))
            else:
                print(" %02x: %i bytes of uncompressed data at load address $%x." % (
                    this, clength, load))
            
            # Create a block with only a header and no data.
            if first_block or not compressed_pieces:
                info = (name, load, exec_, b"", this, 0x0)
                header = write_block(u, name, load, exec_, b"", this, 0x0, 0)
            else:
                info = (name, load, exec_, b"", this, 0)
                header = 0x23
            
            # Calculate the space between the end of the ROM and the
            # current address, leaving room for an end of ROM marker.
            remaining = end_address - address - 1
            
            if remaining < len(header) + compressed_entry_size + clength:
            
                # The file won't fit into the current ROM. Either put it in a
                # new one, or split it and put the rest of the file there.
                print("File %s won't fit in the current ROM - %i bytes too long." % (
                    repr(name), len(header) + compressed_entry_size + clength - remaining))
                
                # Try to fit the block header, compressed entry and
                # part of the compressed file in the remaining space.
                has_free_space = (remaining >= compressed_entry_size + len(header) + 256)
                
                if split_files and has_free_space:
                
                    # Decompress the truncated compressed data to find out
                    # how much raw data needs to be moved to the next ROM.
                    # Avoid truncating the data in the middle of a special
                    # byte sequence - this can be two bytes in length
                    # following a special byte.
                    
                    special = encoded_compressed_data[0]
                    end = remaining - compressed_entry_size - len(header)
                    while end > 2 and special in encoded_compressed_data[end-2:end]:
                        end -= 1
                    
                    if end == 2:
                        sys.stderr.write("Failed to split compressed data for %s.\n" % repr(name))
                        sys.exit(1)
                    
                    # Truncate the compressed data and find the decompressed
                    # data that corresponds to it.
                    encoded_compressed_data = encoded_compressed_data[:end]
                    
                    raw_data_written = distance_pair.decompress(
                        encoded_compressed_data, offset_bits = compress_offset_bits)
                    
                    # Store the raw data that has been handled in a compressed
                    # block and put the rest back in the byte string for it to
                    # be compressed again.
                    encoded_raw_data = enc_raw_data[len(raw_data_written):]
                    
                    # Also add the raw data from any other compressed blocks
                    # in the queue.
                    for piece in compressed_pieces:
                        encoded_raw_data += piece[1]
                    
                    compressed_pieces = []
                    
                    print("Writing %i bytes, leaving %i to be written." % (
                        len(raw_data_written), len(encoded_raw_data)))
                    
                    cdata = encoded_compressed_data
                    
                    compressed_block = Compressed(cdata, info,
                        len(raw_data_written), compress_offset_bits,
                        first_block, header == 0x23)
                    
                    if first_block:
                        file_addresses.append(address)
                    
                    # Add information about the truncated block to the list
                    # of blocks, update the block number and record the
                    # trigger address.
                    blocks.append(compressed_block)
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
                first_block = True
                
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
                
                if split_files and has_free_space:
                    print("Splitting %s - moving %i bytes to the next ROM." % (
                        repr(name), len(encoded_raw_data)))
                    break
                else:
                    print("Moving %s to the next ROM." % repr(name))
                    
                    # No raw data needs to be recompressed.
                    encoded_raw_data = []
                    
                    # Requeue the current piece of compressed data.
                    compressed_pieces.insert(0, [compress_offset_bits,
                        enc_raw_data, encoded_compressed_data])
            
            else:
                # Reserve space for the ROM address, decompression start
                # and finish addresses, source address and compressed data.
                end_address -= compressed_entry_size + clength
                
                # Update the header if this block is the last in the file.
                if not compressed_pieces:
                    info = (name, load, exec_, b"", this, 0x80)
                    header = write_block(u, name, load, exec_, b"", this, 0x80, 0)
                
                cdata = encoded_compressed_data
                
                compressed_block = Compressed(cdata, info, len(enc_raw_data),
                    compress_offset_bits, first_block, header == 0x23)
                
                if first_block:
                    file_addresses.append(address)
                
                if details[r]["decode code"] == "":
                    sys.stderr.write("Cannot write compressed data for %s to ROM "
                        "without compression support.\n" % repr(name))
                    sys.exit(1)
                
                blocks.append(compressed_block)
                triggers.append(address + len(header) - 1)
                
                address += len(header)
                load += len(enc_raw_data)
                encoded_raw_data = []
                this += 1
                first_block = False
    
    # Append any remaining blocks.
    files.append(blocks)
    
    return files, [], r, address, end_address, file_addresses, triggers


def convert_chunks(u, indices, decomp_addrs, data_addresses, headers, details,
                   rom_files):

    uef_files = []
    chunks = []
    names = []
    
    for n, chunk in u.chunks:
    
        if (n == 0x100 or n == 0x102) and chunk and chunk[0] == 0x2a:
        
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
            details[0]["boot commands"].append('"*/%s"' % names[indices[0]])
        elif star_exec:
            details[0]["boot commands"].append('"*EXEC", 34, "%s", 34' % names[indices[0]])
        else:
            details[0]["boot commands"].append('"CHAIN", 34, "%s", 34' % names[indices[0]])
        
        details[0]["boot commands"] = ", ".join(details[0]["boot commands"])
        
        tof, temp_oph_file = tempfile.mkstemp(suffix=os.extsep+'oph')
        tf, temp_boot_file = tempfile.mkstemp(suffix=os.extsep+'boot')
        
        boot_file_text = _open("asm/file_boot_code.oph").read() % details[0]
        _write(tof, boot_file_text)
        
        if os.system("ophis -o " + shlex.quote(temp_boot_file) + " " + shlex.quote(temp_oph_file)) != 0:
            sys.exit(1)
        
        boot_code = open(temp_boot_file, "rb").read()
        os.remove(temp_oph_file)
        os.remove(temp_boot_file)
        
        if boot_code:
            boot_name = details[0]["boot name"]
            uef_files.insert(0, [write_block(u, boot_name, 0x1900, 0x1900, boot_code, 0, 0x80, 0)])
            
            # If we inserted a !BOOT file, increment all the indices by 1 and
            # insert the !BOOT file at the start.
            new_indices = [0]
            for i in indices:
                if i == "s":
                    new_indices.append(i)
                else:
                    new_indices.append(i + 1)
            
            indices = new_indices
            
            if decomp_addrs:
                decomp_addrs[0].insert(0, ("x", None))
    
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
    
        if index == "s":
        
            # Add pending blocks to the list of files, add an address
            # for the end of ROMFS marker, and clear the list of blocks.
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
            
            # Update the data address from the start of the new ROM's
            # data area.
            address = data_addresses[r]
            
            continue
        
        if r < len(decomp_addrs):
            if decomp_addrs[r]:
                decomp_addr, execution_addr = decomp_addrs[r].pop(0)
            else:
                decomp_addr = execution_addr = None
        else:
            decomp_addr = "x"
            execution_addr = None
        
        if decomp_addr != "x":
        
            files, blocks, r, address, end_address, file_addresses, triggers = \
                compress_file(uef_files, index, decomp_addr, execution_addr,
                              details, roms, r, address, end_address,
                              file_addresses, data_addresses, files, triggers)
            
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
                block = b"\x23" + block_data + struct.pack("<H", u.crc(block_data))
            
            if this == 0:
                file_addresses.append(address)
            
            if address + len(block) > end_address - 1:
            
                # The block won't fit into the current ROM. Start a new one
                # and add it there along with the other blocks in the file.
                print("Block $%x in %s won't fit in the current ROM." % (this, repr(name)))
                
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
                    print("Splitting %s - moving block $%x to the next ROM." % (repr(name), this))
                    # Ensure that the first block in the new ROM has a full
                    # header.
                    block = chunk
                else:
                    print("Moving %s to the next ROM." % repr(name))
                    for old_block_info in blocks:
                        address += len(old_block_info.data)
            
            address += len(block)
            blocks.append(Block(block, info))
        
        files.append(blocks)
        blocks = []
        
        end = load + (this * 256) + len(block_data)
        if workspace != workspace_end and \
            (load <= workspace < end or load < workspace_end <= end):
            print("Warning: file %s [$%x,$%x) may overwrite ROM workspace: [$%x,$%x)" % (
                repr(name), load, end, workspace, workspace_end))
    
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
    r = 0
    
    for header, rom_file, rom in zip(headers, rom_files, roms):
    
        tf, temp_file = tempfile.mkstemp(suffix=os.extsep+'oph')
        _write(tf, header)
        
        files, file_addresses, triggers = rom
        
        # Discard the address of the first file.
        address = file_addresses.pop(0)
        print(rom_file)
        
        first_block = True
        file_details = []
        
        for blocks in files:
        
            file_name = ""
            load_addr = 0
            length = 0
            
            for b, block_info in enumerate(blocks):
            
                name, load, exec_, block_data, this, flags = block_info.info
                length += len(block_data)
                last = (b == len(blocks) - 1) and block_info.data[0] != 0x23
                
                # Potential flag modifications:
                #
                #if flags & 0x40 and len(block_data) != 0:
                #    flags = flags & 0xbf
                #if flags & 0x80 and not last:
                #    flags = flags & 0x7f
                
                if isinstance(block_info, Compressed):
                
                    _write(tf, "; %s %x\n" % (repr(name)[1:-1], this))
                    
                    if block_info.first_block:
                        next_address = file_addresses.pop(0)
                    
                    file_details.append((name, load, block_info))
                    length = 0
                    
                    if block_info.short_header:
                        data = b"\x23"
                    else:
                        data = write_block(u, name, load, exec_, block_data, this, flags, next_address)
                    
                    _write(tf, format_data(data))
                    
                    if block_info.first_block:
                        print(" %s starts at $%x and ends at $%x, next file at $%x" % (
                            repr(name), address, address + len(data),
                            next_address))
                
                elif this == 0 or last or first_block:
                    _write(tf, "; %s %x\n" % (repr(name)[1:-1], this))
                    
                    if last:
                        next_address = file_addresses.pop(0)
                        block_info.raw_length = length
                        length = 0
                        
                        if this == 0:
                            print(" %s starts at $%x and ends at $%x, next file at $%x" % (
                                repr(name), address, address + len(block_info.data),
                                next_address))
                    
                    elif this == 0:
                        file_name = name
                        load_addr = load
                        next_address = file_addresses[0]
                        print(" %s starts at $%x, next file at $%x" % (
                            repr(name), address, next_address))
                    
                    else:
                        next_address = file_addresses[0]
                        print(" %s continues at $%x, next file at $%x" % (
                            repr(name), address, next_address))
                    
                    first_block = False
                    
                    data = write_block(u, name, load, exec_, block_data, this, flags, next_address)
                    _write(tf, format_data(data))
                
                else:
                    _write(tf, "; %s %x\n" % (repr(name)[1:-1], this))
                    data = block_info.data
                    _write(tf, format_data(data))
                
                address += len(data)
        
        write_end_marker(tf)
        
        # If a list of triggers was compiled, write the compressed data after
        # the ROMFS data, and write the associated addresses at the end of the
        # ROM file.
        
        if triggers:
        
            _write(tf, "\n; Compressed data\n")
            _write(tf, ".alias after_triggers %i\n" % (len(triggers) * 2))
            
            addresses = []
            for info in file_details:
            
                # Unpack the file information.
                name, decomp_addr, block_info = info
                
                src_label = "src_%x" % id(block_info)
                
                if decomp_addr != "x":
                
                    addr = triggers.pop(0)
                    decomp_addr = decomp_addr & 0xffff
                    addresses.append(AddressInfo(name, addr, src_label, decomp_addr,
                        decomp_addr + block_info.raw_length, block_info.offset_bits))
                    
                    _write(tf, "\n; %s\n" % repr(name)[1:-1])
                    _write(tf, src_label + ":\n")
                    _write(tf, format_data(block_info.data))
            
            #_write(tf, "\n.alias debug %i" % (49 + roms.index(rom)))
            _write(tf, "\ntriggers:\n")
            
            for address_info in addresses:
                if address_info.decomp_addr != "x":
                    _write(tf, ".byte $%02x, $%02x ; %s\n" % (
                        address_info.addr & 0xff, address_info.addr >> 8,
                        repr(address_info.name)[1:-1]))
            
            _write(tf, "\nsrc_addresses:\n")
            
            for address_info in addresses:
                if address_info.decomp_addr != "x":
                    _write(tf, ".byte <%s, >%s\n" % (address_info.src_label,
                        address_info.src_label))
            
            _write(tf, "\ndest_addresses:\n")
            
            for address_info in addresses:
                if address_info.decomp_addr != "x":
                    _write(tf, ".byte $%02x, $%02x\n" % (
                        address_info.decomp_addr & 0xff,
                        address_info.decomp_addr >> 8))
            
            _write(tf, "\ndest_end_addresses:\n")
            
            for address_info in addresses:
                if address_info.decomp_addr != "x":
                    _write(tf, ".byte $%02x, $%02x\n" % (
                        address_info.decomp_end_addr & 0xff,
                        address_info.decomp_end_addr >> 8))
            
            _write(tf, "\noffset_bits_and_count_masks:\n")
            
            for address_info in addresses:
                if address_info.decomp_addr != "x":
                    offset_mask = (1 << address_info.offset_bits) - 1
                    count_mask = 0xff ^ offset_mask
                    _write(tf, ".byte $%02x    ; count mask\n" % count_mask)
                    _write(tf, ".byte %i     ; offset bits\n" % address_info.offset_bits)
            
            _write(tf, "\n")
            
            decomp_addrs = decomp_addrs[len(file_details):]
        
        elif details[r]["compress"]:
        
            # Ideally, we would remove the decompression code and rebuild the ROM.
            sys.stderr.write("ROM file %s contains unused decompression code.\n" % rom_file)
            _write(tf, ".alias after_triggers 0\n")
            _write(tf, "triggers:\n")
            _write(tf, "src_addresses:\n")
            _write(tf, "dest_addresses:\n")
            _write(tf, "dest_end_addresses:\n")
            _write(tf, "offset_bits_and_count_masks:\n")
        
        os.close(tf)
        if os.system("ophis -o " + shlex.quote(rom_file) + " " + shlex.quote(temp_file)) != 0:
            sys.exit(1)
        
        os.remove(temp_file)
        r += 1

def write_end_marker(tf):

    _write(tf, "end_of_romfs_marker:\n")
    _write(tf, ".byte $2b\n")

def get_data_address(header_file, rom_file):

    tf, temp_file = tempfile.mkstemp(suffix=os.extsep+'oph')
    _write(tf, header_file)
    # Include placeholder values.
    _write(tf, ".alias after_triggers 0\n")
    #_write(tf, ".alias debug 48\n")
    _write(tf, "triggers:\n")
    _write(tf, "src_addresses:\n")
    _write(tf, "dest_addresses:\n")
    _write(tf, "dest_end_addresses:\n")
    _write(tf, "offset_bits_and_count_masks:\n")
    _write(tf, "end_of_romfs_marker:\n")
    os.close(tf)
    
    if os.system("ophis -o " + shlex.quote(rom_file) + " " + shlex.quote(temp_file)):
        sys.exit(1)
    
    data_address = 0x8000 + os.stat(rom_file)[stat.ST_SIZE]
    os.remove(temp_file)
    
    return data_address


class ArgumentError(Exception):
    pass

def find_option(args, label, number = 0, missing_value = None):

    try:
        i = args.index(label)
    except ValueError:
        if number == 0:
            return False
        else:
            return False, missing_value
    
    values = args[i + 1:i + number + 1]
    args[:] = args[:i] + args[i + number + 1:]
    
    if number == 0:
        return True
    
    if len(values) < number:
        raise ArgumentError("Not enough values for argument '%s': %s" % (label, repr(values)))
    
    if number == 1:
        values = values[0]
    
    return True, values

def usage():
    sys.stderr.write(__usage__ % sys.argv[0])
    sys.stderr.write(__description__)
    sys.exit(1)

if __name__ == "__main__":

    args = sys.argv[:]
    indices = []
    
    details = [
        {"title": '.byte "", 0', # '.byte "Test ROM", 0',
         "version string": '.byte "", 0', # '.byte "1.0", 0',
         "version": ".byte 1",
         "copyright": '.byte "(C)", 0', # '.byte "(C) Original author", 0',
         "copyright offset": '.byte [copyright_string - rom_start - 1]',
         "rom name": '',
         "service entry command code": "",
         "service command code": "",
         "service boot code": "",
         "boot name": "!BOOT",
         "boot code": "",
         "init romfs code": "",
         "first rom bank init code": "",
         "first rom bank check code": "",
         "first rom bank behaviour code": "",
         "second rom bank check code": "",
         "second rom bank init code": "",
         "second rom bank pointer sync code": "",
         "decode code": "",
         "trigger check": "",
         "trigger routine": "",
         "last file check": "",
         "last file routine": "",
         "compress": False,
         "compress offset bits": None,
         "paging check": "",
         "paging routine": "",
         "custom command code": "",
         "custom init code": "",
         "custom init code jump": "",
         "custom boot page command": "",
         "plus one disable": ""},
        {"title": '.byte "", 0', # '.byte "Test ROM", 0',
         "version string": '.byte "", 0', # '.byte "1.0", 0',
         "version": ".byte 1",
         "copyright": '.byte "(C)", 0', # '.byte "(C) Original author", 0',
         "copyright offset": '.byte [copyright_string - rom_start - 1]',
         "rom name": '',
         "service entry command code": "",
         "service command code": "",
         "service boot code": "",
         "boot name": "!BOOT",
         "boot code": "",
         "init romfs code": "",
         "second rom bank check code": "",
         "second rom bank init code": "",
         "second rom bank pointer sync code": "",
         "decode code": "",
         "trigger check": "",
         "trigger routine": "",
         "last file check": "",
         "last file routine": "",
         "compress": False,
         "compress offset bits": None,
         "paging check": "",
         "paging routine": "",
         "custom command code": "",
         "custom init code": "",
         "custom init code jump": "",
         "custom boot page command": "",
         "plus one disable": ""}
        ]
    
    autobootable = find_option(args, "-a", 0)
    bootable = find_option(args, "-b", 0)
    custom_boot, custom_boot_page = find_option(args, "-B", 1, "")
    compress_files, hints = find_option(args, "-c", 1)
    compress_workspace, compress_workspace_start = find_option(args, "-C", 1, "90")
    compress_bits, compress_offset_bits = find_option(args, "-cbits", 1, None)
    compress_file_blocks, compress_block_size = find_option(args, "-cblk", 1, 512)
    f, files = find_option(args, "-f", 1)
    loop = find_option(args, "-l", 0)
    minimal = find_option(args, "-m", 0)
    paging_code, paging_info = find_option(args, "-P", 2)
    persistent_pointer = find_option(args, "-p", 0)
    split_files = find_option(args, "-s", 0)
    star_exec = find_option(args, "-x", 0)
    star_run = find_option(args, "-r", 0)
    tape_override = find_option(args, "-t", 0)
    tape_counter, tape_counter_value = find_option(args, "-tc", 1)
    fscheck_override = find_option(args, "-T", 0)
    use_workspace, workspace = find_option(args, "-w", 1, 0xa00)
    custom_star_command, custom_star_details = find_option(args, "-M", 2, "")
    custom_init_command, custom_init_details = find_option(args, "-I", 2, "")
    last_file_command, last_file_details = find_option(args, "-L", 2, "")
    patch_files, patch_file_name = find_option(args, "-pf", 1, "")
    joystick_enabled, joystick_info = find_option(args, "-j", 1, "")
    plus1_disable = find_option(args, "-p1", 0)
    custom_rom_name, rom_name = find_option(args, "-rn", 1, "MGC")
    custom_rom_title, rom_title = find_option(args, "-rt", 1, "MGC")
    custom_boot_name, boot_name = find_option(args, "-bf", 1, "!BOOT")
    
    if minimal and (tape_override or fscheck_override or use_workspace):
        sys.stderr.write("Cannot override *TAPE or use extra workspace in "
                         "minimal ROMs.\n")
        sys.exit(1)
    
    if plus1_disable:
        bootable = True
    
    if len(args) < 3:
        usage()
    
    uef_file = args[1]
    rom_files = args[2:]
    
    # Create enough structures for each of the ROM files to be generated.
    for r in range(2, len(rom_files)):
        details.append(details[1].copy())
    
    try:
        if f:
            pieces = files.split(":")
            for piece in pieces:
                if piece == "s":
                    indices.append("s")
                else:
                    if "-" in piece:
                        begin, end = piece.split("-")
                    else:
                        begin = end = piece
                    
                    indices += range(int(begin), int(end) + 1)
        
        if minimal:
            header_template = _open(minimal_header_template_file).read()
        else:
            header_template = _open(header_template_file).read()
        
        if not minimal:
            
            if use_workspace:
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
            details[0]["init romfs code"] = _open("asm/init_romfs.oph").read()
            
            # The second and subsequent ROMs can use a persistent ROM pointer.
            if persistent_pointer:
                for r in range(1, len(rom_files)):
                    details[r]["second rom bank check code"] = _open("asm/second_rom_bank_check.oph").read()
                    details[r]["second rom bank pointer sync code"] = _open("asm/second_rom_bank_sync.oph").read()
        
        if compress_files:
            # -c [<addr0>.[<exec0>]]:...:[<addrN>.[<execN>]];[<addrN+1>.[<execN+1>]]:...:[<addrM>.[<execM>]]
            # or use x instead of <addr>.[<exec>]
            decomp_addrs = []
            for i, addr_list in enumerate(hints.split("/")):
            
                if addr_list.strip() == "":
                    continue
                
                decomp_addrs.append([])
                do_compression = False
                
                for addrs in addr_list.split(":"):
                    if "." in addrs:
                        addr, execute = addrs.split(".")
                        execute = int(execute, 16)
                    else:
                        addr, execute = addrs, None
                    
                    if addr == "x":
                        decomp_addrs[-1].append(("x", execute))
                    elif addr:
                        decomp_addrs[-1].append((int(addr, 16), execute))
                        do_compression = True
                    else:
                        decomp_addrs[-1].append((None, execute))
                        do_compression = True
                
                if do_compression:
                
                    cws = int(compress_workspace_start, 16)
                    
                    if compress_offset_bits != None:
                        compress_offset_bits = int(compress_offset_bits)
                    
                    compress_block_size = int(compress_block_size)
                    
                    dp_dict = {
                        "src": cws, "src_low": cws, "src_high": cws + 1,
                        "dest": cws + 2, "dest_low": cws + 2, "dest_high": cws + 3,
                        "trigger_offset": cws + 4,
                        "special": cws + 5, "offset": cws + 6,
                        "from_low": cws + 7, "from_high": cws + 8
                        }
                    
                    details[i]["decode code"] = _open("asm/dp_decode.oph").read() % dp_dict
                    details[i]["trigger check"] = "jsr trigger_check\n"
                    details[i]["trigger routine"] = _open("asm/trigger_check.oph").read()
                    details[i]["compress"] = True
                    details[i]["compress offset bits"] = compress_offset_bits
        else:
            decomp_addrs = []
        
        if autobootable:
            details[0]["service boot code"] = _open("asm/service_boot.oph").read()
            bootable = True
        else:
            if bootable or custom_star_command:
                # Not auto-bootable but still bootable, so include code to
                # allow the ROM to be initialised.
                details[0]["service entry command code"] = _open("asm/service_entry_command.oph").read()
                details[0]["service command code"] = _open("asm/service_command.oph").read() % {
                    "run service command": "jmp rom_command"}
        
        if bootable:
            # Record the boot file name for later file creation.
            details[0]["boot name"] = boot_name
            if not custom_boot_name:
                # Just load the first file and ignore the default name.
                boot_name = ""
            
            details[0]["boot code"] = _open("asm/boot_code.oph").read() % {"boot name": boot_name}
            if minimal:
                # Minimal ROMs only need to call *ROM when booting.
                details[0]["init romfs code"] = _open("asm/init_romfs.oph").read()
            
            boot_commands = []
            
            if custom_boot:
                if custom_boot_page.startswith("0x"):
                    custom_boot_page = custom_boot_page[2:]
                elif custom_boot_page[:1] in "$&":
                    custom_boot_page = custom_boot_page[1:]
                
                # Add quotes for assember strings.
                boot_commands.append('"PAGE=&%X|M"' % int(custom_boot_page, 16))
            
            details[0]["boot commands"] = boot_commands
            
            if plus1_disable:
                details[0]["plus one disable"] = "\n".join([
                    "lda #163", "ldx #128", "ldy #1", "jsr $fff4",
                    "lda #$d6", "sta $212",
                    "lda #$f1", "sta $213",
                    "lda #0", "sta $2ac"
                    ])
        else:
            details[0]["boot code"] = "pla\npla\nlda #0\nrts"
        
        if paging_code:
            base_number_address, rom_indices = paging_info
            
            rom_indices = list(map(int, rom_indices.split(":")))
            
            if len(rom_indices) < len(rom_files):
                sys.stderr.write("Insufficient number of ROM indices specified.\n")
                sys.exit(1)
            
            for r, rom_index in enumerate(rom_indices):
                details[r]["paging check"] = _open("asm/paging_check.oph").read() % {
                    "base number address": int(base_number_address, 16),
                    "rom index": int(rom_index)
                    }
                details[r]["paging routine"] = _open("asm/paging_routine.oph").read()
        
        if not minimal or custom_star_command or custom_init_command or bootable or custom_rom_name:
            # Even though a minimal ROM without a custom star command doesn't
            # need a name, we apparently need one if we want autobooting to
            # work.
            details[0]["rom name"] = '.byte "%s", 13' % rom_name
        
        if custom_rom_title:
            details[0]["title"] = '.byte "%s", 13' % rom_title
        
        if minimal:
            if custom_star_command:
                custom_oph_file, custom_label = custom_star_details
                details[0]["service entry command code"] = _open("asm/service_entry_command.oph").read()
                details[0]["service command code"] = _open("asm/service_command.oph").read() % {
                    "run service command": "jsr %s\npla\ntax\npla\ntay\nlda #0\nrts" % custom_label}
                details[0]["custom command code"] = open(custom_oph_file).read()
            
            if custom_init_command:
                custom_oph_file, custom_label = custom_init_details
                details[0]["custom init code jump"] = "jsr %s" % custom_label
                details[0]["custom init code"] = open(custom_oph_file).read()
        
        if last_file_command:
            last_file_name, last_file_label = last_file_details
            
            details[-1]["last file check"] = "jsr last_file_check\n"
            if compress_files:
                last_file_wrapper = "asm/last_file_check_compressed.oph"
            else:
                last_file_wrapper = "asm/last_file_check.oph"
            
            print("Including", last_file_name, "to be called after all files have been loaded.")
            print("The", last_file_label, "subroutine will be called.")
            details[-1]["last file routine"] = \
                _open(last_file_wrapper).read() % {
                    "last_file_label": last_file_label,
                    "last_file_routine": open(last_file_name).read()
                    }
    
    except (IndexError, ValueError):
        usage()
    
    # Check that we have suitable input and output files.
    if len(rom_files) < 1:
        usage()
    
    # Create directories as required.
    for rom_file in rom_files:
    
        if rom_file.endswith(".uef"):
            sys.stderr.write("Unexpected file name '%s' passed for a ROM file.\n" % rom_file)
            sys.exit(1)
        
        dir_name, file_name = os.path.split(rom_file)
        if dir_name and not os.path.exists(dir_name):
            os.mkdir(dir_name)
    
    # The size of the workspace is determined in the romfs-template.oph file
    # and includes the two byte address for the BYTEV vector and an eight byte
    # routine to suppress *TAPE commands.
    workspace_end = workspace
    
    for r in range(len(rom_files)):
        details[r]["rom pointer"] = workspace
    
    if minimal:
        # Both ROM files are minimal. Do not use workspace for a persistent ROM
        # pointer or bank number.
        for r in range(len(rom_files)):
            details[r]["rom bank"] = workspace_end
    else:
        # For non-minimal single ROMs we use two bytes for the persistent ROM
        # pointer.
        workspace_end += 2
        for r in range(len(rom_files)):
            details[r]["rom bank"] = workspace_end
        
        if len(rom_files) > 1:
            # For more than one ROM we use an additional byte for the bank number.
            workspace_end += 1
            
            details[0]["first rom bank init code"] = _open("asm/first_rom_bank_init.oph").read()
            details[0]["first rom bank check code"] = _open("asm/first_rom_bank_check.oph").read()
            if loop:
                details[0]["first rom bank behaviour code"] = "jsr reset_pointer"
            else:
                details[0]["first rom bank behaviour code"] = "bne exit"
            
            second_rom_bank_init = _open("asm/second_rom_bank_init.oph").read()
            details[0]["second rom bank init code"] = second_rom_bank_init
            for r in range(1, len(rom_files)):
                details[r]["second rom bank init code"] = second_rom_bank_init
    
    # Add entries for tape interception, even if they are unused.
    details[0]["bytev"] = workspace_end
    details[0]["tape workspace"] = workspace_end + 2
    
    if tape_override or joystick_enabled:
        # Allow the vector to point to somewhere other than the code itself. This
        # enables us to borrow a JMP instruction elsewhere in memory to hide the
        # true location of our code.
        if tape_workspace_call_address is None:
            tape_workspace_call_address = details[0]["tape workspace"]
        
        if tape_workspace_call_address >= 0xc000:
            tape_init_code = _open("asm/tape_init_via_os_rom.oph").read()
        else:
            tape_init_code = _open("asm/tape_init.oph").read()
        
        details[0]["call tape init"] = "    jsr tape_init"
        # Move the end of the workspace to include the space for the old BYTEV
        # address and the bytes of the tape and joystick code in the new
        # routine.
        workspace_end += 2  # old BYTEV address
        workspace_end += 4  # core routine
        
        bytev_fragments = {
            "bytev": details[0]["bytev"],
            "bytev address": tape_workspace_call_address,
            "bytev tape check": "",
            "bytev counter check": "",
            "bytev counter": "",
            "bytev analogue check": "",
            "bytev analogue routines": ""
            }
        
        if tape_override:
            bytev_fragments["bytev tape check"] = _open("asm/bytev_tape_code.oph").read()
            workspace_end += 4
        
        if tape_counter:
            bytev_fragments["bytev counter check"] = _open("asm/bytev_tape_counter.oph").read()
            bytev_fragments["bytev counter"] = "bytev_counter: .byte %s" % tape_counter_value
            workspace_end += 13
        
        if joystick_enabled:
            analogue_code = (
                "    cmp #129\n"
                "    bne return_via_old_bytev\n"
                "    pha\n"
                )
            workspace_end += 5  # main check
            
            horizontal = vertical = False
            
            for key_info in joystick_info.split(":"):
                if key_info:
                    direction, keycode = key_info.split("=")
                    direction = direction.lower()
                    if direction in "lr": horizontal = True
                    if direction in "du": vertical = True
                    key_check_code, i = joystick.key_check(direction, keycode)
                    analogue_code += key_check_code
                    workspace_end += i
            
            analogue_code += (
                "    return_via_old_bytev_pop:\n"
                "    pla\n"
                )
            workspace_end += 1
            
            analogue_routines = (
                "    bytev_key_pressed:\n"
                "    pla\n"
                "    ldx #255\n"
                "    ldy #255\n"
                "    sec\n"
                "    rts\n"
                )
            workspace_end += 7
            
            if horizontal or vertical:
                analogue_routines += (
                    "bytev_read_analogue:\n"
                    "    sta $fc70\n"
                    "    lda $fc70\n"
                    "    rts\n"
                    )
                workspace_end += 7
            
            bytev_fragments["bytev analogue check"] = analogue_code
            bytev_fragments["bytev analogue routines"] = analogue_routines
        
        # Paste the fragments into the code to create a file to assemble.
        bytev_code = _open("asm/bytev_code.oph").read() % bytev_fragments
        
        # Create and write the source file.
        tf, temp_file = tempfile.mkstemp(suffix=os.extsep+'oph')
        _write(tf, bytev_code)
        os.close(tf)
        
        # Assemble the bytev code.
        tbf, temp_bytev_file = tempfile.mkstemp(suffix=os.extsep+'bytev')
        
        if os.system("ophis -o " + shlex.quote(temp_bytev_file) + " " + shlex.quote(temp_file)) != 0:
            sys.exit(1)
        
        os.remove(temp_file)
        bytev_asm_code = open(temp_bytev_file, "rb").read()
        os.remove(temp_bytev_file)
        
        details[0]["tape init"] = tape_init_code % {
            "bytev code": format_data(bytev_asm_code)
            }
        details[0]["tape workspace call address"] = tape_workspace_call_address
    else:
        details[0]["call tape init"] = ""
        details[0]["tape init"] = ""
        details[0]["tape workspace call address"] = details[0]["tape workspace"]
    
    details[0]["argsv"] = workspace_end
    details[0]["fscheck workspace"] = workspace_end + 2
    
    if fscheck_override:
        details[0]["fscheck init"] = _open("asm/fscheck_init.oph").read()
        details[0]["call fscheck init"] = "    jsr fscheck_init"
        workspace_end += 17
        
        fs_call = details[0]["fscheck workspace call address"] = details[0]["fscheck workspace"]
    
    else:
        details[0]["call fscheck init"] = ""
        details[0]["fscheck init"] = ""
        details[0]["fscheck workspace call address"] = 0
    
    print("Workspace starts at $%04x. Ends at $%04x." % (workspace, workspace_end), end=" ")
    print((workspace_end - workspace), "bytes of workspace used.")
    
    # Calculate the starting address of the ROM data by assembling the ROM
    # template files.
    minimal_header_template = _open(minimal_header_template_file).read()
    
    header_templates = [header_template % details[0]]
    for r in range(1, len(rom_files)):
        header_templates.append(minimal_header_template % details[r])
    
    data_addresses = []
    for r, header_template in enumerate(header_templates):
        data_addresses.append(get_data_address(header_template % details[r], rom_files[r]))
    
    u = UEFfile.UEFfile(uef_file)
    
    if patch_files:
        patcher.patch_files(u, patch_file_name)
    
    # Convert the UEF chunks to ROM data.
    convert_chunks(u, indices, decomp_addrs, data_addresses, header_templates,
                   details, rom_files)
    
    for rom_file in rom_files:
    
        if not os.path.exists(rom_file):
            continue
        
        length = os.stat(rom_file)[stat.ST_SIZE]
        used = length % 16384
        if used != 0:
            print("Free space in %s: %i %s." % (rom_file, 16384 - used,
                plural_str(16384 - used, "byte", "bytes")))
            data = open(rom_file, "rb").read()
            open(rom_file, "wb").write(data + (b"\xff" * (16384 - used))) 
    
    sys.exit()
