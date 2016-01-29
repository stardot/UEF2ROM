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

header_template = """
.org $8000
.alias current_rom_id_address $f4
.alias set_current_rom_address $f5
.alias rom_pointer $f6
.alias OSRDRM $ffb9

rom_start:
.byte 0, 0, 0   ; null language entry
jmp service_entry

; ROM type
.byte $82       ; 6502 code (2), language ($40), service ($80)

copyright_offset:
.byte [copyright_string - rom_start - 1]

; Version
.byte %(version)i

; Title string
.byte "%(title)s", 0

; Version string
.byte "%(version string)s", 0

copyright_string:
.byte "%(copyright)s", 0

.byte 0

service_entry:

    cmp #$0d
    beq init_command
    cmp #$0e
    beq read_byte_command

    service_entry_exit:
    rts

init_command:

    pha
    jsr invert_rom_number
    cmp current_rom_id_address
    bcc exit

    lda #<data
    sta rom_pointer
    lda #>data
    sta [rom_pointer + 1]

    lda current_rom_id_address
    jsr invert_rom_number
    sta set_current_rom_address

claim:
    pla
    lda #0
    rts

exit:
    pla
    rts

read_byte_command:
    pha
    tya
    bmi os120

    jsr invert_rom_number
    cmp current_rom_id_address
    bne exit
    ldy #0
    lda (rom_pointer),y
    tay

claim1:
    inc rom_pointer
    bne claim
    inc [rom_pointer + 1]
    jmp claim

os120:
    jsr invert_rom_number

    tay
    jsr OSRDRM
    tay
    jmp claim1

invert_rom_number:
    lda set_current_rom_address
    eor #$ff
    and #$0f
    rts

data:
"""

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

def convert_chunks(u, data_address, tf):

    blocks = []
    files = []
    address = data_address
    
    for chunk in u.chunks:
    
        n, data = chunk
        
        if (n == 0x100 or n == 0x102) and data and data[0] == "\x2a":
        
            name, load, exec_, block, this, flags = read_block(chunk)
            blocks.append(chunk)
            
            if this == 0:
                # Record the starting addresses of each file.
                files.append(address)
            
            last = flags & 0x80
            
            if this == 0 or last:
                # The next block follows the normal header and block data.
                address += len(data)
            else:
                # The next block follows the continuation marker, raw block data
                # and the block checksum.
                address += len(block) + 3
            
            if last:
                print repr(name), "has length", address - files[-1]
    
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


if __name__ == "__main__":

    if len(sys.argv) != 3:
        sys.stderr.write("Usage: %s <UEF file> <ROM file>\n" % sys.argv[0])
        sys.exit(1)
    
    uef_file = sys.argv[1]
    rom_file = sys.argv[2]
    tf, temp_file = tempfile.mkstemp(suffix=os.extsep+'oph')
    
    details = {"title": "Test ROM",
               "version string": "1.0",
               "version": 1,
               "copyright": "(C) Original author"}
    
    u = UEFfile.UEFfile(uef_file)
    
    write_header(tf, details)
    os.system("ophis -o " + commands.mkarg(rom_file) + " " + commands.mkarg(temp_file))
    data_address = 0x8000 + os.stat(rom_file)[stat.ST_SIZE]
    convert_chunks(u, data_address, tf)
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
