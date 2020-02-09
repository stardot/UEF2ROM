#!/usr/bin/env python

"""
Copyright (C) 2018 David Boddie <david@boddie.org.uk>

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

import sys
import UEFfile

def get_updated_info(line):

    # Syntax: ! <position> <assignment0> ... <assignmentN>
    # <assignment> := <name>=<value>
    # <value> := 0x<hexadecimal>
    
    line = line[1:].strip()
    pieces = line.split()
    
    position = int(pieces.pop(0))
    
    info = {}
    for piece in pieces:
        if piece.count("=") != 1:
            raise ValueError
        
        name, value = piece.split("=")
        info[name] = int(value, 16)
    
    return position, info


def get_patched_data(line):

    position, offset, span_length, data = line.split()
    
    position = int(position)
    offset = int(offset, 16)
    if span_length.startswith("0x"):
        span_length = int(span_length, 16)
    else:
        span_length = int(span_length, 10)
    
    bytes = ""
    for byte in data.split(","):
        if "*" in byte:
            byte, count = byte.split("*")
            if count.startswith("0x"):
                count = int(count, 16)
            else:
                count = int(count, 10)
        else:
            count = 1
        bytes += chr(int(byte, 16)) * count
    
    return position, offset, span_length, bytes


def patch_files(u, patch_file):

    print "Applying patch file", patch_file
    
    f = open(patch_file)
    n = 0
    
    while True:
    
        line = f.readline()
        if not line:
            break
        
        n += 1
        line = line.strip()
        
        if not line or line.startswith("#"):
            continue
        
        try:
            if line.startswith("!"):
                position, new_info = get_updated_info(line)
            else:
                position, offset, span_length, bytes = get_patched_data(line)
        
        except ValueError:
            sys.stderr.write("Invalid syntax at line %i of patch file %s.\n" % (
                n, patch_file))
            sys.exit(1)
        
        # Obtain the information about the file at the specified position in the
        # UEF file.
        info = u.contents[position]
        
        # Obtain the file data.
        file_data = info["data"]
        
        if line.startswith("!"):
            # Change the attributes of the file.
            for name, value in new_info.items():
                info[name] = value
        else:
            # Patch the file data with the new data.
            file_data = file_data[:offset] + bytes + file_data[offset + span_length:]
            
            print "%i (%s): Replacing %i bytes at 0x%x with %i bytes." % (position,
                repr(info["name"]), span_length, offset, len(bytes))
        
        # Create UEF chunks for the modified file.
        chunks = u.create_chunks(info["name"], info["load"], info["exec"], file_data)
        
        # Replace the old chunks for the file with the new ones.
        start = info["position"]
        after = info["last position"] + 1
        u.chunks = u.chunks[:start] + chunks + u.chunks[after:]
        
        # Refresh the table of contents to ensure that chunks indices are
        # correct for future accesses.
        u.read_contents()
    
    f.close()


if __name__ == "__main__":

    if len(sys.argv) != 4:
        sys.stderr.write("Usage: %s <UEF file> <patch file> <new UEF file>\n" % sys.argv[0])
        sys.exit(1)
    
    uef_file = sys.argv[1]
    patch_file = sys.argv[2]
    new_uef_file = sys.argv[3]
    
    u = UEFfile.UEFfile(uef_file)
    
    patch_files(u, patch_file)
    
    try:
        u.write(new_uef_file, write_emulator_info = False)
    except UEFfile.UEFfile_error:
        sys.stderr.write("Failed to write the new UEF file: %s\n" % new_uef_file)
        sys.exit(1)
    
    sys.exit()
