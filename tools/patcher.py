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
            position, offset, span_length, data = line.split()
        except ValueError:
            sys.stderr.write("Invalid syntax at line %i of patch file %s.\n" % (
                n, patch_file))
            sys.exit(1)
        
        position = int(position)
        offset = int(offset, 16)
        if span_length.startswith("0x"):
            span_length = int(span_length, 16)
        else:
            span_length = int(span_length, 10)
        
        bytes = ""
        for byte in data.split(","):
            bytes += chr(int(byte, 16))
        
        print "Replacing %i bytes at 0x%x with %i bytes." % (span_length,
            offset, len(bytes))
        
        # Obtain the information about the file at the specified position in the
        # UEF file.
        info = u.contents[position]
        
        # Obtain the file data and patch it with the new data.
        file_data = info["data"]
        file_data = file_data[:offset] + bytes + file_data[offset + span_length:]
        
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
