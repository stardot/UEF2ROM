#!/usr/bin/env python

# Copyright (C) 2016 David Boddie <david@boddie.org.uk>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# A type-annotated version of distance_pair.py for Cython to process.

import sys

def compress_blocks(list data, int block_size = 256, str window = "output"):

    """Splits the data into blocks of a given size and compresses them using
    all possible offset bits, retaining the smallest compressed data and the
    offset bits for each block and merging consecutive blocks with the same
    offset bits. Returns a list of pieces, where each piece contains the
    number of offset bits and the compressed data."""
    
    cdef list pieces = []
    cdef int current_bits = 0
    
    # Use the same special byte in all blocks so that we can concatenate blocks
    # with the same offset bits together.
    cdef int special = find_least_used(data)
    
    cdef int i = 0
    cdef list best
    cdef int offset_bits
    
    while i < len(data):
    
        block = data[i:i + block_size]
        best = []
        
        for offset_bits in range(1, 8):
            output = compress(block, special, offset_bits, window)
            
            if not best or len(output) < len(best[2]):
                best = [offset_bits, block, output]
        
        offset_bits, block, output = best
        
        if offset_bits == current_bits:
            # Discard the byte declaring the special value.
            output.pop(0)
            
            # Append the output to the data in the last piece.
            piece = pieces.pop()
            piece[1] += block
            piece[2] += output
        else:
            piece = best
            current_bits = offset_bits
        
        pieces.append(piece)
        
        i += block_size
    
    return pieces


def compress_file(list data, int offset_bits = 4, str window = "output"):

    cdef int special = find_least_used(data)
    return compress(data, special, offset_bits, window)


def compress(list data, int special, int offset_bits = 4, str window = "output"):

    cdef int max_offset = (1 << offset_bits) - 1
    cdef int max_length = (1 << (7 - offset_bits)) + 2
    
    cdef list output, match
    output = [special]
    
    cdef int i = 0
    cdef int b, k, end, length
    
    while i < len(data):
    
        best = []
        b = 0
        
        # Compare strings in the window with upcoming input, starting at the
        # beginning of the window.
        if window == "output":
            k = max(0, i - 128)
            end = i
        else:
            k = max(0, len(output) - 128)
            end = len(output)
        
        while k < end:
        
            if window == "output":
                match = find_match(data, k, i)
            else:
                match = find_match_in_compressed(output, data, k, i)
            
            # Find better matches, replacing those of equal length with later
            # ones as they are found.
            if len(match) >= len(best):
                best = match
                b = k
            
            k += 1
        
        length = len(best)
        
        if length <= 2:
        
            # If there is no match, or the match would be inefficient to record,
            # then just include the next byte in the window.
            
            # If the special byte occurs in the input, encode it using a
            # special sequence.
            if data[i] == special:
                output += [special, 0]
                i += 1
            else:
                output.append(data[i])
                i += 1
        
        else:
            # Otherwise, encode the special byte, offset from the end of the
            # window and length, skipping the corresponding number of matching
            # bytes in the input stream. Subtracting 3 from the length in the
            # second case but nothing from the offset avoids the possibility of
            # encoding a zero in the second byte, confusing the first two cases.
            #
            # special 0                 -> special
            #
            # Near references are defined using the number of bits passed in
            # the offset_bits parameter. These vary from 2 to 5:
            #
            # special 0llllloo          -> length (3-34), offset (1-3)
            # special 0llllooo          -> length (3-18), offset (1-7)
            # special 0llloooo          -> length (3-10), offset (1-15)
            # special 0llooooo          -> length (3-6), offset (1-31)
            #
            # Far references:
            # special 1ooooooo llllllll -> offset (1-128), length (4-259)
            
            if window == "output":
                offset = i - b
            else:
                offset = len(output) - b
            
            if length <= max_length and offset <= max_offset:
                # Store non-zero offset to avoid potential encoding of zero
                # in the second byte.
                output += [special, ((length - 3) << offset_bits) | offset]
                i += length
            
            elif length > 3:
                # Store offset - 1 and length - 4 to allow higher lengths
                # to be stored.
                output += [special, 0x80 | (offset - 1), length - 4]
                i += length
            
            elif data[i] == special:
                output += [special, 0]
                i += 1
            
            else:
                output.append(data[i])
                i += 1
    
    return output


def find_least_used(list data):

    cdef list freq = [0] * 256
    cdef int b
    
    for b in data:
        freq[b] += 1
    
    try:
        # Try to find an unused byte value.
        special = freq.index(0)
    except ValueError:
        # Find the least used byte value.
        pairs = map(lambda i: (freq[i], i), range(len(freq)))
        pairs.sort()
        special = pairs.pop(0)[1]
    
    return special


def find_match(list data, int k, int i):

    # Compare the bytes in the window, starting at index k, with the bytes in
    # the upcoming data, starting at index i.
    #
    # | data   i        |
    #          v
    # | window |        |
    #   ^           ^
    #   k --------- j
    
    cdef list match = []
    cdef int j = i
    
    while len(match) < 259:
    
        if j == len(data) or data[k] != data[j]:
            return match
        
        match.append(data[k])
        
        k += 1
        j += 1
    
    return match


def find_match_in_compressed(output, data, k, i):

    # Compare the bytes in the compressed data, starting at index k, with the
    # bytes in the upcoming data, starting at index i.
    #
    #          i
    # | data   |    ^   |
    #     k ------- j
    #     v
    # | output |
    
    match = []
    j = i
    
    while len(match) < 255 and k < len(output):
    
        if j == len(data) or output[k] != data[j]:
            return match
        
        match.append(output[k])
        
        k += 1
        j += 1
    
    return match


def decompress(list data, int offset_bits = 4, str window = "output", stop_at = None):

    cdef int offset_mask = (1 << offset_bits) - 1
    
    cdef int special = data[0]
    cdef list output = []
    
    cdef int i = 1
    cdef int b, j, offset, count
    
    while i < len(data):
    
        b = data[i]
        
        if b != special:
            output.append(b)
            i += 1
        else:
            offset = data[i + 1]
            if offset == 0:
                output.append(special)
                i += 2
            
            else:
                j = i
                
                if offset & 0x80 == 0:
                    count = (offset >> offset_bits) + 3
                    offset = offset & offset_mask
                    i += 2
                else:
                    offset = (offset & 0x7f) + 1
                    count = data[i + 2] + 4
                    i += 3
                
                if window == "compressed":
                    offset -= count
                
                while count > 0:
                    if window == "output":
                        output.append(output[-offset])
                    else:
                        output.append(data[j - offset - count])
                    count -= 1
        
        if stop_at != None and len(output) > stop_at:
            return data[:i], output
    
    return output


def decompress_blocks(list pieces, str window = "output"):

    """Decompresses and returns compressed data stored in the list of pieces,
    where each piece contains the number of offset bits to use and compressed
    data stored as a list of integers."""
    
    cdef list output = []
    cdef list piece, data, cdata
    cdef int offset_bits
    
    for piece in pieces:
    
        offset_bits, data, cdata = piece
        output += decompress(cdata, offset_bits, window)
    
    return output


def merge(list data):

    # Take the lowest 4 bits of each byte and pack them together, then take
    # the highest 4 bits of each byte and pack them together. Append the last
    # byte in an odd-sized stream.
    cdef list output = []
    
    cdef int i = 0
    while i < len(data) - 1:
        output.append((data[i] & 0x0f) | ((data[i+1] & 0x0f) << 4))
        i += 2
    
    i = 0
    while i < len(data) - 1:
        output.append((data[i] & 0xf0) | ((data[i+1] & 0xf0) >> 4))
        i += 2
    
    if len(data) % 2 == 1:
        output.append(data[-1])
    
    return output


def unmerge(list data):

    cdef list output = []
    
    cdef int i = 0
    hl = len(data)/2
    while i < hl:
        output.append(data[i] & 0x0f)
        output.append(data[i] >> 4)
        i += 1
    
    cdef int j = 0
    while i < hl*2:
        output[j] = output[j] | (data[i] & 0xf0)
        output[j+1] = output[j+1] | ((data[i] & 0x0f) << 4)
        i += 1
        j += 2
    
    if len(data) % 2 == 1:
        output.append(data[-1])
    
    return output
