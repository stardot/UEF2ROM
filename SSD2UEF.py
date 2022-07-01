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

__author__ = "David Boddie <david@boddie.org.uk>"
__date__ = "2022-06-18"
__version__ = "0.4"
__license__ = "GNU General Public License (version 3 or later)"

import sys
from tools import makedfs, UEFfile

if __name__ == "__main__":

    args = sys.argv[:]
    
    if "-s" in args:
        at = args.index("-s")
        strip_prefix = args[at + 1].encode("latin1")
        args = args[:at] + args[at + 2:]
    else:
        strip_prefix = b"$."
    
    if not 3 <= len(args) <= 4:
        sys.stderr.write("Usage: %s <ssd file> <uef file> [file0,...]\n" % args[0])
        sys.stderr.write("Usage: %s -l <ssd file>\n" % args[0])
        sys.exit(1)
    
    if args[1] == "-l":
        print_catalogue = True
        ssd_file = args[2]
    else:
        print_catalogue = False
        ssd_file = args[1]
        uef_file = args[2]
    
    cat = makedfs.Catalogue(open(ssd_file, "rb"))
    if ssd_file.endswith(".dsd"):
        cat.interleaved = True
    
    title, disk_files = cat.read()
    
    if print_catalogue:
        max_length = 0
        for file in disk_files:
            max_length = max(max_length, len(repr(file.name)))
        
        print(repr(title))
        for file in disk_files:
            spacing = " " * (max_length - len(repr(file.name)))
            print(repr(file.name), spacing + "%08x %08x %x" % (
                file.load_address, file.execution_address, file.length))
        
        sys.exit()
    
    if len(args) == 4:
        names = [x.encode("latin1") for x in args[3].split(",")]
    else:
        names = []
        for file in disk_files:
            names.append(file.name)
    
    index = {}
    for file in disk_files:
        index[file.name] = file
    
    files = []
    for name in names:
        bname = name
        try:
            file = index[bname]
        except KeyError:
            sys.stderr.write("File '%s' not found in the disk catalogue.\n" % name)
            sys.exit(1)
        
        if bname.startswith(strip_prefix):
            bname = bname.lstrip(strip_prefix)
        
        info = (bname, file.load_address, file.execution_address, file.data)
        files.append(info)
    
    u = UEFfile.UEFfile(creator = "SSD2UEF.py " + __version__)
    u.minor = 6
    u.target_machine = "Electron"
    u.import_files(0, files, gap = True)
    
    u.write(uef_file, write_emulator_info = False)
    sys.exit()
