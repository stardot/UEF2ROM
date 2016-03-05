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

__author__ = "David Boddie <david@boddie.org.uk>"
__date__ = "2015-08-23"
__version__ = "0.1"
__license__ = "GNU General Public License (version 3 or later)"

import sys
from tools import makedfs, UEFfile

if __name__ == "__main__":

    if len(sys.argv) != 3:
        sys.stderr.write("Usage: %s <ssd file> <uef file>\n" % sys.argv[0])
        sys.exit(1)
    
    cat = makedfs.Catalogue(open(sys.argv[1]))
    title, disk_files = cat.read()
    
    files = []
    for file in disk_files:
        name = file.name
        if "." in name:
            name = name.split(".")[-1]
        info = (name, file.load_address, file.execution_address, file.data)
        files.append(info)
    
    u = UEFfile.UEFfile(creator = "ssd2uef.py " + __version__)
    u.minor = 6
    u.target_machine = "Electron"
    u.import_files(0, files, gap = True)
    
    u.write(sys.argv[2], write_emulator_info = False)
    sys.exit()
