#!/usr/bin/env python

import glob, os, sys

if __name__ == "__main__":

    if len(sys.argv) != 2:
        sys.stderr.write("Usage: %s <ROM directory>\n" % sys.argv[0])
        sys.exit(1)
    
    romdir = sys.argv[1]
    
    roms = glob.glob(os.path.join(romdir, "*"))
    max_name = 0
    results = []
    
    for rom in roms:
    
        data = open(rom, "rb").read()
        i = len(data) - 1
        while i >= 0:
            if data[i] != "\xff":
                break
            i -= 1
        
        name = os.path.split(rom)[1]
        max_name = max(len(name), max_name)
        results.append((name, len(data) - i))
    
    results.sort()
    result_format = "{:%i} {}" % max_name
    
    for name, free in results:
        print result_format.format(name, free)
    
    sys.exit()
