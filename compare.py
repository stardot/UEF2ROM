#!/usr/bin/env python

import glob, os, sys

if __name__ == "__main__":

    if len(sys.argv) != 3:
        sys.stderr.write("Usage: %s <ROM directory 1> <ROM directory 2>\n" % sys.argv[0])
        sys.exit(1)
    
    romdir1 = sys.argv[1]
    romdir2 = sys.argv[2]
    
    roms1 = glob.glob(os.path.join(romdir1, "*.rom"))
    roms2 = glob.glob(os.path.join(romdir2, "*.rom"))
    
    names1 = []
    for rom in roms1:
        names1.append(os.path.split(rom)[1])
    
    names2 = []
    for rom in roms2:
        names2.append(os.path.split(rom)[1])
    
    common = set(names1).intersection(names2)
    common = list(common)
    common.sort()
    
    for name in common:
        if open(os.path.join(romdir1, name)).read() == open(os.path.join(romdir2, name)).read():
            continue
        
        os.system("hd " + os.path.join(romdir1, name) + " > t1.txt")
        os.system("hd " + os.path.join(romdir2, name) + " > t2.txt")
        sys.stdout.write(name + "\n")
        sys.stdout.flush()
        os.system("diff -u t1.txt t2.txt")
    
    sys.exit()
