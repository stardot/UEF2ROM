UEF2ROM - a UEF to ROM Conversion Tool for Acorn Electron ROM Cartridges
========================================================================

This repository contains a tool for modern computers that converts UEF files
containing representations of cassette software for the Acorn Electron to ROM
images for use in ROM cartridges or sideways ROM expansions.

The tool requires Ophis to be installed in order to assemble 6502 code needed
for the ROM images it creates:

https://michaelcmartin.github.io/Ophis/

Features
--------

I've implemented three things in my ROMs that make it possible to convert
cassette-based games to one or two ROM images:

 1. A persistent ROM pointer that can be used to remember where in the ROM the
    filing system was reading from, so that when it gets the inevitable
    initialisation call, it doesn't automatically return to the start of the
    data.
 2. Code to intercept `*TAPE` calls - surprisingly few games need this.
 3. A ROM bank variable that is set by the first and second ROMs so that when
    the first ROM is encountered after the second ROM has been read (thanks to
    an init call) it can pretend it can't handle the call, leaving the filing
    system to go looking for files in the second ROM.

The last of these is useful because I split files across ROMs and this confuses
the filing system, causing it to finish reading the split file in the second
ROM, but then returning to the first ROM to look for any following files. If I
don't either reset the persistent pointer or reject the call, an invalid
pointer is used and I get a "Bad ROM" error.

See http://stardot.org.uk/forums/viewtopic.php?f=2&t=1095 for a discussion
about similar tools.

Usage
-----

The `UEF2ROM.py` script is (over)complicated and provides many options to help
produce heavily customised ROMs based on existing, unmodified UEF files.
However, it might be possible to convert a small UEF into a single ROM using
the following command:

  UEF2ROM.py -a -m -s <UEF file> rom1

If the contents of the UEF file does not fit into the number of ROMs, it is
possible to either use two ROM images or compress files using the `-c` option
and a colon separated list of load addresses. For example, to compress the
files to fit into one ROM:

  UEF2ROM.py -a -c e00:x -m -s <UEF file> rom1

Alternatively, to use two ROMs:

  UEF2ROM.py -a -m -s <UEF file> rom1 rom2

If a pair of ROMs is not enough then compression can be specified for the files
that fit into one of the ROMs:

  UEF2ROM.py -a -c e00:x/ -m -s <UEF file> rom1 rom2

Using `x` in a list of load addresses indicates that the corresponding file in
the UEF file should not be compressed. If you omit a load address for a file
then the meta-data in the UEF file will be used. The `/` character separates
the load addresses used for the files in each ROM.

If the software in the UEF file performs `*TAPE` commands, making it fail when
run from ROM, code to suppress this system call can be inserted into the
generated ROM with the `-t` option. This is typically used with the `-w` option
to specify where the suppression code should be stored in RAM, as in the
following example:

  UEF2ROM.py -a -m -t -w 39f <UEF file> rom1

Because different pieces of software use different parts of memory, some
experimentation may be needed to find a suitable memory location for the tape
suppression code.

Limitations
-----------

There are many other options to use to work around issues with many existing
UEF files. However, not all UEF files can be used as they are. Many contain too
many files to fit into two ROMs, though the tool does support a paging
mechanism for the Mega Games Cartridge that allows long sequences of ROMs to be
created. Others rely on filing system features that are not supported by the
ROM filing system that this tool relies on. Additionally, a lot of software
written in the 1980s was designed to only run from tape-based systems and
contains hostile checks for expansion hardware. Some of these can be bypassed
but this tool does not provide a general solution for this problem.

Licenses
--------

Both the assembly language routines and the Python modules and tools are
licensed under the GNU General Public License version 3 or later:

  Copyright (C) 2016 David Boddie <david@boddie.org.uk>
 
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

According to the GPL FAQ, an installer and the files it installs are considered
to be separate works:

  http://www.gnu.org/licenses/gpl-faq.html#GPLCompatInstaller

This means that compliance with the above license with respect to the routines
provided in this package is independent of compliance with the license of the
code or data you include in an assembled ROM file.

The code or data you include in an assembled ROM file will retain its original
copyright and license which must be handled accordingly. Including a work in an
assembled ROM file does not exempt you from any obligations you have under that
work's license.
