This tool requires Ophis to assemble 6502 code:

https://michaelcmartin.github.io/Ophis/

I've implemented three things in my ROMs that make it possible to convert
cassette-based games to one or two ROM images:

 1. A persistent ROM pointer that can be used to remember where in the ROM the
    filing system was reading from, so that when it gets the inevitable
    initialisation call, it doesn't automatically return to the start of the
    data.
 2. Code to intercept *TAPE calls - surprisingly few games need this.
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
