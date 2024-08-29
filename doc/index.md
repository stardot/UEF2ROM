# UEF2ROM Manual

UEF2ROM is a tool for converting
[Unified Emulator Format (UEF)](https://en.wikipedia.org/wiki/Unified_Emulator_Format)
files containing cassette data for 8-bit Acorn computers into ROM files that
can be loaded into sideways ROM and RAM slots on those computers.

## Background

The majority of software titles for the Acorn Electron are distributed as UEF
files. Electron emulators can read them and there are various tools to read,
write and convert them to and from other formats.
UEF files can also be used with real hardware. Online and offline tools are
available that can convert data into audio files that can be played into an
Electron's cassette interface, assuming you have a suitable cable.

There are other ways to get data into and out of an Electron. Disk interfaces
and solid state add-ons that mimic disk interfaces provide convenient ways to
access data much more quickly than via the cassette interface.

In some situations it can be desirable to provide software in the form of ROMs,
either individually or in the form of a multi-ROM cartridge. In the 1980s,
certain kinds of ROM-based software on Acorn machines were stored using the
built-in ROM Filing System (RFS) which allowed software to be encoded, decoded
and used in a way that was very similar to how it would be used from cassette.

Much of the software available in UEF files is similar to the kinds of software
that were historically stored on ROM using RFS. Games software stored in this
way can be loaded from ROM into RAM without having to be rewritten to run from
ROM. UEF2ROM was designed for this use case. It enables some software provided
as UEF files to be converted into ROM files using RFS data structures to encode
the data. It also provides features to compress data, work around badly behaved
code (copy protection) and customise the resulting ROM files in various ways.

UEF2ROM is not very well designed. It grew from a simple proof of concept,
accumulating new features as problems or issues were encountered with UEF files
and their contents. Please bear this in mind when using the tool, but
especially if you need to modify the code. It started as something conceptually
simple and evolved into something less manageable.

## Examples

Some users will find it easier to apply UEF2ROM to their own use case by
following some examples. This may help to introduce the different features that
the tool provides.

In each example, we will refer to a UEF file in a `UEFs` directory. It is up to
you to create the `UEFs` directory and install the UEFs within. Links to the
files containing UEFs are provided. Similarly, you will need to create a `ROMs`
directory to hold the output files.

### A minimal ROM

The following command converts the `Where_E.uef` file (from
[Where_E.zip](https://www.stairwaytohell.com/electron/uefarchive/leisure/Micropower/Where_E.zip))
to a ROM called `Where.rom`:

```
UEF2ROM.py -m UEFs/Where_E.uef ROMs/Where.rom
```

The `-m` option tells UEF2ROM to create a minimal ROM, containing a basic RFS
structure to hold the files. This means that the user of the Electron will need
to select the filing system before loading the software as they would normally
do from cassette:

```
*ROM
CHAIN ""
```

This type of ROM leaves as much space for data as possible. It doesn't even
provide a help string.

### Providing a command

If you don't want the user to have to enter too many commands to run the
software, you can add a default star command entry point by using the `-b`
option:

```
UEF2ROM.py -b -m UEFs/Where_E.uef ROMs/Where.rom
```

This option doesn't cause the ROM to auto-boot when the machine is powered on,
or when Break is pressed. Instead, it responds to the default `MGC` command
when the user enters it in BASIC:

```
*MGC
```

This causes the RFS to be selected and the software to be run, using `CHAIN`
to load the first program as before.

### Custom commands

If the default command is unsuitable, the `-rn` option can be used with an
alternative command name:

```
UEF2ROM.py -b -rn WHERE -m UEFs/Where_E.uef ROMs/Where.rom
```

Now, the user can run the software from BASIC using the custom command:

```
*WHERE
```

This loads and runs the software in the same way as before.

### Using *RUN instead of CHAIN

If you use the `-b` option to provide a star command for the ROM, the code to
handle the command will use the `CHAIN` keyword in BASIC to load and run the
software. However, some pieces of software need to be run with the `*RUN`
command. One example of this is `Wychwood_RUN_BE.uef` (from
[Wychwood_RUN_BE.zip](https://www.stairwaytohell.com/electron/uefarchive/Larsoft/Wychwood_RUN_BE.zip)).

We use the `-r` option to tell UEF2ROM that the first file must be run with
`*RUN` not `CHAIN`:

```
UEF2ROM.py -b -m -r UEFs/Wychwood_RUN_BE.uef ROMs/Wychwood.rom
```

This runs the game correctly when the user uses the default `MGC` command.

### Auto-booting ROMs

It can be desirable to ensure that software on a ROM is run immediately when
the computer is powered up or rebooted, without user interaction.

The `-a` option is used to enable this behaviour for [Snapper](https://www.stairwaytohell.com/roms/Electron_Acornsoft_Snapper_Rom.zip):

```
UEF2ROM.py -a UEFs/Snapper_E.uef ROMs/Snapper.rom
```

If the ROM is present in sideways ROM or RAM, or in a standard ROM slot, the
game will load at boot if it is in a slot with a higher priority than BASIC.

### Persistent ROM pointer

Some software written for cassette takes short-cuts with file names because
the order of the files is predetermined and the software only needs to load or
run the next file on the cassette.
When running software like this from ROM, this causes a problem in that the
RFS does not keep track of the last or next file in the catalogue.

UEF2ROM allows us to work around this problem by providing a persistent ROM
pointer (or file pointer) that points to the current file block. This feature
is enabled by default and is disabled with the `-m` option.

Using the `-a` option to auto-boot the game, but no other options:

```
UEF2ROM.py -a UEFs/Snapper_E.uef ROMs/Snapper.rom
```

If the `-m` option is used, the loading process never gets past the loading
screen. Using a persistent ROM pointer solves this issue.

### Workspace

The persistent ROM pointer is stored in RAM, with a default address of &A00
($A00). While this may be suitable for some software, it can clash with files
loaded from ROM or workspace used by the programs as they load. The workaround
for this is to specify a workspace address.

In this case the `-w` option is used to specify a workspace address that will
not clash with the files in the ROM as they are loaded:

```
UEF2ROM.py -a -w 39f UEFs/NightmareMaze-MRM_E.uef ROMs/NightmareMaze.rom
```

Without this change of workspace address the game will overwrite the ROM
pointer and the game will repeatedly restart the loading process.

### Disabling `*TAPE`

Some games used the trick of running the `*TAPE` command during the loading
process to prevent users from copying them to disk, or to ensure that the
value of `PAGE` was set to a low value. This prevents games stored in RFS from
loading.

The `-t` option is used to add code that intercepts `*TAPE` calls:

```
UEF2ROM.py -a -w 39f -t UEFs/Stranded_E.uef ROMs/Stranded.rom
```

This option is often used with the `-w` option to specify where the ROM pointer
and `*TAPE` interception code should be stored. Another related option is `-T`
which disables file system checks.

### Choosing files

To save space, or to reduce loading time, it can be necessary to discard some
files when transferring them to ROM.

The `-f` option and its argument are used to select files by their position in
the UEF file, starting with 0 for the first file. In this example, the second
file in the UEF file is selected:

```
UEF2ROM.py -a -f 1 -r UEFs/Monsters_E.uef ROMs/Monsters.rom
```

In this case the `-r` option is also used because the second file needs to be
run using `*RUN` and it is now the first file in the ROM.

The syntax of the `-f` option's argument supports ranges of files as well as
lists of individual files. See the command line option documentation below for
more information.

### Multiple ROMs

When there are too many files to fit into one ROM, multiple ROMs can be
specified. Although some hardware supports the use of multiple ROMs, in most
situations it is only practical to use two ROMs together.

To generate two ROMs simply specify two ROM files:

```
UEF2ROM.py -a -m UEFs/KillerGorilla_E.uef ROMs/KillerGorilla-1.rom ROMs/KillerGorilla-2.rom
```

UEF2ROM will store files in the first ROM until one fails to fit. UEF2ROM will
then try to store the file in the second ROM and continue using that ROM until
all files are stored or another fails to fit. It never returns to the first ROM
to store more files.

### Splitting files

When using two or more ROMs a situation can occur where a file is encountered
that is too large to fit in the remaining space in the first ROM, but which is
also too large for the empty second ROM. Sometimes the combined free space is
large enough to fit the file if it is split.

Using the `-s` option splits the file at the block level so that it can fit in
the free space provided by both ROMs:

```
UEF2ROM.py -a -m -s UEFs/Boxer_E.uef ROMs/Boxer-1.rom ROMs/Boxer-2.rom
```

Without the `-s` option, the second file would be too large (16409 bytes) to
fit in a single ROM.

### Compressing files

Selecting/discarding files, using multiple ROMs and splitting files at the
block level fail may not do enough to fit files into ROMs. When this happens
the next step is to compress files so that they fit.

The `-c` option and its argument are used to specify which files should be
compressed:

```
UEF2ROM.py -a -m -c e00 UEFs/Skirmish_E.uef ROMs/Skirmish.rom
```

In this simple case, the `-c` option enables compression for all files that are
stored in the ROM. The argument refers to the load address for the first file
in the UEF, overriding the load address meta-data in the UEF.

The colon character is used to separate addresses in the `-c` option's argument.
In this case the second address is prefixed by a period because it is an
execute address instead of a load address:

```
UEF2ROM.py -a -m -c e00:.4700 UEFs/MagicMushrooms_E.uef ROMs/MagicMushrooms.rom
```

This overrides the meta-data in the UEF file for the second file, keeping its
load address but ensuring that the code at &4700 ($4700) is run when the file
is decompressed into RAM.

It can be useful to leave some files uncompressed. This is done by specifying
`x` as the address in the `-c` option's argument:

```
UEF2ROM.py -a -m -r -c x:/: UEFs/LastOfTheFree_E.uef ROMs/LastOfTheFree-1.rom ROMs/LastOfTheFree-2.rom
```

This is useful for files that are so small that the compression algorithm is
inefficient, or when there are unforseen problems with decompression.

The mechanism used to decompress files also has the effect of making them load
much faster, so this option may be useful even if there are no issues fitting
files into one or two ROMs.

The `-c` option is covered in more detail in the command line option
documentation below.

### Disabling file system checks

Some games tried to prevent users from overriding the `*TAPE` command by using
checks for the current filing system.

The `-T` option inserts code to report the cassette filing system (CFS) as the
current filing system:

```
UEF2ROM.py -a -T -w 39f UEFs/DiamondPete_E.uef ROMs/DiamondPete-1.rom ROMs/DiamondPete-2.rom
```

This option is often used with the `-w` option to specify where the interception
code should be stored.

### Disabling the Plus 1

Some games do not run correctly with the Plus 1 enabled. Many were released
with notes containing commands that the user needed to input before loading
them.

The `-p1` option is used to insert boot code to disable the Plus 1:

```
UEF2ROM.py -a -m -p1 UEFs/EscapeFromMoonbaseAlpha_E.uef ROMs/EscapeFromMoonbaseAlpha.rom
```

The code itself is executed as part of the generated `!BOOT` file and is not
input as a series of BASIC commands.

### Looping ROMs

Some software is designed as a series of programs that run each other, such as
a suite of applications or a menu with a series of games. When used from
cassette, the user would rewind to the beginning of the cassette when reloading
a menu program, for example.

This use case isn't well supported by RFS in the case where the files are
distributed across multiple ROMs. Once a ROM has been read, it isn't revisited.

UEF2ROM allows earlier ROMs to be revisited by allowing a set of ROMs to be
looped. This is enabled with the `-l` option for non-minimal ROMs:

```
UEF2ROM.py -a -c :4300/: -l -s UEFs/TwelfthNight_E.uef ROMs/TwelfthNight-1.rom ROMs/TwelfthNight-2.rom
```

In this example, when the filing system reaches the end of the last file, the
ROM pointer is reset to the first file in the first ROM so that the software
can load the relevant data file.

### Workspace indirection

Some games would check for indirection of vectors to prevent the user from
redirecting `*TAPE` and intercepting other system calls. This is a problem
when using the `-t` option to disable the `*TAPE` command. However, if the
checks are simple enough then a workaround can be used to prevent the game
from detecting that vectors have been redirected.

The `-w` option is used with an additional address, separated from the first
by a colon:

```
UEF2ROM.py -a -c :/:x:4600 -s -t -w d3f:ef97 UEFs/BeachHead_E.uef ROMs/BeachHead-1.rom ROMs/BeachHead-2.rom
```

This uses workspace at &D3f ($d3f) but redirects the BYTEV vector to &EF97
($ef97) which is a location in the OS ROM. This address will pass the vector
table checks in some games because they are only looking for addresses in RAM.
Redirecting BYTEV to an arbitrary address in ROM may seem like a bad idea but
the contents of this address is a sequence of three bytes that correspond to
the instruction `JMP &D44` which is in the workspace block. The result is that
`*TAPE` calls are still intercepted, but are not detected by these games.

## Features

### Persistent ROM pointer

Normal RFS ROMs require that software is written to use file names when loading
and running files. For example:

```
CHAIN "LOADER"
*RUN CODE
```

However, with cassette software, the file name is often unnecessary because it
the files are stored in the order in which they need to be loaded.


### Minimal ROMs

Minimal ROMs are supported by the `asm/romfs-minimal-template.oph` file.


## Command line options

### `-b`

Enables a star command that can be used to load the software stored in the ROM.
The default command is `MGC` but this can be changed with the `-rn` option.

### `-B <address>`

When using the `-a` or `-b` options, this option inserts boot code to set the
value of `PAGE` to the address specified.

**Example:** `-B 1900`

### `-bf <file name>`

Customises the name of the boot file when the `-a` or `-b` options are used to
the file name specified.

### `-c`



### `-C`

### `-cbits`

### `-cblk`

### `-f <files>`

Selects files by their positions in the UEF file, starting from an index of 0.

**Example:** `-f 1` selects the second file.

Lists of files can be specified, with the colon character being used to
separate indices.

**Example:** `-f 2:4` selects the third and fifth files.

Ranges of files can also be specified.

**Example:** `-f 1-3` selects the second, third and fourth files.

These can be mixed to select individual files and ranges of files.

**Example:** `-f 1-3:5` selects the second, third, fourth and sixth files.

A special value of `s` can be used to indicate the end of a ROM, so that files
following this will be added to a new ROM. More than one ROM file must be
specified.

**Example:** `-f 2-4:s:5-6` puts the sixth and seventh files in the second ROM.

### `-I <oph file> <label>`

Similar to the `-M` option except that the custom code is not tied to a star
command and will be run before any other initialisation code that is inserted
into the ROM by other options.

### `-l`

Allows the persistent ROM pointer to loop back to the first ROM in a set of
multiple ROMs. Cannot be used with minimal ROMs.

### `-L <oph file> <label>`

Allows a custom piece of code to be run after the last file has been read,
accepting the name of the Ophis file to assemble and the name of the label in
the file that is the start of the subroutine to call.

**Example:** `-L postload/southern_belle.oph postload`

### `-m`

Causes a minimal ROM to be generated. Minimal ROMs do not include support for
intercepting file systems calls and other features of non-minimal ROMs, but
this reduces their overhead, leaving more space for data.

### `-M <oph file> <label>`

Allows a custom piece of code to be used to respond to the star command that is
used when the `-b` option is specified, and which can be customised with the
`-rn` option.

### `-p`

When generating more than one ROM, the `-p` option is used to enable the
persistent ROM pointer for the second ROM. This requires the first ROM to be
a non-minimal ROM, meaning that the `-m` option cannot be used with this option.

### `-P <address> <ROM indices>`

Includes code that writes to a paging register to switch between ROMs when the
end of RFS data is reached. This enables more than two ROMs to be used together,
but requires that some hardware implements a paging register at &FC00 ($fc00)
and records a bank number at &290 ($290). This is designed for use with the
Mega Games Cartridge (MGC).

The address specifies where in RAM the bank number is stored for the current
ROM. When paging occurs, this address is used to find the base number for a
set of ROMs. The number for the next bank is added to the base number and
the result is written to the paging register.

The ROM indices indicate the order of ROMs in a set as a colon-separated list
of decimal integers. For each ROM, the entry in the list gives the index of the
next ROM in the set to page in.

**Example:** `-P 290 1:2:3:1`

In this example, the first ROM (0) will be paged in initially, then the second
(1), third (2) and fourth (3) ROMs will be paged in when the end of the files
in the previous ROMs are encountered. Finally, after the fourth ROM has been
read, the second (1) ROM is paged in.

### `-pf <patch file name>`

Specifies a patch file that is used to apply patches to the files in the UEF
file before they are stored in ROM.

The patch file contains a sequence of lines. Blank lines or those beginning
with a `#` character are ignored. Each line describes either a patch to a
particular file or a change to a file's meta-data.

A patch is a line containing four whitespace-separated fields. The first field
is the index of the file in the UEF file, starting at 0. The second field is
the offset from the start of the file. The third field describes the length of
a span of data to replace. The fourth field contains the data to replace the
span of data expressed as a comma-separated sequence of hexadecimal values.

**Example:** `0 0x3d7 16 1c,0e,0f,18,0b,0c,0c,87,8d,41,76,69,61,74,6f,72`

This example selects the first file in the UEF file, patching data at offset
0x3d7, replacing a span of data 16 bytes in length with a sequence of bytes of
the same length.

If the length of the replacement data is smaller than that of the original data,
the file decreases in size. If the replacement data is larger, the file
increases in size.

Changes to meta-data are indicated by a line that begins with a `!` character.
The second field on the line is the index of the file to modify. Each subsequent
field describes a modification to the file's meta-data.

**Example:** `! 2 load=0xd00`

In this case, the `load` attribute is changed. The only other valid attribute
is `exec`.

### `-r`

When the `-a` or `-b` options are used, this specifies that the first file
should be loaded and run using a `*RUN` command.

### `-rn` <name>

Customises the star command provided by the ROM, if `-b` is specified, to use
the name passed as an argument to this option.

**Example:** `-b -rn WHERE`

### `-rt <title>`

Allows the ROM title to be customised from the default, "MGC". This is only
usually visible in lists of ROMs produced by various utilities.

### `-s`

When using multiple ROMs, specifies that files can be split at the block level
across ROM boundaries instead of requiring files to be kept whole and stored
only on a single ROM.

This is useful when individual files are larger than 16K in size, but it is
also a good way to ensure that ROM space is used efficiently.

### `-t`

Includes code for disabling `*TAPE` calls.

This can only be used with non-minimal ROMs and uses additional workspace.
The `-w` option can be used to customise the address used for the workspace.

### `-tc <value>`

Adds support for a tape counter check that restores the original address for the
BYTEV vector when the value reaches zero. The idea for this was to trick
software into loading from ROM but then restore its ability to select the
cassette filing system after it has loaded.

### `-T`

Includes code for disabling file system checks.

This can only be used with non-minimal ROMs and uses additional workspace.
The `-w` option can be used to customise the address used for the workspace.

### `-w <address>[:<fsbyte address>]`

Specifies the address of the workspace in RAM used by ROMs created with UEF2ROM.
The default address for the workspace is &A00 ($a00).

**Example:** `-w 39f`

Minimal ROMs with no additional features do not use any workspace. Non-minimal
ROMs require at least two bytes for the persistent ROM pointer. Features like
`*TAPE` suppression increase the size of the workspace.

UEF2ROM will print the amount of workspace that a ROM needs to the console when
creating it.

An second address can also be specified after a colon character. This specifies
a replacement address for the BYTEV vector to be used instead of the address at
the end of the workspace. This is used in cases where it is necessary to trick
software that checks addresses in the vector table.

### `-x`

When the `-a` or `-b` options are used, this specifies that the first file
should be loaded and run using a `*EXEC` command.
