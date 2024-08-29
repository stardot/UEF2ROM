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
simple, but it evolved into something less manageable.

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
looped. This is enabled with the `-l` option:

```
UEF2ROM.py -a -c :4300/: -l -s UEFs/TwelfthNight_E.uef ROMs/TwelfthNight-1.rom ROMs/TwelfthNight-2.rom
```

In this example, when the filing system reaches the end of the last file, the
ROM pointer is reset to the first file in the first ROM so that the software
can load the relevant data file.

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

### `-B` <address>

When using the `-a` or `-b` options, this option inserts boot code to set the
value of `PAGE` to the address specified.

**Example:** `-B 1900`

### `-bf` <file name>

### `-c`

### `-C`

### `-cbits`

### `-cblk`

### `-f`

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

### `-I`

### `-l`

### `-L`

### `-m`

Causes a minimal ROM to be generated. Minimal ROMs do not include support for
intercepting file systems calls and other features of non-minimal ROMs, but
this reduces their overhead, leaving more space for data.

### `-M`

### `-p`

When generating more than one ROM, the `-p` option is used to enable the
persistent ROM pointer for the second ROM. This requires the first ROM to be
a non-minimal ROM, meaning that the `-m` option cannot be used with this option.

### `-P`

### `-pf` <patch file name>

### `-r`

When `-a` or `-b` are used, this specifies that the first file should be loaded
and run using a `*RUN` command.

### `-rn` <name>

Customises the star command provided by the ROM, if `-b` is specified, to use
the name passed as an argument to this option.

**Example:** `-b -rn WHERE`

### `-rt` <title>

### `-s`

### `-t`

### `-tc`

### `-T`

### `-w`

### `-x`
