# Based: BOTW Assembly Editor

Simple tool to create code patches for *The Legend of Zelda: Breath of the Wild*

## Setup

Supports Windows and most modern Linux distros. On Windows, requires the
[WebView2 runtime](https://go.microsoft.com/fwlink/p/?LinkId=2124703).

- Download the latest release for your platform
- Extract wherever you want
- Run the executable (`based.exe` on Windows or just `based` on Linux)

## Usage

There are two ways to use Based: directly patching your BOTW RPX or creating
a `Patches.hax` file that can be used with [CafeLoader](https://github.com/aboood40091/CafeLoader).
*CafeLoader is the recommended method,* but Based was originally designed for
RPX patching.

Based supports patching individual assembly instructions at specified offsets.
Injecting *new* code is not yet supported and may or may not ever be.

### Adding Patches

There are two ways to add patches: manually entering the instruction address
and new assembly or importing an existing code patch. Two patch formats are
supported for import: Cemu patches (select the `rules.txt`) and CafeLoader
patches (`Patches.hax`).

When manually adding patches, make sure to use the offset as displayed in Cemu
or Ghidra, which will usually start with `0x02` for code and `0x1` for data. The
provided address must be 8 digits long (10 characters if you count the `0x`
prefix).

If you import a Cemu code patch, Based will check for any preset variables and,
if there are any, require you to select the preset you would like to use. 
*Patches with a code cave section (i.e. they add new code) are not supported.*

Once you have added the patches you want to use, you need to actually create
your executable mod, either by patching the RPX or creating a CafeLoader patch
(recommended).

### CafeLoader Method (Recommended)

For CafeLoader, the process is simple. Once you have added your patches, click
"Create Patches.hax" and your patch file will be created. Put it on your SD card
under `/cafeloader/TITLEID/`, where, obviously, `TITLEID` is the title ID of
your game. For USA users, that will be `00050000101C9400`.

If you do not already have CafeLoader installed, this too is easy. Download the
Wii U Plugin Loader (like any other Wii U homebrew app), and then download the
[latest CafeLoader release](https://github.com/aboood40091/CafeLoader/releases/latest).
Put the `cafeloader.mod` file on your SD card under `/wiiu/plugins/`. Then open
the plugin loader from the Homebrew Launcher, tick CafeLoader on, and play BOTW.

### RPX Patching Method

Now that Based supports CafeLoader, it is highly recommended. But if for any
reason you want to patch your RPX instead, simply select your unmodded
`U-King.rpx` file from your dump (make sure to use the update copy, not the
base game), select where to save your modified RPX, and then click "Apply
Patches." You will need to transfer your modded RPX to your Wii U to replace
the old one. For that use FTPiiU, and check online for guides. I won't hold
your hand because I don't recommend this method anymore anyway.

## Contributing

It is *possible* that Based could support adding new code. If anyone figures it
out, submit a PR, please. The main requirements will be (1) finding regions of
unused code in executable and (2) making sure it can be compiled and integrated
correctly.

## License

Based is licensed under the GPL 3, read all about it 
[here](https://www.gnu.org/licenses/gpl-3.0.en.html). The release packages also
include a copy of Wii U RPX Tool, which is also under the GPL 3 and the source
is available [here](https://github.com/0CBH0/wiiurpxtool/).
