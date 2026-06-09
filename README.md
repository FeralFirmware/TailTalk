# TailTalk

TailTalk is designed as a "toolkit" for building fully userspace AppleTalk implementations on Linux, and later Mac OS and Windows
systems. It is built from scratch with zero dependencies on Netatalk or any kernel drivers - All it needs is a raw socket and 
patience for grumpy old computers. It provides a complete AppleTalk stack, with multiple copies of it able to run on the same machine 
at the same time.

I started this project to be able to copy files to/from my old Macs, print to LaserWriters and networked StyleWriters, and be able
to write modern async software to communicate with them. It is not meant to support the full feature set of Netatalk, but rather 
communicate with small networks of a couple Macs and printers. Zones, routing, and other similar features are beyond the scope
of this project.

Each part of the stack is meant to be as "zero config" as possible, just like running on a Mac of the era. Just plug it in, 
launch and things should just work without any fuss.

This project is very much a work in progress prototype, so expect bugs and missing features. `expect` and `unwrap` are used
far too often during my prototyping and will be replaced with proper error handling in time.

## Features

Packet parsers and fully async APIs for almost all the major AppleTalk protocols.

- AppleTalk Address Resolution Protocol (AARP)
- Datagram Delivery Protocol (DDP)
- Name Binding Protocol (NBP)
- AppleTalk Transaction Protocol (ATP)
- Printer Access Protocol (PAP)
- AppleTalk Session Protocol (ASP)
- AppleTalk Filing Protocol (AFP)
- AppleTalk Data Stream Protocol (ADSP - untested) 

It additionally supports running with TashTalk for LocalTalk Macs.

## Building

### Prerequisites

This project requires Rust 1.90 or above, which can be installed from [rustup.rs](https://rustup.rs). This should install
a matching compiler for your OS and CPU architecture by default.

This project uses [cargo-packager](github.com/crabnebula-dev/cargo-packager) for building AppImage for Linux, and App bundles
for macOS and installers for Windows. Install it with `cargo install cargo-packager`.

### Windows Only

Ensure you have the Windows MSVC prerequisites installed as specified in the [rustup book](https://rust-lang.github.io/rustup/installation/windows-msvc.html).

Windows requires the npcap SDK to be saved somewhere on your machine. It is available at [npcap.com](https://npcap.com/#download). Point a LIB environment variable to the folder where you unzipped the SDK, such as:
``` C:\npcap-sdk-1.13\Lib\x64```


### Running the build

Once the prerequisites are installed, run `cargo build --release` from the root of this repository to build everything, or for just the
TailTail GUI run `cargo build -p tailtalk-gui --release`.

After building the binaries should be located at `target/release/`.


Then run the following based on your OS:
```sh
# Linux
cargo packager --release -f appimage -p tailtalk-gui
# macOS
cargo packager --release -p tailtalk-gui
# Windows 
cargo packager --release -f nsis -p tailtalk-gui

```

The resulting bundle will be placed in dist/. 


## TashTalk USB

Quick start guide: [Setup.md](/Setup.md)

TashTalk USB uses a Silicon Labs CP210x USB-to-UART bridge (VID `10c4`, PID `ea60`). 

### Linux
The `cp210x` kernel module is likely installed already but by default the device node is only accessible by root. To grant your user
access without requiring root, create a udev rule:

```sh
echo 'SUBSYSTEM=="tty", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", TAG+="uaccess"' \
  | sudo tee /etc/udev/rules.d/99-tashtalk-usb.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

After running these commands, unplug and re-plug the TashTalk USB device. It will appear as `/dev/ttyUSB0` (or
similar) and be accessible without root.

### Windows
Install the CP210x VCP Windows driver from 
[Silicon Labs](https://www.silabs.com/software-and-tools/usb-to-uart-bridge-vcp-drivers?tab=downloads).

Install npcap 1.88 from [npcap.com](https://npcap.com/#download)

### MacOS
macOS 11 and later includes support for the CP2102N USB chip out of the box. For 10.12 through 10.15 the driver from Silicon
Labs is required for the device to be recognised: https://www.silabs.com/software-and-tools/usb-to-uart-bridge-vcp-drivers?tab=downloads

## Existing Programs
There are 4 demo programs I have written to verify the functionality of this software as I have developed it:

- [aep-echo](/examples/aep-echo/) - A simple echo program that sends an echo request to a target address and prints the response time.
- [afp-server](/examples/afp-server) - An AFP 1.0, 1.1 and 2.0 compatible AFP server. Very much a work in progress but is capable of reading and writing files to classic Mac systems. Basic directory browsing and file operations are supported.
- [nbp-lookup](/examples/nbp-lookup) - Performs an NBP lookup based on the provided request string and returns the results
- [pap-print](/examples/pap-print) - Sends a PostScript file to a PAP printer. Aimed at LaserWriters, and have only tested on my own 4/600 PS.
- [tailtalk-gui](/examples/tailtalk-gui/) - A simple GUI for sharing a folder as a volume over EtherTalk and/or LocalTalk (via TashTalk).

All of the examples run a complete copy of the stack using a raw socket (if EtherTalk is enabled) and thus need to be run as root,
 or the appropriate setcap applied to the compiled binary. If only using TashTalk then this is not required.

## Testing

Beyond unit tests I have found the best way to test this software is with real hardware. My current test setup consists of:

- Linux machine running TailTalk
- PowerBook G3 running Mac OS 9.2 via Ethernet
- LaserWriter 4/600 PS via AsanteTalk
- Color StyleWriter 2200 via EtherTalk adapter
- Macintosh SE/30 running System 7.1 via AsanteTalk
- Macintosh Classic running System 6.0.8 via AsanteTalk

### AsanteTalk

When the AsanteTalk is first powered on it "listens" for incoming packets on the Ethernet
side before choosing what EtherTalk phase to operate under. If it doesn't see any EtherTalk Phase 2 packets it will default to
Phase 1. TailTalk supports Phase 1 and this works just fine for LaserWriters, NBP and some basic operations but does
not work with AFP (The Mac will discover the AFP TailTalk server but our responses appear to be dropped).

## Known Issues

* Multiple AFP sessions are not properly supported yet - whilst it can support two or more clients at once
  the server can/will ask strangely. 

## Contributing

I'd love to see this project grow into something that can be used to build more complete AppleTalk implementations. All contributions 
are welcome, but please open an issue first to discuss the changes you'd like to make. Additionally Pull Requests should mention what 
systems the change was verified against. This project has made me realise how quirky old systems are.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
