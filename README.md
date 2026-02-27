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

## Existing Programs
There are 4 demo programs I have written to verify the functionality of this software as I have developed it:

- [aep-echo](/examples/aep-echo/) - A simple echo program that sends an echo request to a target address and prints the response time.
- [afp-server](/examples/afp-server) - An AFP 1.0, 1.1 and 2.0 compatible AFP server. Very much a work in progress but is capable of reading and writing files to classic Mac systems. Basic directory browsing and file operations are supported.
- [nbp-lookup](/examples/nbp-lookup) - Performs an NBP lookup based on the provided request string and returns the results
- [pap-print](/examples/pap-print) - Sends a PostScript file to a PAP printer. Aimed at LaserWriters, and have only tested on my own 4/600 PS. 

All of the examples run a complete copy of the stack using a raw socket and thus need to be run as root, or the appropriate setcap
applied to the compiled binary. 

## Testing

Beyond unit tests I have found the best way to test this software is with real hardware. My current test setup consists of:

- Linux machine running TailTalk
- PowerBook G3 running Mac OS 9.2 via Ethernet
- LaserWriter 4/600 PS via AsanteTalk
- Color StyleWriter 2200 via EtherTalk adapter
- Macintosh SE/30 running System 7.1 via AsanteTalk
- Macintosh Classic running System 6.0.8 via AsanteTalk

## Contributing

I'd love to see this project grow into something that can be used to build more complete AppleTalk implementations. All contributions 
are welcome, but please open an issue first to discuss the changes you'd like to make. Additionally Pull Requests should mention what 
systems the change was verified against. This project has made me realise how quirky old systems are.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
