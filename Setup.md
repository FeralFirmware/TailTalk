# Quickstart Guide for TashTalk USB for File Sharing

TashTalk USB should work with any Macintosh system with a LocalTalk port running System 3.3
and later with a crossover Mac serial cable, or LocalTalk dongle. For devices with two serial
ports like early systems, the cable should be plugged in to the one with a printer icon, not
the modem (phone icon) port.

For systems with multiple AppleTalk sources (i.e Ethernet or IrDA) please make sure that in
Control Panels -> AppleTalk the AppleTalk device is set to "Modem/Serial" port.

Note that TailTalk GUI does not work with FAT32 or exFAT filesystems when sharing volumes. Whilst
it will let you choose a folder on one of these filesystems file transfers will not work correctly.

HFS+, APFS, ext2/3/4 and most other common Unix filesystems should work just fine.

## Download
The modern macOS and Linux side software can be found on the Releases page [here](https://github.com/FeralFirmware/TailTalk/releases/latest).
The Mac version should work with Intel and Apple Silicon machines running 10.12 and newer. The Linux version
should run on any relatively recent x86_64 distro.

For Windows, Mac OS 10.12 through 10.15 and Linux please check out the driver notes from the main README [here](https://github.com/FeralFirmware/TailTalk#tashtalk-usb).

## Running

After launching the TailTalk GUI you should be presented with a screen like this:

![TailTalk GUI](/docs/tailtalk_gui.png)

For the first run the TashTalk device can be chosen from the drop down menu on "TashTalk Port". 
Then choose a folder to share to the Macintosh devices with the Browse button. 

The name shown on "Chooser" on Macintosh can be set via "Server Name", and the name of the volume (what appears on the Mac desktop)
can be set as well with "Volume Name".

Once these are chosen you can optionally import StuffIt Archive files to your chosen volume via File -> Import StuffIt Archive.
This will auto extract the contents within and set up the corresponding resource forks and finder info in case your target system
does not have StuffIt installed. 

![TailTalk GUI StuffIt import](/docs/stuffit.png)

Once finished with the above simply push Start to launch the AFP server. The server will remain running until the program is
closed or the stop button is pushed.

### Mac Side
(Note that depending on your Mac System version some of these screens may appear different on your system, but the flow is 
still largely the same)

On the Mac side go to Apple Menu -> Chooser, and then "AppleShare":

![Macintosh Chooser](/docs/Chooser.png)

The server name you chose in the previous step should appear. Double click on it (or push Ok) to start the connection, then the following
screen should appear:

![Macintosh user](/docs/Connect.png)

TailTalk does not support user based access, so push Connect here. That should then bring you to the volume selection screen:

![Macintosh volume selection](/docs/Volume.png)

Tick the box of the volume (there should only be one) and click OK. That should then cause these windows to disappear and
show you the original Chooser screen again, but with the volume now appearing on your desktop

![Macintosh volume visible](/docs/Mounted.png)

The volume can be interacted with like any other folder / volume on your classic Mac. 

![Macintosh volume viewing](/docs/Viewing.png)

To unmount the volume, just drag it to the trash can when complete. Shutting down the TailTalk GUI with the stop 
button will also automatically unmount the disk.

And thats it! When starting up the TailTalk GUI program again the settings should be remembered from last time and 
only the Start button needs to be pushed.
