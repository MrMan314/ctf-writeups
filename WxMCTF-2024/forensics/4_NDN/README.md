# WxMCTF '24 Forensics 4 - NDN
> Shane is working on making NDNs (Nerdy Dinosaur Names). It seems the data in the files have been stored weirdly. Can you help?

(solved this with about 21 seconds remaining on the clock)

With about five minutes left on the clock, and not much progress being done on the problem `leakleakleak`, I decided to look for another problem to do.  

First, we attempted to unzip the file using the `unzip` command, but the file was not in the correct format. Looking the file's raw hex dump using `xxd ndn.zip | head`, my suspicion was confirmed:

```
00000000: 0403 4b50 0008 0014 4b2e 0008 0000 5859  ..KP....K.....XY
00000010: 0000 0000 79b4 0000 0004 0004 6173 0020  ....y.......as. 
00000020: 5455 7275 d907 000d d965 db4d ff65 db4d  TUru.....e.M.e.M
00000030: 7565 db80 0100 0b78 0001 f604 0014 0400  ue.....x........
00000040: 2100 0000 4ebf de40 000a 1a47 0252 440d  !...N..@...G.RD.
00000050: 00d0 02cf 009d f200 5e41 4480 b614 98ec  ........^AD.....
00000060: 4450 4ebf 3963 d410 ce09 1106 e748 ce19  DPN.9c.......H..
00000070: 3926 cb9c 824b 31a8 dbd6 cfcf e0b3 bb35  9&...K1........5
00000080: ba7a edba feaa e9ba d884 4867 b3d6 999d  .z........Hg....
00000090: f871 90bc a919 374a 71f0 e83d 52b0 c831  .q....7Jq..=R..1
```

A normal zip file is supposed to start with the bytes `50 4B 03 04`.  It seemed that this file had its endianness fliped, evident from the first four bytes being the zip signature in reverse.  

After a quick google search for a script to do this very task, I found a [simple python](https://stackoverflow.com/a/76167941) script to do so.  With not much time remaining on the clock, I decided to copy it:
```py
# walrus.py
import sys
while word := sys.stdin.buffer.read(4):
    sys.stdout.buffer.write(bytes(reversed(word)))
```

In order to use the script, I piped the file into the script, then piped its output into Java's `jar` utility (I swear this thing is half of the reason why I have this installed on my computer apart from Minecraft, Ghidra, and BurpSuite): `python3 walrus.py < ndn.zip | jar -xv`

The extraction revealed two files: `dino`, `saur`, and a `__MACOSX` directory (someone is using macOS here).  The `__MACOSX` directory can be discarded.  

I xxd'ed the two files and it seemed like the files could be "interlaced" to create a PNG image.  This is evident from the hexdumps:

dino:
```
00000000: 8950 0d0a 0000 4948 0000 0000 0806 006f  .P....IH.......o
```
saur:
```
00000000: 4e47 1a0a 000d 4452 02cf 02d0 0000 f29d  NG....DR........
```

I put together a script in to interlace the two files; two bytes at a time:
```py
# dinosaur.py
import sys
with open("dino", "rb") as dino, open("saur", "rb") as saur:
	while True:
		sys.stdout.buffer.write(dino.read(2))
		sys.stdout.buffer.write(saur.read(2))
```

I piped the script into a file by running `python3 dinosaur.py > dinosaur.png`.  Since the python script does not terminate, I killed the process after it ran for a few seconds.  

Finally, viewing the image revealed the flag: 
![wxmctf{TyrannoTechnoTinkerer}](dinosaur.png "dinosaur.png")
`wxmctf{TyrannoTechnoTinkerer}`
