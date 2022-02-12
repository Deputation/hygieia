# Hygieia
The Greek goddess of health, her name is the source for the word "hygiene". 

Hygieia is a windows driver that works similarly to how pagewalkr (https://github.com/Deputation/pagewalkr) does, except it's written in a much more elegant manner.

Most of Hygieia has been ripped out of a bigger private project of mine made to investigate how Windows stores data regarding the drivers that have been unloaded in the system.

PRs are welcome.

## How does it work?
Hygieia scans the system's paging tables looking for a known vulnerable driver's timestamp and name (in this case, we're looking for kdmapper's driver).

You can find kdmapper here, to see what I'm talking about: https://github.com/z175/kdmapper

## What does it support?
Hygieia has been tested as a test signed driver on Windows 10 21H1, and is capable of scanning 1 GB large pages, 2 MB large pages, and regular 4KB pages.

## What is it for?
Investigating the traces left by vulnerable drivers to be able to better understand how the system stores and elaborates data relating to unloaded drivers, so that more effective detection methods could be built to find out whether or not one was loaded prior to loading a specific driver for anti-cheating purposes.

Of course, you can also use it to erase your vulnerable driver's **traces** to hide yourself, although I do not condone using Hygieia for anything that's not strictly educational.

## How to compile it?
Install the Windows SDK and the Windows WDK, then simply build the solution.

## How to use it? 
On an administrative command prompt (preferrably in a VM), simply create a service and start it like so:
```
sc create hygieia type= kernel binPath= "C:\Path\To\Hygieia.sys"
sc start hygieia
```
and watch the magic happen in the debugger. Results will be printed there.

## Output sample
This is how Hygieia's output looks like, after having mapped a driver using kdmapper.

```
[Hygieia] Driver started @FFFFF8025EF50000 - 0000000000008000
[Hygieia] Thread started!
[Hygieia] Physical address of page directory: 00000000001AD000
[Hygieia] Virtual address of page directory: FFFF86432190C000 
[Hygieia] Found vulnerable driver timestamp outside Hygieia @FFFFE609A360D9B0
[Hygieia] Found vulnerable driver name outside Hygieia @FFFFF603F64D90C0
[Hygieia] Found vulnerable driver timestamp outside Hygieia @FFFFF603F64D90CC
[Hygieia] Found vulnerable driver name **inside** Hygieia @FFFFF8025EF530C0
[Hygieia] Found vulnerable driver timestamp **inside** Hygieia @FFFFF8025EF530CC
[Hygieia] Total scanned memory: 1795510272.
[Hygieia] Scan completed in 27827 ms.
```

As you can see, Hygieia is capable of finding several hits inside kernel memory. Investigating those and correctly clearing them (and others that don't show up due to other information being stored other than the timestamp and the driver's name) is up to the reader.