Rewrote [ctr-elf](https://github.com/archshift/ctr-elf) because it messed up the .bss section and required external dependencies (arm-none-eabi from DevkitARM), only tested with Python 2.7.13 and Yo-kai Watch 3 Sukiyaki but it should work fine on any code.bin+exh.bin

Also, you can just place it in the directory that ctrtool creates and run it which is a lot easier and faster than making a separate workdir folder.

Not sure what else to put in here, provided with no warranty or guarantee of operability, feel free to modify and redistribute.
