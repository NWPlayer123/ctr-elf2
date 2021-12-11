from struct import pack, unpack

with open("exh.bin", "rb") as f:
    name = f.read(8).strip(b"\x00")
    data = unpack("<5xBH12I", f.read(0x38))

print(b"Name: " + name)
print("Flag: %02x " % data[0] + ["", "[compressed]"][data[0] & 1] + ["", "[sd app]"][(data[0] & 2) >> 1])
print("Rev.: %04x" % data[1])
print

info = [".text addr: ", ".text page: ", ".text size: ", "stack size: ",
        ".read addr: ", ".read page: ", ".read size: ", "PleaseDoNotP",
	".data addr: ", ".data page: ", ".data size: ", ".bss size:  "]
it = 0
for i in info: #Don't do this kids it's bad form
    if it != 7: #Don't print, it's zero
        print(i + "%08X" % data[2 + it])
    if it in [3, 7]: print #Pretty print
    it += 1

if data[2] != 0x100000: print("WARNING: base address wrong, might be encrypted")

with open("ExeFS/code.bin", "rb") as f:
	data1 = f.read(data[4])  #Text
	f.seek(data[3] * 0x1000)
	data2 = f.read(data[8])  #Read
	f.seek((data[3] + data[7]) * 0x1000)
	data3 = f.read(data[12]) #Data

table = b"\x00.shstrtab\x00.text\x00.fini\x00.rodata\x00.memregion\x00.data\x00.bss\x00"
#Please never create an ELF file from scratch you will hate yourself like me
with open("ExeFS.elf", "wb") as f:
    f.write(b"\x7FELF\x01\x01\x01\x61" + b"\x00" * 8) #magic
    f.write(pack("<HHI", 2, 0x28, 1)) #Executable, ARM, ver 1
    off = [];base = 0x10000
    for size in [len(data1), len(data2), len(data3)]:
        off.append(base)
        base += size
    off.append(base)
    off.append(base + (0x100 - (base % 0x100))) #text, read, data, end, end+pad
    f.write(pack("<III", data[2], 0x34, off[4]+len(table))) #Start addr, program offset, section offset
    f.write(pack("<I6H", 0, 0x34, 0x20, 4, 0x28, 8, 7)) #Up to 52/0x34, time for sections
    #Type (Load), ELF offset, Virt and Phys offset, file and mem size, flags, align
    f.write(pack("<8I", 1, off[0],  data[2],   data[2], len(data1), len(data1), 5, 4)) #text
    f.write(pack("<8I", 1, off[1],  data[6],   data[6], len(data2), len(data2), 4, 4)) #read
    f.write(pack("<8I", 1, off[2], data[10],  data[10], len(data3), len(data3), 6, 4)) #data
    f.write(pack("<8I", 1, off[3], data[10]+len(data3), data[10]+len(data3), 0, data[-1], 6, 4)) #.bss
    #Now to write actual section data
    f.write(b"\x00" * 0xFF4C) #Hardcoded to pad 0x10000
    f.write(data1)
    f.write(data2)
    f.write(data3)
    f.write(b"\x00" * (off[4] - off[3])) #Align to 0x100
    f.write(table)
    # str | type | flag | addr | offset | size | link | info | align | entsize
    f.write(b"\x00" * 0x28) #.null
    f.write(pack("<10I", 11, 1, 6,  1 << 20, off[0], len(data1), 0, 0, 0x1000, 0)) #.text
    f.write(pack("<10I", 17, 1, 7,  data[6], off[3], 0, 0, 0, 1, 0)) #.fini
    f.write(pack("<10I", 23, 1, 3,  data[6], off[1], len(data2), 0, 0, 1, 0)) #.rodata
    f.write(pack("<10I", 31, 1, 1, data[10], off[3], 0, 0, 0, 1, 0)) #.memregion
    f.write(pack("<10I", 42, 1, 3, data[10], off[2], len(data3), 0, 0, 1, 0)) #.data
    f.write(pack("<10I", 48, 8, 3, data[10]+len(data3), size, data[-1], 0, 0, 1, 0)) #.bss
    f.write(pack("<10I", 1, 3, 0, 0, off[4],len(table), 0, 0, 1, 0)) #.shstrtab
    
