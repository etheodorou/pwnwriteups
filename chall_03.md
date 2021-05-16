# Chall_00

## Solution

##### Disassembling

First we run ```checksec --file=a.out``` to see any vulnerabilities and see there is ```No canary found``` and NX disabled which means we can implant shellcode. 

Then we run ```r2 -Ad a.out``` to disassemble the file in debug mode and then enter ```s main``` to be taken to main and ```Vp``` to open visual.

```assembly
65: sym.vuln ();                                                                                                                 
│           ; var int64_t var_140h @ rbp-0x140                                                                                     
│           0x5624af44e189      f30f1efa       endbr64                                                                             
│           0x5624af44e18d      55             push rbp                                                                            
│           0x5624af44e18e      4889e5         mov rbp, rsp                                                                        
│           0x5624af44e191      4881ec400100.  sub rsp, 0x140                                                                      
│           0x5624af44e198      488d85c0feff.  lea rax, [var_140h]                                                                 
│           0x5624af44e19f      4889c6         mov rsi, rax                                                                        
│           0x5624af44e1a2      488d3d5f0e00.  lea rdi, str.Heres_a_leak_:___p_n    ; 0x5624af44f008 ; "Here's a leak :) %p\n"     
│           0x5624af44e1a9      b800000000     mov eax, 0                                                                          
│           0x5624af44e1ae      e8cdfeffff     call sym.imp.printf     ;[1] ; int printf(const char *format)                       
│           0x5624af44e1b3      488d85c0feff.  lea rax, [var_140h]                                                                 
│           0x5624af44e1ba      4889c7         mov rdi, rax                                                                        
│           0x5624af44e1bd      b800000000     mov eax, 0                                                                          
│           0x5624af44e1c2      e8c9feffff     call sym.imp.gets       ;[2] ; char *gets(char *s)                                  
│           0x5624af44e1c7      90             nop                                                                                 
│           0x5624af44e1c8      c9             leave                                                                               
└           0x5624af44e1c9      c3             ret  

37: int main (int argc, char **argv, char **envp);                                                                               
│           0x5624af44e1ca      f30f1efa       endbr64                                                                             
│           0x5624af44e1ce      55             push rbp                                                                            
│           0x5624af44e1cf      4889e5         mov rbp, rsp                                                                        
│           0x5624af44e1d2      488d3d470e00.  lea rdi, str.She_sellz_sea_shellz_by_the_return_address    ; 0x5624af44f020 ; "She 
│           0x5624af44e1d9      e892feffff     call sym.imp.puts       ;[3] ; int puts(const char *s)                              
│           0x5624af44e1de      b800000000     mov eax, 0                                                                          
│           0x5624af44e1e3      e8a1ffffff     call sym.vuln           ;[4]                                                        
│           0x5624af44e1e8      b800000000     mov eax, 0                                                                          
│           0x5624af44e1ed      5d             pop rbp                                                                             
└           0x5624af44e1ee      c3             ret                                                                                 
            0x5624af44e1ef      90             nop 
```
