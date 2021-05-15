# Chall_00

## Solution

##### Disassembling

First we run ***checksec --file=a.out*** to see any vulnerabilities and see there is ***No canary found***. 
Then we run ***r2 -Ad a.out*** to disassemble the file in debug mode and then enter ***s main*** to be taken to main and ***Vp*** to open visual.

```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   67) Symbols	  No	0		1		a.out
```



```assembly
96: int main (int argc, char **argv, char **envp);                                                                                                                                                                                          
│           ; var int64_t var_110h @ rbp-0x110                                                                                                                                                                                                
│           ; var int64_t var_4h @ rbp-0x4                                                                                                                                                                                                    
│           0x562186007189      f30f1efa       endbr64                                                                                                                                                                                        
│           0x56218600718d      55             push rbp                                                                                                                                                                                       
│           0x56218600718e      4889e5         mov rbp, rsp                                                                                                                                                                                   
│           0x562186007191      4881ec100100.  sub rsp, 0x110                                                                                                                                                                                 
│           0x562186007198      c745fc371300.  mov dword [var_4h], 0x1337                                                                                                                                                                     
│           0x56218600719f      488d3d620e00.  lea rdi, str.Now_tell_me_what_you_want_what_you_really_really_want_____    ; 0x562186008008 ; "Now tell me what you want what you really really want!!!!!"                                     
│           0x5621860071a6      e8c5feffff     call sym.imp.puts       ;[1] ; int puts(const char *s)                                                                                                                                         
│           0x5621860071ab      488d85f0feff.  lea rax, [var_110h]                                                                                                                                                                            
│           0x5621860071b2      4889c7         mov rdi, rax                                                                                                                                                                                   
│           0x5621860071b5      b800000000     mov eax, 0                                                                                                                                                                                     
│           0x5621860071ba      e8d1feffff     call sym.imp.gets       ;[2] ; char *gets(char *s)                                                                                                                                             
│           0x5621860071bf      817dfc209406.  cmp dword [var_4h], 0x69420                                                                                                                                                                    
│       ┌─< 0x5621860071c6      750e           jne 0x5621860071d6                                                                                                                                                                             
│       │   0x5621860071c8      488d3d740e00.  lea rdi, str._bin_sh    ; 0x562186008043 ; "/bin/sh"                                                                                                                                           
│       │   0x5621860071cf      e8acfeffff     call sym.imp.system     ;[3] ; int system(const char *string)                                                                                                                                  
│      ┌──< 0x5621860071d4      eb0c           jmp 0x5621860071e2                                                                                                                                                                             
│      │└─> 0x5621860071d6      488d3d730e00.  lea rdi, str.Ill_tell_you_what_i_want_what_i_really_really_want__ls    ; 0x562186008050 ; "Ill tell you what i want what i really really want; ls"                                             
│      │    0x5621860071dd      e89efeffff     call sym.imp.system     ;[3] ; int system(const char *string)                                                                                                                                  
│      │    ; CODE XREF from main @ 0x5621860071d4                                                                                                                                                                                            
│      └──> 0x5621860071e2      b800000000     mov eax, 0                                                                                                                                                                                     
│           0x5621860071e7      c9             leave                                                                                                                                                                                          
└           0x5621860071e8      c3             ret                                                                                                                                                                                            
            0x5621860071e9      0f1f80000000.  nop dword [rax]                                                                                                                                                                                
            ; DATA XREF from entry0 @ 0x5621860070ba    
```           
