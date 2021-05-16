# Chall_01

## Solution

##### Disassembling

First we run ```checksec --file=a.out``` to see any vulnerabilities and see there is ```No canary found``` just like chall_00. 

```console
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      No canary found  NX enabled    PIE enabled     No RPATH   No RUNPATH   67) Symbols	  No	0		1		a.out
```

Then we run ```r2 -Ad a.out``` to disassemble the file in debug mode and then enter ```s main``` to be taken to main and ```Vp``` to open visual.

``` assembly
┌ 131: int main (int argc, char **argv, char **envp);                                                                                                                             
│           ; var int64_t var_110h @ rbp-0x110                                                                                                                                    
│           ; var int64_t var_8h @ rbp-0x8                                                                                                                                        
│           ; var int64_t var_4h @ rbp-0x4                                                                                                                                        
│           0x55892799a189      f30f1efa       endbr64                                                                                                                            
│           0x55892799a18d      55             push rbp                                                                                                                           
│           0x55892799a18e      4889e5         mov rbp, rsp                                                                                                                       
│           0x55892799a191      4881ec100100.  sub rsp, 0x110                                                                                                                     
│           0x55892799a198      488d3d690e00.  lea rdi, str.Obi_Wan_has_trained_you_well...    ; 0x55892799b008 ; "Obi Wan has trained you well..."                               
│           0x55892799a19f      e8ccfeffff     call sym.imp.puts       ;[1] ; int puts(const char *s)                                                                             
│           0x55892799a1a4      c745fc371300.  mov dword [var_4h], 0x1337                                                                                                         
│           0x55892799a1ab      c745f8696969.  mov dword [var_8h], 0x69696969    ; 'iiii'                                                                                         
│           0x55892799a1b2      488b15572e00.  mov rdx, qword [reloc.stdin]    ; [0x55892799d010:8]=0                                                                             
│           0x55892799a1b9      488d85f0feff.  lea rax, [var_110h]                                                                                                                
│           0x55892799a1c0      be18010000     mov esi, 0x118          ; 280                                                                                                      
│           0x55892799a1c5      4889c7         mov rdi, rax                                                                                                                       
│           0x55892799a1c8      e8c3feffff     call sym.imp.fgets      ;[2] ; char *fgets(char *s, int size, FILE *stream)                                                        
│           0x55892799a1cd      817dfc696969.  cmp dword [var_4h], 0x69696969                                                                                                     
│       ┌─< 0x55892799a1d4      7523           jne 0x55892799a1f9                                                                                                                 
│       │   0x55892799a1d6      817df8371300.  cmp dword [var_8h], 0x1337                                                                                                         
│      ┌──< 0x55892799a1dd      751a           jne 0x55892799a1f9                                                                                                                 
│      ││   0x55892799a1df      488d3d420e00.  lea rdi, str.My_powers_have_doubled_since_the_last_time_we_met    ; 0x55892799b028 ; "My powers have doubled since the last time w
│      ││   0x55892799a1e6      e885feffff     call sym.imp.puts       ;[1] ; int puts(const char *s)                                                                             
│      ││   0x55892799a1eb      488d3d680e00.  lea rdi, str._bin_sh    ; 0x55892799b05a ; "/bin/sh"                                                                               
│      ││   0x55892799a1f2      e889feffff     call sym.imp.system     ;[3] ; int system(const char *string)                                                                      
│     ┌───< 0x55892799a1f7      eb0c           jmp 0x55892799a205                                                                                                                 
│     │└└─> 0x55892799a1f9      488d3d620e00.  lea rdi, str.But_you_are_not_a_Jedi_yet_    ; 0x55892799b062 ; "But you are not a Jedi yet!"                                       
│     │     0x55892799a200      e86bfeffff     call sym.imp.puts       ;[1] ; int puts(const char *s)                                                                             
│     │     ; CODE XREF from main @ 0x55892799a1f7                                                                                                                                
│     └───> 0x55892799a205      b800000000     mov eax, 0                                                                                                                         
│           0x55892799a20a      c9             leave                                                                                                                              
└           0x55892799a20b      c3             ret                                                                                                                                
            0x55892799a20c      0f1f4000       nop dword [rax]
```
