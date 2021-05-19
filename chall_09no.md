# Chall_09

## Solution

This problem is a little more unique because when we run ```checksec``` we find that there is a ```Full RELRO``` and everything else is enabled. So we open up the file to see what's happening.

 ``` assembly
 181: int main (int argc, char **argv, char **envp);                                                                                                                                                              
│           ; var int64_t var_54h @ rbp-0x54                                                                                                                                                                       
│           ; var int64_t var_50h @ rbp-0x50                                                                                                                                                                       
│           ; var int64_t var_18h @ rbp-0x18                                                                                                                                                                       
│           0x55828e6b61c9      f30f1efa       endbr64                                                                                                                                                             
│           0x55828e6b61cd      55             push rbp                                                                                                                                                            
│           0x55828e6b61ce      4889e5         mov rbp, rsp                                                                                                                                                        
│           0x55828e6b61d1      53             push rbx                                                                                                                                                            
│           0x55828e6b61d2      4883ec58       sub rsp, 0x58                                                                                                                                                       
│           0x55828e6b61d6      64488b042528.  mov rax, qword fs:[0x28]                                                                                                                                            
│           0x55828e6b61df      488945e8       mov qword [var_18h], rax                                                                                                                                            
│           0x55828e6b61e3      31c0           xor eax, eax                                                                                                                                                        
│           0x55828e6b61e5      488b15742e00.  mov rdx, qword [reloc.stdin]    ; [0x55828e6b9060:8]=0                                                                                                              
│           0x55828e6b61ec      488d45b0       lea rax, [var_50h]                                                                                                                                                  
│           0x55828e6b61f0      be32000000     mov esi, 0x32           ; '2' ; 50                                                                                                                                  
│           0x55828e6b61f5      4889c7         mov rdi, rax                                                                                                                                                        
│           0x55828e6b61f8      e8c3feffff     call sym.imp.fgets      ;[1] ; char *fgets(char *s, int size, FILE *stream)                                                                                         
│           0x55828e6b61fd      c745ac000000.  mov dword [var_54h], 0                                                                                                                                              
│       ┌─< 0x55828e6b6204      eb35           jmp 0x55828e6b623b                                                                                                                                                  
│      ┌──> 0x55828e6b6206      8b45ac         mov eax, dword [var_54h]                                                                                                                                            
│      ╎│   0x55828e6b6209      4898           cdqe                                                                                                                                                                
│      ╎│   0x55828e6b620b      0fb64405b0     movzx eax, byte [rbp + rax - 0x50]                                                                                                                                  
│      ╎│   0x55828e6b6210      83f069         xor eax, 0x69           ; 105                                                                                                                                       
│      ╎│   0x55828e6b6213      0fbed0         movsx edx, al                                                                                                                                                       
│      ╎│   0x55828e6b6216      8b45ac         mov eax, dword [var_54h]                                                                                                                                            
│      ╎│   0x55828e6b6219      4898           cdqe                                                                                                                                                                
│      ╎│   0x55828e6b621b      488d0dfe2d00.  lea rcx, obj.key        ; 0x55828e6b9020 ; "=\x01"                                                                                                                  
│      ╎│   0x55828e6b6222      0fb60408       movzx eax, byte [rax + rcx]                                                                                                                                         
│      ╎│   0x55828e6b6226      0fb6c0         movzx eax, al                                                                                                                                                       
│      ╎│   0x55828e6b6229      39c2           cmp edx, eax                                                                                                                                                        
│     ┌───< 0x55828e6b622b      740a           je 0x55828e6b6237                                                                                                                                                   
│     │╎│   0x55828e6b622d      bf45000000     mov edi, 0x45           ; 'E' ; 69                                                                                                                                  
│     │╎│   0x55828e6b6232      e899feffff     call sym.imp.exit       ;[2] ; void exit(int status)                                                                                                                
│     └───> 0x55828e6b6237      8345ac01       add dword [var_54h], 1                                                                                                                                              
│      ╎│   ; CODE XREF from main @ 0x55828e6b6204                                                                                                                                                                 
│      ╎└─> 0x55828e6b623b      8b45ac         mov eax, dword [var_54h]                                                                                                                                            
│      ╎    0x55828e6b623e      4863d8         movsxd rbx, eax                                                                                                                                                     
│      ╎    0x55828e6b6241      488d45b0       lea rax, [var_50h]                                                                                                                                                  
│      ╎    0x55828e6b6245      4889c7         mov rdi, rax                                                                                                                                                        
│      ╎    0x55828e6b6248      e843feffff     call sym.imp.strlen     ;[3] ; size_t strlen(const char *s)                                                                                                         
│      ╎    0x55828e6b624d      4839c3         cmp rbx, rax                                                                                                                                                        
│      └──< 0x55828e6b6250      72b4           jb 0x55828e6b6206                                                                                                                                                   
│           0x55828e6b6252      488d3dab0d00.  lea rdi, str._bin_sh    ; 0x55828e6b7004 ; "/bin/sh"                                                                                                                
│           0x55828e6b6259      e852feffff     call sym.imp.system     ;[4] ; int system(const char *string)                                                                                                       
│           0x55828e6b625e      b800000000     mov eax, 0                                                                                                                                                          
│           0x55828e6b6263      488b75e8       mov rsi, qword [var_18h]  
 
|           0x55828e6b6267      644833342528.  xor rsi, qword fs:[0x28]                                                                                                                                            
│       ┌─< 0x55828e6b6270      7405           je 0x55828e6b6277                                                                                                                                                   
│       │   0x55828e6b6272      e829feffff     call sym.imp.__stack_chk_fail ;[5] ; void __stack_chk_fail(void)                                                                                                    
│       └─> 0x55828e6b6277      4883c458       add rsp, 0x58                                                                                                                                                       
│           0x55828e6b627b      5b             pop rbx                                                                                                                                                             
│           0x55828e6b627c      5d             pop rbp                                                                                                                                                             
└           0x55828e6b627d      c3             ret                                                                                                                                                                 
            0x55828e6b627e      6690           nop
 ```

We see that there is a ```for``` loop in this program that checks the length of input provided. So ```rbx``` and ```rax```. We also see that there is a second ```for``` loop that takes an address function called ```obj.key``` and adds its to the input and compares it with ```edx```. 

If we dive deeper into the ```obj.key``` function we can find information in byte form.
```console
p8 @ obj.key
3d01001a49001a074e1d49191e0700070e491d01001a49001a491b0c1f0c1b1a00070e454905000f0c49001a49084905000c
```
Now if we open ```ipython``` we can format and set up our payload. 
```python
bytes.fromhex("3d01001a49001a074e1d49191e0700070e491d01001a49001a491b0c1f0c1b1
   ...: a00070e454905000f0c49001a49084905000c")
Out[1]: b'=\x01\x00\x1aI\x00\x1a\x07N\x1dI\x19\x1e\x07\x00\x07\x0eI\x1d\x01\x00\x1aI\x00\x1aI\x1b\x0c\x1f\x0c\x1b\x1a\x00\x07\x0eEI\x05\x00\x0f\x0cI\x00\x1aI\x08I\x05\x00\x0c'

```
