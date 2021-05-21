# Chall_12

## Solution

When we run ```checksec``` we find that everything is secure apart from ```RELRO```.

Then we open it up in radare and find a ```vuln``` function with an ```fgets```. We notice that when we run the program it gives us a message and an address which turns out is the address for the main function. 

```assembly
115: sym.vuln ();                                                                                                                                            
│           ; var int32_t var_4ch @ ebp-0x4c                                                                                                                   
│           ; var int32_t var_ch @ ebp-0xc                                                                                                                     
│           ; var int32_t var_4h @ ebp-0x4                                                                                                                     
│           0x565af27c      f30f1efb       endbr32                                                                                                             
│           0x565af280      55             push ebp                                                                                                            
│           0x565af281      89e5           mov ebp, esp                                                                                                        
│           0x565af283      53             push ebx                                                                                                            
│           0x565af284      83ec54         sub esp, 0x54                                                                                                       
│           0x565af287      e8c4feffff     call sym.__x86.get_pc_thunk.bx ;[1]                                                                                 
│           0x565af28c      81c3c4200000   add ebx, 0x20c4                                                                                                     
│           0x565af292      65a114000000   mov eax, dword gs:[0x14]                                                                                            
│           0x565af298      8945f4         mov dword [var_ch], eax                                                                                             
│           0x565af29b      31c0           xor eax, eax                                                                                                        
│           0x565af29d      8b8330000000   mov eax, dword [ebx + 0x30]                                                                                         
│           0x565af2a3      8b00           mov eax, dword [eax]                                                                                                
│           0x565af2a5      83ec04         sub esp, 4                                                                                                          
│           0x565af2a8      50             push eax                                                                                                            
│           0x565af2a9      6a40           push 0x40                   ; '@' ; 64                                                                              
│           0x565af2ab      8d45b4         lea eax, [var_4ch]                                                                                                  
│           0x565af2ae      50             push eax                                                                                                            
│           0x565af2af      e80cfeffff     call sym.imp.fgets          ;[2] ; char *fgets(char *s, int size, FILE *stream)                                     
│           0x565af2b4      83c410         add esp, 0x10                                                                                                       
│           0x565af2b7      83ec0c         sub esp, 0xc                                                                                                        
│           0x565af2ba      8d45b4         lea eax, [var_4ch]                                                                                                  
│           0x565af2bd      50             push eax                                                                                                            
│           0x565af2be      e8edfdffff     call sym.imp.printf         ;[3] ; int printf(const char *format)                                                   
│           0x565af2c3      83c410         add esp, 0x10                                                                                                       
│           0x565af2c6      83ec0c         sub esp, 0xc                                                                                                        
│           0x565af2c9      8d83c0ecffff   lea eax, [ebx - 0x1340]                                                                                             
│           0x565af2cf      50             push eax                                                                                                            
│           0x565af2d0      e80bfeffff     call sym.imp.puts           ;[4] ; int puts(const char *s)                                                          
│           0x565af2d5      83c410         add esp, 0x10                                                                                                       
│           0x565af2d8      90             nop                                                                                                                 
│           0x565af2d9      8b45f4         mov eax, dword [var_ch]                                                                                             
│           0x565af2dc      653305140000.  xor eax, dword gs:[0x14]                                                                                            
│       ┌─< 0x565af2e3      7405           je 0x565af2ea                                                                                                       
│       │   0x565af2e5      e8d6000000     call sym.__stack_chk_fail_local ;[5]                                                                                
│       └─> 0x565af2ea      8b5dfc         mov ebx, dword [var_4h]                                                                                             
│           0x565af2ed      c9             leave                                                                                                               
└           0x565af2ee      c3             ret                                                                                                                 
┌ 76: int main (char **argv);                                                                                                                                  
│           ; var int32_t var_8h @ ebp-0x8                                                                                                                     
│           ; arg char **argv @ esp+0x24                                                                                                                       
│           0x565af2ef      f30f1efb       endbr32                                                                                                             
│           0x565af2f3      8d4c2404       lea ecx, [argv]                                                                                                     
│           0x565af2f7      83e4f0         and esp, 0xfffffff0                                                                                                 
│           0x565af2fa      ff71fc         push dword [ecx - 4]                                                                                                
│           0x565af2fd      55             push ebp                                                                                                            
│           0x565af2fe      89e5           mov ebp, esp                                                                                                        
│           0x565af300      53             push ebx                                                                                                            
│           0x565af301      51             push ecx
|           0x565af302      e834000000     call sym.__x86.get_pc_thunk.ax ;[4]                                                                                 
│           0x565af307      0549200000     add eax, 0x2049                                                                                                     
│           0x565af30c      83ec08         sub esp, 8                                                                                                          
│           0x565af30f      8d909fdfffff   lea edx, [eax - 0x2061]                                                                                             
│           0x565af315      52             push edx                                                                                                            
│           0x565af316      8d90c8ecffff   lea edx, [eax - 0x1338]                                                                                             
│           0x565af31c      52             push edx                                                                                                            
│           0x565af31d      89c3           mov ebx, eax                                                                                                        
│           0x565af31f      e88cfdffff     call sym.imp.printf         ;[1] ; int printf(const char *format)                                                   
│           0x565af324      83c410         add esp, 0x10                                                                                                       
│           0x565af327      e850ffffff     call sym.vuln               ;[5]                                                                                    
│           0x565af32c      b800000000     mov eax, 0                                                                                                          
│           0x565af331      8d65f8         lea esp, [var_8h]                                                                                                   
│           0x565af334      59             pop ecx                                                                                                             
│           0x565af335      5b             pop ebx                                                                                                             
│           0x565af336      5d             pop ebp                                                                                                             
│           0x565af337      8d61fc         lea esp, [ecx - 4]                                                                                                  
└           0x565af33a      c3             ret
```

If we use ```pwn``` we can open up the elf functions and view addresses of all the symbols. We discover that there is a ```win``` function with an address and a ```puts``` along with a ```printf``` which which could lead to a way in. If try sending some lines we could discover its offset and if send it ```%7&p``` we get back the message from the program and our input in asci form which means we found our offset number. We can discover the beginning of the offset by subtracting the leak from main and sending a payload with ```python fmtstr_payload(7, {elf.got.puts: elf.sym.win}, write_size='short')``` and sending the result. After that we can get shell with ```interactive()```
