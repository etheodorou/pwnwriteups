# Chall_08

## Solution

If we run ```checksec``` we find ```No pie``` and ```Partial Relro```

Then we open the file with radare and we are given a value of ```0x404050``` as an ```obj.target``` We also see that we have a ```win``` function we want to get to. 
We also see that before this value ```rax``` is multiplied by 8. A crucial part of this is that there is a ```puts``` in ```main``` later on so we need to calculate the distance between our value and ```puts```. 

We set up ELF with ```elf=ELF("./chall_08")``` and then if we ```elf.got``` we can see all the dynamically linked functions which in our case includes the address of ```puts```. So If we ```0x404050 - elf.got.puts``` we get ```56```. And since we already know what it was multiplied with we can divide by 8 and get ```7```, well its ```-7``` since it comes before and not after. The thing about puts is that it works with strings so we need to send the win address in the form of a string. So our payload will look like ```p.sendline(str(elf.sym.win))``` and then ```p.sendline("-7")```. And finally with ```interactive()``` we get our shell. 
