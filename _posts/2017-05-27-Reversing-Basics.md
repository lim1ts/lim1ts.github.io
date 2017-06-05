---
layout: post
title:  "[0x0:Crackme] Basic Reversing with Radare2 and GDB Peda."
comments: true
date:   2017-05-27 22:50:00
categories: main
---
#### I previously wanted to complete a few more `crackmes`, but this has been sitting in my local repo for a week. I'll have to push this out first - more to come in time! :)

# Requirements:
1. Radare2
2. GDB Peda
3. Basic Linux command line knowledge
 
	Binary Ninja or IDA Pro works as well, since we're not diving into the scripting abilities of Radare2 yet.

# Introduction
To start things off, download the challenges pack from RPISEC:[challenges](http://security.cs.rpi.edu/courses/binexp-spring2015/lectures/2/challenges.zip). These are all ELF binaries, so you need a Linux system to run them. Their lecture slides and course materials can be accessed [here](http://security.cs.rpi.edu/courses/binexp-spring2015/).

Make sure you have downloaded [GDB Peda](https://github.com/longld/peda) and [Radare2](https://github.com/radare/radare2).

## [crackme0x00a]
Lets start up Radare2 by doing `r2 crackme0x00a`.
The first thing you see from the output (ignoring the greeter message), would be a memory address followed by the input section.
This address is your current position in the file.

### Some cursory commands
To navigate the binary, use `s`. 
To print out the next few hex values, use `x`.
```
[0x08048430]> s
0x8048430
[0x08048430]> x 16
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x08048430  31ed 5e89 e183 e4f0 5054 5268 e085 0408  1.^.....PTRh....
[0x08048430]> x 32
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x08048430  31ed 5e89 e183 e4f0 5054 5268 e085 0408  1.^.....PTRh....
0x08048440  6870 8504 0851 5668 e484 0408 e8bf ffff  hp...QVh........
[0x08048430]> s++
[0x08048530]> s-- 16
[0x08048430]> s++
[0x08048530]> s--
[0x08048430]> s?
|Usage: s  # Seek commands
| s                 Print current address
| s:pad             Print current address with N padded zeros (defaults to 8)
| s addr            Seek to address
| s-                Undo seek
| s- n              Seek n bytes backward
| s--               Seek blocksize bytes backward
| s+                Redo seek
| s+ n              Seek n bytes forward
| s++               Seek blocksize bytes forward
| s[j*=]            List undo seek history (JSON, =list, *r2)
| s/ DATA           Search for next occurrence of 'DATA'
| s/x 9091          Search for next occurrence of \x90\x91
| s.hexoff          Seek honoring a base from core->offset
| sa [[+-]a] [asz]  Seek asz (or bsize) aligned to addr
| sb                Seek aligned to bb start
| sC[?] string      Seek to comment matching given string
| sf                Seek to next function (f->addr+f->size)
| sf function       Seek to address of specified function
| sg/sG             Seek begin (sg) or end (sG) of section or file
| sl[?] [+-]line    Seek to line
| sn/sp             Seek next/prev scr.nkey
| so [N]            Seek to N next opcode(s)
| sr pc             Seek to register
[0x08048430]>
```
### Starting the disassembly
`aa`, which stands for `analyze all` will search through the binary and analyze its symbols.
It's commonly said that the only GUI you need is CLI, but if you prefer a visual mode, hit `v` for Radare2's visual mode.
`p` can be used to cycle between different view modes.

    *hex, the hexadecimal view
    *disasm, the disassembly listing
    *debug, the debugger
    *words, the word-hexidecimal view
    *buf, the C-formatted buffer
    *annotated, the annotated hexdump

Scrolling through the binary, we find the main function.
```
            ;-- main:                                                                                                                                 
/ (fcn) sym.main 133                                                                                                                                  
|   sym.main ();                                                                                                                                      
|           ; var int local_4h @ esp+0x4                                                                                                              
|           ; var int local_13h @ esp+0x13                                                                                                            
|           ; var int local_2ch @ esp+0x2c                                                                                                            
|              ; DATA XREF from 0x08048447 (entry0)                                                                                                   
|           0x080484e4      55             push ebp                                                                                                   
|           0x080484e5      89e5           mov ebp, esp                                                                                               
|           0x080484e7      83e4f0         and esp, 0xfffffff0                                                                                        
|           0x080484ea      83ec30         sub esp, 0x30               ; '0'                                                                          
|           0x080484ed      65a114000000   mov eax, dword gs:[0x14]    ; [0x14:4]=1                                                                   
|           0x080484f3      8944242c       mov dword [esp + local_2ch], eax                                                                           
|           0x080484f7      31c0           xor eax, eax                                                                                               
|              ; JMP XREF from 0x08048560 (sym.main)                                                                                                  
|       .-> 0x080484f9      b840860408     mov eax, str.Enter_password: ; "Enter password: " @ 0x8048640                                              
|       |   0x080484fe      890424         mov dword [esp], eax                                                                                       
|       |   0x08048501      e8cafeffff     call sym.imp.printf         ;[1]; int printf(const char *format)                                           
|       |   0x08048506      b851860408     mov eax, 0x8048651          ; "%s"                                                                         
|       |   0x0804850b      8d542413       lea edx, [esp + local_13h]  ; 0x13                                                                         
|       |   0x0804850f      89542404       mov dword [esp + local_4h], edx                                                                            
|       |   0x08048513      890424         mov dword [esp], eax                                                                                       
|       |   0x08048516      e805ffffff     call sym.imp.__isoc99_scanf ;[2]; int scanf(const char *format)                                            
|       |   0x0804851b      8d442413       lea eax, [esp + local_13h]  ; 0x13                                                                         
|       |   0x0804851f      89442404       mov dword [esp + local_4h], eax                                                                            
|       |   0x08048523      c7042424a004.  mov dword [esp], str.g00dJ0B_ ; [0x804a024:4]=0x64303067 ; LEA obj.pass.1685 ; "g00dJ0B!" @ 0x804a024      
|       |   0x0804852a      e891feffff     call sym.imp.strcmp         ;[3]; int strcmp(const char *s1, const char *s2)                               
|       |   0x0804852f      85c0           test eax, eax                                                                                              
|      ,==< 0x08048531      7521           jne 0x8048554               ;[4]                                                                           
|      ||   0x08048533      c70424548604.  mov dword [esp], str.Congrats_ ; [0x8048654:4]=0x676e6f43 ; LEA str.Congrats_ ; "Congrats!" @ 0x8048654    

	...

```
You can also use `VV` to get an ascii call graph.
Hit `q` to go back.

As we can see above, `mov dword [esp], str.g00dJ0B_` places the string `g00dJ0B!` into the `esp` register before calling `strcmp`.
We do not want to take the jump at `0x08048531` to `0x8048554`.

In the x86 assembly language, the TEST instruction performs a bitwise AND on two operands. The flags SF, ZF, PF are modified while the result of the AND is discarded. 

The `ZF` will be set to 1 when the bitwise AND of the operands are zero (meaning that the operands are equal). The `SF` flag is set to the most significant bit result of this bitwise AND. The parity flag `PF` is set to the result of the bitwise XNOR of the least significant byte of the result ( 1 if the number of ones in the byte is even, 0 if odd).

The `JE` (Jump if equal) instruction tests the `ZF` and jumps if the flag is set. It's also an alias of `JZ` (Jump if zero).
Here, `JNE` (Jump not equal) instruction jumps when the the flag is _not_ set (not equal).
For our program to _not_ take the jump, our outcome of `test eax, eax` has to set `ZF` to `0`.

In other words, for the operand to be equal to `g00dJ0B!`.
At this point, we have already solved the crackme, but lets go on to some less important details.

We see a call to scanf a few lines above the `strcmp`. We know that our input comes from somewhere around here.
It's actually difficult to find which registers `strcmp` and `scanf` interacts with because these are higher-level function calls, and it is possible that different compilers, optimization levels, etc will use a different set of instruction to evaluate the function call.

The `lea` instruction reads the address at `[esp + local_13h]` and stores it the address (not the variable stored at the address) into `eax`.
The `mov` instruction then reads a variable stored at a address, in this case the address stored inside `eax`, and stores it into `[esp + local_4h]`.
`strcmp` is then called.

Cool. So lets try out the password we just got.

```
lim1ts@thesignal:~/Downloads/challenges$ ./crackme0x00a
Enter password: g00dJ0B!
Congrats!
```

Awesome.

## Onwards to crackme0x00b!

You can get a visual graph view by doing `VV`.
Similarly, "p" can be used here to cycle between view modes differing in verbosity.

```
mov dword [esp], obj.pass.1964
call sym.imp.wcscmp ;[gd]
```
Huh. Looks like we're not using `strcmp` anymore.
What does `wcscmp` do?

From the [reference](http://www.cplusplus.com/reference/cwchar/wcscmp/):

```
Compare two strings
Compares the C wide string wcs1 to the C wide string wcs2.
```

A wide string is 


Hmm. So what originally looks like a "w" in the compare could be something else.
At this point entering "w" into our problem gives us an incorrect answer.
Lets see what else is there.

```
[0x08048494]> s 0x804a040
[0x0804a040]> x
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0804a040  7700 0000 3000 0000 7700 0000 6700 0000  w...0...w...g...
0x0804a050  7200 0000 6500 0000 6100 0000 7400 0000  r...e...a...t...
0x0804a060  0000 0000 4743 433a 2028 5562 756e 7475  ....GCC: (Ubuntu
0x0804a070  2f4c 696e 6172 6f20 342e 362e 312d 3975  /Linaro 4.6.1-9u
0x0804a080  6275 6e74 7533 2920 342e 362e 3100 002e  buntu3) 4.6.1...
0x0804a090  7379 6d74 6162 002e 7374 7274 6162 002e  symtab..strtab..
0x0804a0a0  7368 7374 7274 6162 002e 696e 7465 7270  shstrtab..interp
0x0804a0b0  002e 6e6f 7465 2e41 4249 2d74 6167 002e  ..note.ABI-tag..
0x0804a0c0  6e6f 7465 2e67 6e75 2e62 7569 6c64 2d69  note.gnu.build-i
0x0804a0d0  6400 2e67 6e75 2e68 6173 6800 2e64 796e  d..gnu.hash..dyn
0x0804a0e0  7379 6d00 2e64 796e 7374 7200 2e67 6e75  sym..dynstr..gnu
0x0804a0f0  2e76 6572 7369 6f6e 002e 676e 752e 7665  .version..gnu.ve
0x0804a100  7273 696f 6e5f 7200 2e72 656c 2e64 796e  rsion_r..rel.dyn
0x0804a110  002e 7265 6c2e 706c 7400 2e69 6e69 7400  ..rel.plt..init.
0x0804a120  2e74 6578 7400 2e66 696e 6900 2e72 6f64  .text..fini..rod
0x0804a130  6174 6100 2e65 685f 6672 616d 655f 6864  ata..eh_frame_hd
[0x0804a040]> 
```
Ah! 
Trying `w0wgreat` gives us the correct answer.
Awesome! 

I'm going to have to stop here for now - stay tuned for more!
[repo]:    https://github.com/lim1ts
