---
layout: post
title:  "[0x2:Crackme] Basic Reversing with Radare2 and GDB Peda."
comments: true
date:   2017-10-1 12:15:00
categories: main
---
#### Post was written on 28th June, but `crackme0x09` was completed only on `01/10` after I was crushed at two ctfs.
Note: I don't have a complete solution for 0x09, and I received help in the form of reading [WereW's writeup](https://werew.tk/article/11/ioli-crackme0x0)

CrossCTF: 10th Qualifiying. 14th Finals.
HackIt CTF: 82nd.

We didn't perform very well, and its apparent that my skills are severly lacking in all aspects. My current documentation with my progress using this blog is also, quite frankly, terrible. I will look forward to updating the blog to be more readable and easier to work with, as well as continue to refine my skillsets in the RE, Pwn and Web areas.
### Crackme0x04

![r2 screenshot](http://i.imgur.com/JM7asBz.png)
Hmm. `JAE`. We haven't seen that one before.
#### JAE
```
Jump if Above or Equal (unsigned comparison)

jae loc

CF = 0 or ZF = 1 
```
Remember that back when `cmp` was first introduced to us, we know that it performs a _bitwise AND_ operation with the two operands.
It will modify the flags `ZF=1` iff the result of the operation is 0 (i.e, the operands are equal).

We don't want to take the jump, so we just need to set our argument to whatever `dword [ebp - local_ch]` is NOT.

That seems to work fine, however we see later on that there is a `cmp dword [ebp - local_8h], 0xf`.
Do we actually control that local variable?

At this point you can actually enter GDB and realise that what the program really is doing is just adding each digit together, and all combinations that reach 16 as a sum would work. But lets look at what the instructions are doing.

```
| 0x080484a8 8b45f4         mov eax, dword [ebp - local_ch]    // Moving Local variable _CH into eax. (turns out to be zero)
| 0x080484ab 034508         add eax, dword [ebp + arg_8h]      // Then we add our argument to it. !This means we're offsetting it by 0!
| 0x080484ae 0fb600         movzx eax, byte [eax]              // movzx is basically moving with zero padded.
							       // So we the byte size of [eax] into eax. This means the first digit.
| 0x080484b1 8845f3         mov byte [ebp - local_dh], al      // Then we move the lowest 1 byte into variable _DH. (Also first digit)  >--+
| 0x080484b4 8d45fc         lea eax, [ebp - local_4h]          // And load the address of variable _4H into eax.		           |
| 0x080484b7 89442408       mov dword [esp + local_8h_2], eax  // Which is then moved into local variable _8H_2.		           |
|    ; [0x8048638:4]=0x50006425                                									           |
|    ; "%d"                                                    									           |
| 0x080484bb c74424043886.  mov dword [esp + local_4h_2], ,0x8048638  // just '%d"						           |
| 0x080484c3 8d45f3         lea eax, [ebp - local_dh]          // Looks like we're now putting the address of our first Digit here. <------+
| 0x080484c6 890424         mov dword [esp], eax               // Then mov-ing it to [esp]? Preparing for a function call huh.
| 0x080484c9 e8d6feffff     call sym.imp.sscanf ;[ge]          // What this scanf call does is to write the first digit into the address.
							       // The address it writes to belong to local variable _4H.
| 0x080484ce 8b55fc         mov edx, dword [ebp - local_4h]    // We should expect edx to hold the first digit now.
| 0x080484d1 8d45f8         lea eax, [ebp - local_8h]          // Effective address of local variable _8H loaded into eax.
| 0x080484d4 0110           add dword [eax], edx               // Then added by edx (first digit)
|    ; [0xf:4]=0x3000200                                        
| 0x080484d6 837df80f       cmp dword [ebp - local_8h], 0xf    // and its value is compared to 15.
| 0x080484da 7518           jne 0x80484f4 ;[gf] 	       // We need the value to be 15!
```
But we can't enter 15 as a single digit right?
We need at least 2 digits, like "87".

What happens when the jump is taken?

```
|0x080484f4 8d45f4         lea eax, [ebp - local_ch] 	       // Effective address of local variable _CH loaded into eax. Its 0.
|0x080484f7 ff00           inc dword [eax]		       // Now local variable _CH is incremented to 1.
|0x080484f9 eb9d           jmp 0x8048498 ;[gd]		       // We then jump back to the start.
```

[NOTE]: We refer to the variables as _*H, but they simply are $ebp/$esp - *Hex. The H just stands for hex.
 
We loop back again, but this time the offset is 1!
This means we're going to be looking at the second digit.
Remember we still have our first digit in variable _8H. After the sscanf, we see that our second digit will be added.
This means we're doing a digit-by-digit sum!

Also, realise that the block of function with `STRLEN` is just trying to make sure we don't read past the number of digits.
And that each digit must be bigger than 0.

### Crackme0x05

Basically the same thing, just that the sum needs to be 16.

At this point, I was getting kind of bored. So I decided to skip all the way to the final level. :x

### Crackme0x09
We see that this is a stripped binary - meaning we can't do `pdf @ sym.main` here.
In [stripped binaries](https://en.wikipedia.org/wiki/Stripped_binary), the debugging symbols are removed from the binary. The primary benefit to this is to save memory, but it also makes the binary more difficult to disassemble or reverse.

But hey, we can still see `main`.

So lets do `pdf @ main`.

```
[0x08048420]> pdf @ main
/ (fcn) main 120
|   main (int arg_10h);
|           ; var int local_78h @ ebp-0x78
|           ; var int local_4h_2 @ ebp-0x4
|           ; arg int arg_10h @ ebp+0x10
|           ; var int local_4h @ esp+0x4
|              ; DATA XREF from 0x08048437 (entry0)
|           0x080486ee      55             push ebp
|           0x080486ef      89e5           mov ebp, esp
|           0x080486f1      53             push ebx
|           0x080486f2      81ec84000000   sub esp, 0x84
|           0x080486f8      e869000000     call fcn.08048766
|           0x080486fd      81c3f7180000   add ebx, 0x18f7
|           0x08048703      83e4f0         and esp, 0xfffffff0
|           0x08048706      b800000000     mov eax, 0
|           0x0804870b      83c00f         add eax, 0xf
|           0x0804870e      83c00f         add eax, 0xf
|           0x08048711      c1e804         shr eax, 4
|           0x08048714      c1e004         shl eax, 4
|           0x08048717      29c4           sub esp, eax
|           0x08048719      8d8375e8ffff   lea eax, [ebx - 0x178b]
|           0x0804871f      890424         mov dword [esp], eax
|           0x08048722      e8b9fcffff     call sym.imp.printf         ; int printf(const char *format)
|           0x08048727      8d838ee8ffff   lea eax, [ebx - 0x1772]
|           0x0804872d      890424         mov dword [esp], eax
|           0x08048730      e8abfcffff     call sym.imp.printf         ; int printf(const char *format)
|           0x08048735      8d4588         lea eax, [local_78h]
|           0x08048738      89442404       mov dword [local_4h], eax
|           0x0804873c      8d8399e8ffff   lea eax, [ebx - 0x1767]
|           0x08048742      890424         mov dword [esp], eax
|           0x08048745      e876fcffff     call sym.imp.scanf          ; int scanf(const char *format)
|           0x0804874a      8b4510         mov eax, dword [arg_10h]    ; [0x10:4]=-1 ; 16
|           0x0804874d      89442404       mov dword [local_4h], eax
|           0x08048751      8d4588         lea eax, [local_78h]
|           0x08048754      890424         mov dword [esp], eax
|           0x08048757      e8bafeffff     call sub.strlen_616         ; size_t strlen(const char *s)
|           0x0804875c      b800000000     mov eax, 0
|           0x08048761      8b5dfc         mov ebx, dword [local_4h_2]
|           0x08048764      c9             leave
\           0x08048765      c3             ret
```
The rest of the functions are not so lucky - we see them as `fcn.*`.

The `main` function can be located in a stripped ELF binary is straightforward, no symbol information is required.

The prototype for __libc_start_main is
```
int __libc_start_main(int (*main) (int, char**, char**), 
                      int argc, 
                      char *__unbounded *__unbounded ubp_av, 
                      void (*init) (void), 
                      void (*fini) (void), 
                      void (*rtld_fini) (void), 
                      void (*__unbounded stack_end));
```

The runtime memory address of `main()` is the argument `int`, which also means that it will be the last memory addressed saved on runtime stack prior to calling __libc_start_main is the memory address of main(), since arguments are pushed onto the runtime stack in the reverse order.

We can also see an interesting function call - 

```
[0x08048420]> afn do_something fcn.08048616
[0x08048420]> pdf @ do_something 
```
`afn` renames the function to do_something in radare.
Lets look at that function.

```
|       .-> 0x08048636      8b4508         mov eax, dword [userInput]  ; [0x8:4]=-1 ; 8
|       |   0x08048639      890424         mov dword [esp], eax
|       |   0x0804863c      e88ffdffff     call sym.imp.strlen         ; size_t strlen(const char *s)
|       |   0x08048641      3945f0         cmp dword [count2], eax     ; [0x13:4]=-1 ; 19
|      ,==< 0x08048644      734f           jae 0x8048695
|      ||   0x08048646      8b45f0         mov eax, dword [count2]
|      ||   0x08048649      034508         add eax, dword [userInput]
|      ||   0x0804864c      0fb600         movzx eax, byte [eax]
|      ||   0x0804864f      8845ef         mov byte [local_11h], al
|      ||   0x08048652      8d45f8         lea eax, [local_8h]
|      ||   0x08048655      89442408       mov dword [local_8h_2], eax
|      ||   0x08048659      8d835ee8ffff   lea eax, [ebx - 0x17a2]
|      ||   0x0804865f      89442404       mov dword [local_4h], eax
|      ||   0x08048663      8d45ef         lea eax, [local_11h]
|      ||   0x08048666      890424         mov dword [esp], eax
|      ||   0x08048669      e882fdffff     call sym.imp.sscanf         ; int sscanf(const char *s,
|      ||   0x0804866e      8b55f8         mov edx, dword [local_8h]
|      ||   0x08048671      8d45f4         lea eax, [count1]
|      ||   0x08048674      0110           add dword [eax], edx
|      ||   0x08048676      837df410       cmp dword [count1], 0x10    ; [0x10:4]=-1 ; 16
|     ,===< 0x0804867a      7512           jne 0x804868e
|     |||   0x0804867c      8b450c         mov eax, dword [arg_ch]     ; [0xc:4]=-1 ; 12
|     |||   0x0804867f      89442404       mov dword [local_4h], eax
|     |||   0x08048683      8b4508         mov eax, dword [userInput]  ; [0x8:4]=-1 ; 8
|     |||   0x08048686      890424         mov dword [esp], eax
|     |||   0x08048689      e8fbfeffff     call sub.sscanf_589         ; int sscanf(const char *s,
|     ||!      ; JMP XREF from 0x0804867a (do_something)
|     `---> 0x0804868e      8d45f0         lea eax, [count2]
|      ||   0x08048691      ff00           inc dword [eax]
|      |`=< 0x08048693      eba1           jmp 0x8048636
|      |       ; JMP XREF from 0x08048644 (do_something)
|      `--> 0x08048695      e8c3feffff     call sub.printf_55d         ; int printf(const char *format)
|           0x0804869a      8b450c         mov eax, dword [arg_ch]     ; [0xc:4]=-1 ; 12
|           0x0804869d      89442404       mov dword [local_4h], eax
|           0x080486a1      8b45f8         mov eax, dword [local_8h]
|           0x080486a4      890424         mov dword [esp], eax
|           0x080486a7      e828feffff     call sub.strncmp_4d4        ; int strncmp(const char *s1, const char *s2, size_t n)
|           0x080486ac      85c0           test eax, eax
|       ,=< 0x080486ae      7438           je 0x80486e8
|       |   0x080486b0      c745f0000000.  mov dword [count2], 0
|       |      ; JMP XREF from 0x080486e6 (do_something)
|      .--> 0x080486b7      837df009       cmp dword [count2], 9       ; [0x9:4]=-1 ; 9
|     ,===< 0x080486bb      7f2b           jg 0x80486e8
|     |||   0x080486bd      8b45f8         mov eax, dword [local_8h]
|     |||   0x080486c0      83e001         and eax, 1
|     |||   0x080486c3      85c0           test eax, eax
|    ,====< 0x080486c5      751a           jne 0x80486e1
|    ||||   0x080486c7      8d836fe8ffff   lea eax, [ebx - 0x1791]
|    ||||   0x080486cd      890424         mov dword [esp], eax
|    ||||   0x080486d0      e80bfdffff     call sym.imp.printf         ; int printf(const char *format)
|    ||||   0x080486d5      c70424000000.  mov dword [esp], 0
|    ||||   0x080486dc      e82ffdffff     call sym.imp.exit           ; void exit(int status)
|    ||!|      ; JMP XREF from 0x080486c5 (do_something)
|    `----> 0x080486e1      8d45f0         lea eax, [count2]
|     |||   0x080486e4      ff00           inc dword [eax]
|     |`==< 0x080486e6      ebcf           jmp 0x80486b7
|     | |      ; JMP XREF from 0x080486ae (do_something)
|     | |      ; JMP XREF from 0x080486bb (do_something)
|     `-`-> 0x080486e8      83c424         add esp, 0x24               ; '$'
|           0x080486eb      5b             pop ebx
|           0x080486ec      5d             pop ebp
\           0x080486ed      c3             ret

```

We see two variables here at the start of the function.
I've renamed them to `count1` and `count2` using `afvn <original_name> <new_name>`. (You need to seek to the function scope first.)
The arguement has also been renamed to `userInput`.

Seeing the `inc dword[eax]` here, and seeing that it only reaches that branch because of a previous `jne`, we can guess that this is probably a `for loop`.
From the use of `userInput`, we see that the shortened 8 bits are used to add into the whatever has been added in already.
Hence, we deduce that `count1` is the char by char summation, and we need `count1` to be the sum of 16 - that sounds familiar!
Looks like our target is to reach `call sub.sscanf_589`, now to see inside it:

```
[0x08048616]> pdf @ sub.sscanf_589
/ (fcn) sub.sscanf_589 141
|   sub.sscanf_589 (int arg_8h, int arg_9h, int arg_ch);
|           ; var int local_ch @ ebp-0xc
|           ; var int local_8h @ ebp-0x8
|           ; arg int arg_8h @ ebp+0x8
|           ; arg int arg_9h @ ebp+0x9
|           ; arg int arg_ch @ ebp+0xc
|              ; CALL XREF from 0x08048689 (do_something)
|           0x08048589      55             push ebp
|           0x0804858a      89e5           mov ebp, esp
|           0x0804858c      53             push ebx
|           0x0804858d      83ec14         sub esp, 0x14
|           0x08048590      e8d1010000     call init_ebx
|           0x08048595      81c35f1a0000   add ebx, 0x1a5f
|           0x0804859b      8d45f8         lea eax, [local_8h]
|           0x0804859e      89442408       mov dword [esp + 8], eax
|           0x080485a2      8d835ee8ffff   lea eax, [ebx - 0x17a2]
|           0x080485a8      89442404       mov dword [esp + 4], eax
|           0x080485ac      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=-1 ; 8
|           0x080485af      890424         mov dword [esp], eax
|           0x080485b2      e839feffff     call sym.imp.sscanf         ; int sscanf(const char *s,
|           0x080485b7      8b450c         mov eax, dword [arg_ch]     ; [0xc:4]=-1 ; 12
|           0x080485ba      89442404       mov dword [esp + 4], eax
|           0x080485be      8b45f8         mov eax, dword [local_8h]
|           0x080485c1      890424         mov dword [esp], eax
|           0x080485c4      e80bffffff     call sub.strncmp_4d4        ; int strncmp(const char *s1, const char *s2, size_t n)
|           0x080485c9      85c0           test eax, eax
|       ,=< 0x080485cb      7443           je 0x8048610
|       |   0x080485cd      c745f4000000.  mov dword [local_ch], 0
|       |      ; JMP XREF from 0x0804860e (sub.sscanf_589)
|      .--> 0x080485d4      837df409       cmp dword [local_ch], 9     ; [0x9:4]=-1 ; 9
|     ,===< 0x080485d8      7f36           jg 0x8048610
|     |||   0x080485da      8b45f8         mov eax, dword [local_8h]
|     |||   0x080485dd      83e001         and eax, 1
|     |||   0x080485e0      85c0           test eax, eax
|    ,====< 0x080485e2      7525           jne 0x8048609
|    ||||   0x080485e4      8b83fcffffff   mov eax, dword [ebx - 4]
|    ||||   0x080485ea      833801         cmp dword [eax], 1          ; [0x1:4]=-1 ; 1
|   ,=====< 0x080485ed      750e           jne 0x80485fd
|   |||||   0x080485ef      8d8361e8ffff   lea eax, [ebx - 0x179f]
|   |||||   0x080485f5      890424         mov dword [esp], eax
|   |||||   0x080485f8      e8e3fdffff     call sym.imp.printf         ; int printf(const char *format)
|   |||!|      ; JMP XREF from 0x080485ed (sub.sscanf_589)
|   `-----> 0x080485fd      c70424000000.  mov dword [esp], 0
|    ||||   0x08048604      e807feffff     call sym.imp.exit           ; void exit(int status)
|    ||!|      ; JMP XREF from 0x080485e2 (sub.sscanf_589)
|    `----> 0x08048609      8d45f4         lea eax, [local_ch]
|     |||   0x0804860c      ff00           inc dword [eax]
|     |`==< 0x0804860e      ebc4           jmp 0x80485d4
|     | |      ; JMP XREF from 0x080485cb (sub.sscanf_589)
|     | |      ; JMP XREF from 0x080485d8 (sub.sscanf_589)
|     `-`-> 0x08048610      83c414         add esp, 0x14
|           0x08048613      5b             pop ebx
|           0x08048614      5d             pop ebp
\           0x08048615      c3             ret
```

From:
```
|           0x080485c4      e80bffffff     call sub.strncmp_4d4        ; int strncmp(const char *s1, const char *s2, size_t n)
|           0x080485c9      85c0           test eax, eax
|           0x080485cb      7443           je 0x8048610
```
We see that whatever sub.strncmp_4d4 returns, if it equals to 0 (test eax,eax. Remember that `TEST` sets the `ZF` when the `AND` is 0, and `JE` jumps if `ZF` is 0. Test does not save the result of the AND operation anywhere, but `CMP` subtracts the second operand from the first operand.), it will jump to the end and exit out.

Lets take a look into it, and see what to supply so that the value it returns is not 0.
In the lower half of the function,
```
|      ||   0x0804852a      e8d1feffff     call sym.imp.strncmp        ; int strncmp(const char *s1, const char *s2, size_t n)
|      ||   0x0804852f      85c0           test eax, eax
|      |`=< 0x08048531      75ba           jne 0x80484ed
|      |    0x08048533      8b83fcffffff   mov eax, dword [ebx - 4]
|      |    0x08048539      c70001000000   mov dword [eax], 1
|      |    0x0804853f      c745f4010000.  mov dword [local_ch], 1
|      |,=< 0x08048546      eb0c           jmp 0x8048554
|      ||      ; JMP XREF from 0x080484fe (sub.strncmp_4d4)
|      `--> 0x08048548      c70424ffffff.  mov dword [esp], 0xffffffff ; [0xffffffff:4]=-1 ; -1
|       |   0x0804854f      e8bcfeffff     call sym.imp.exit           ; void exit(int status)
|       |      ; JMP XREF from 0x08048546 (sub.strncmp_4d4)
|       `-> 0x08048554      8b45f4         mov eax, dword [local_ch]
```
We spot this. So whatever `sym.imp.strncmp` is for, if the result of this comparison is 0 (same) then we will get a value of `1` in `eax`.

####At this point, I had a lot of help from WereW's writeup. I'm not sure how he realized that there was an environment variable constraint, but the rest of his solution are as follows: https://werew.tk/article/11/ioli-crackme0x09

It saddens me to realize that I have a lot more to learn when I overestimated myself and jumped forword 5 levels.
This blogpost was completed on 1st October, 3 months late due to University work and CTFs.

