---
layout: post
title:  "[0x1:Crackme] Basic Reversing with Radare2 and GDB Peda."
comments: true
date:   2017-06-05 22:50:00
categories: main
---
#### Continuing on, today we will try to finish Crackme0x01 - Crackme0x03.


## [crackme0x01]
So lets look at what we have in the main function.
```
|    ; [0x8048541:4]=0x73736150                   |
|    ; LEA str.Password:                          |
|    ; "Password: " @ 0x8048541                   |
| mov dword [esp], str.Password:                  |
| call sym.imp.printf ;[ga]                       |
| lea eax, [ebp - local_4h]                       |
| mov dword [esp + local_4h_2], eax               |
|    ; [0x804854c:4]=0x49006425                   |
|    ; "%d"                                       |
| mov dword [esp], 0x804854c                      |
| call sym.imp.scanf ;[gb]                        |
|    ; [0x149a:4]=0x2ec0804                       |
| cmp dword [ebp - local_4h], 0x149a              |
```
In the `scanf` call, it appears that `%d` is passed into the function.
So our password must be a number. 

Below, we see that the `cmp` looks for whatever is equal to 0x149a.
What is 0x149a in decimal?

Outside of Radare2, we can use `rax2 0x149a` to find out.
Inside, we can use '? 0x149a` to display the various representations of 0x149a.

```
lim1ts@thesignal:~/Downloads/challenges$ rax2 0x149a
5274
lim1ts@thesignal:~/Downloads/challenges$ ./crackme0x01
IOLI Crackme Level 0x01
Password: 5274
Password OK :)
```

Sure enough, 5274 is our answer.

## [crackme0x02]
We spot a `JNE` instruction at the jump location. Once again our `cmp eax, dword [ebp - local_ch]` has to be the same.
This time we get a success when we _don't_ make the jump.

Observe that there's a lot of MOV around. That's alright.
But notice two new instructions - `ADD` and `IMUL`.

`ADD` is pretty straight forward; it just adds one register or immediate(hard coded constant) into the other.
The calling convention here dictates that we will add `edx` into `eax`... *wait*.

It's adding into `dword[eax]`? What's that supposed to mean?

First let's talk about `dword` - we kinda took this for granted.
The 'd' in _dword_ stands for _double_.
A _word_ is 16 bits long, so a dword is 32 bits.

The size directives `BYTE PTR`, `WORD PTR` and `DWORD PTR` tells the machine which location the operand should operate on.
For example, consider `mov [ebx], 2`.

It it difficult to know which area to move the value `2` into. The assembler must be given a size directive to understand where this value would go to, since it can move the 32-bit, 16-bit or 8-bit representation of 2 into the register.

The size directives BYTE PTR, WORD PTR, and DWORD PTR serve this purpose, indicating sizes of 1, 2, and 4 bytes respectively.

##### From [this guide to x86 assembly](http://www.cs.virginia.edu/~evans/cs216/guides/x86.html).
```
For example:

    mov BYTE PTR [ebx], 2 	; Move 2 into the single byte at the address stored in EBX.
    mov WORD PTR [ebx], 2 	; Move the 16-bit integer representation of 2 into the 2 bytes starting at the address in EBX.
    mov DWORD PTR [ebx], 2     	; Move the 32-bit integer representation of 2 into the 4 bytes starting at the address in EBX.
```

What `IMUL` does in this context `(imul eax, dword [ebp - local_8h])` is to multiple `eax` by the 32-bit representation of the _value_ held by `EBP-local_8h`, and stores the result in `eax`.

Now that we're all clear, lets take it from the top, this time with the help of GDB.

Let's break right after the `scanf`, at `0x0804842b` by doing `b \*0x0804842b`.
Use `ni` to step through the instructions.

```
=> 0x804842b <main+71>:	mov    DWORD PTR [ebp-0x8],0x5a
   0x8048432 <main+78>:	mov    DWORD PTR [ebp-0xc],0x1ec
```
P.S: the PTR forces expression to be treated as a pointer of specific type (DWORD).
It appears in GDB but not in Radare2. Think of it as a typecast, like in C.

Step through these instructions, and observe that the values are moved into their repective memory regions.
Use "x/w" to do so.
Where `x` means to print some intger as a hexadecimal, and `w` is the size (4 bytes).
```
gdb-peda$ x/w $ebp-0x8
0xffffce80:	0x0000005a
gdb-peda$ x/w $ebp-0xc
0xffffce7c:	0x000001ec
```

Continuing on...
```
0x804843c <main+88>:	lea    eax,[ebp-0x8]
0x804843f <main+91>:	add    DWORD PTR [eax],edx
```
Looks like we're going to take the *address* of `ebp-0x8` and store it into eax.
Then, we're going to take the value of `edx` and add it to the `DWORD PTR [EAX]`. 

What does this do?
Let's step past it.

`EAX` now takes a value of `0x246`, which is the sum of `0x5a` and `0x1ec`.
*But hey - take a look at `ebp-0x8`. It also takes the value of `0x246`!*

This is because we didn't just move the value of `ebp-0x8` in, but we loaded its address and did the `ADD` on it.
Hence, according to GDB, the status of the `EAX` register is:

```
[----------------------------------registers-----------------------------------]
EAX: 0xffffce80 --> 0x246
```
Ah.
The next instruction then does a `mov eax, DWORD [ebp - 0x8]`. This moves the value `0x246` into eax.
Giving us....
`
EAX: 0x246 
`

Next, `IMUL`. We expect `EAX`'s value to be multiplied by `DWORD [ebp - 0x8]`, which is essentially a square.
Later, the variable that we typed in through `scanf` will be loaded into `eax` and compared against it.
At this point of time, you might have realized that there was no need to go through all this, and everything could have been done with GDB actually.

All you had to do was to break right before the compare, and do a simple:
```
gdb-peda$ x $ebp-0xc
0xffffce7c:	0x00052b24

...

lim1ts@thesignal:~/Downloads/challenges$ ./crackme0x02
IOLI Crackme Level 0x02
Password: 338724
Password OK :)

```

Awesome!

## [Crackme0x03]
Now this one is a little bit tricky.
You don't see any signs of "Invalid password" or "Password ok" anywhere! 
This is because they are hidden within the `test` function and obfuscated only to be "unravelled" in the `shift` function.
Lets ignore that for now.

The `main` program looks quite simple to the previous problem. 
Our goal is the make this jump inside the `test` function succeed.

```
   0x8048474 <test+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x8048477 <test+9>:	cmp    eax,DWORD PTR [ebp+0xc]
=> 0x804847a <test+12>:	je     0x804848a <test+28>
```

The addition to `ebp` tells us that these values are taken from the Caller, which is `main`, instead of the local function.
These values are `0x5a` and `0x1ec`.

Lets look at the main function again and see where we can help.

```
| mov dword [ebp - local_8h], 0x5a                |
| mov dword [ebp - local_ch], 0x1ec               |
| mov edx, dword [ebp - local_ch]                 |
| lea eax, [ebp - local_8h]                       |
| add dword [eax], edx                            |
| mov eax, dword [ebp - local_8h]                 |
| imul eax, dword [ebp - local_8h]                |
| mov dword [ebp - local_ch], eax                 |
| mov eax, dword [ebp - local_ch]                 |
| mov dword [esp + local_4h_2], eax               |
| mov eax, dword [ebp - local_4h]                 |
| mov dword [esp], eax 			          |
| 0x0804850c e85dffffff     call sym.test ;[gc]   |
``` 

So the input that we control - `ebp - 0x4 ` is being used 
The value inside `eax` is then moved into the address of `esp`.
This means that whatever `eax` has been pointing to, now `esp` points to it as well.
`esp` now points to our input.

In the test function we see:

```
   0x804846e <test>:	push   ebp
   0x804846f <test+1>:	mov    ebp,esp
   0x8048471 <test+3>:	sub    esp,0x8
=> 0x8048474 <test+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x8048477 <test+9>:	cmp    eax,DWORD PTR [ebp+0xc]
   0x804847a <test+12>:	je     0x804848a <test+28>
```

`ebp` is being changed by `esp`!
It is then subtracted by a `0x8`.

That is, after the calling conventions where the caller's `esp` is now the callee's `ebp`.
The `esp` is then subtracted again to make space for callee's local variables.

This is seen in: 
```
   0x804846e <test>:    push   ebp       ; save old frame pointer
   0x804846f <test+1>:  mov    ebp,esp   ; get new frame pointer
   0x8048471 <test+3>:  sub    esp,0x8   ; reserve place for locals.
```

Okay... so where does EBP point to right now?
The stack looks like this now:

```
0000| 0xffffce50 --> 0xffffce84 --> 0x1
0004| 0xffffce54 --> 0xf7ffd918 --> 0x0
0008| 0xffffce58 --> 0xffffce88 --> 0x0       <----- EBP points here! Remember, its the BASE pointer.
0012| 0xffffce5c --> 0x8048511 (<main+121>:     mov    eax,0x0)
0016| 0xffffce60 --> 0x1 
0020| 0xffffce64 --> 0x52b24
```
The next 2 instructions shows that we will be performing a `cmp` on `ebp + 0x8` and `ebp + 0xc`.
These values are `0x1` (my entered value) and `0x52b24`.

Huh, looks like that answer might be the same.

```
lim1ts@thesignal:~/Downloads/challenges$ ./crackme0x03
IOLI Crackme Level 0x03
Password: 338724
Password OK!!! :)
```

Indeed!

### Afterword

We didn't look into the `shift` function this time, but I imagine such obfucastion techniques will become rather userful to understand in the times tocome. That being said, we have yet to look into the raw power of Radare2 yet.

We will continue next time! 

