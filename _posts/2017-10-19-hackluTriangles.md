---
layout: post
title: HackLU writeup for Triangles challenge
comments: true
date: 2017-10-19
categories: ctf
---
Hello! Welcome to my first CTF write-up, aimed at beginners such as myself.
This is my 4th CTF thus far, and also the one that we did the worst at.
But we'll get better. With that said, lets begin!

Please skip to the UnicornJS part if you are familiar with the basics.

# Triangles Writeup

## Challenge: [Triangles](https://flatearth.fluxfingers.net/challenges/3)

When we first visit the [challenge link](https://triangle.flatearth.fluxfingers.net/), we are greeted with a login form preceeded with a flag.

Looking through the source, we find some .js scripts linked as well as a snippet embedded. It looks scary, but `o1, o2, o3` will be very useful later.

![https://i.imgur.com/5d4chSU.png](https://i.imgur.com/5d4chSU.png)

Lets look at what these scripts are doing.

### secret.js

```javascript
function test_pw(e, _) {
    var t = stoh(atob(getBase64Image("eye")))
      , r = 4096
      , m = 8192
      , R = 12288
      , a = new uc.Unicorn(uc.ARCH_ARM,uc.MODE_ARM);
    a.reg_write_i32(uc.ARM_REG_R9, m),
    a.reg_write_i32(uc.ARM_REG_R10, R),
    a.reg_write_i32(uc.ARM_REG_R8, _.length),
    a.mem_map(r, 4096, uc.PROT_ALL);
    for (var o = 0; o < o1.length; o++)
        a.mem_write(r + o, [t[o1[o]]]);
    a.mem_map(m, 4096, uc.PROT_ALL),
    a.mem_write(m, stoh(_)),
    a.mem_map(R, 4096, uc.PROT_ALL),
    a.mem_write(R, stoh(e));
    var u = r
      , c = r + o1.length;
    return a.emu_start(u, c, 0, 0),
    a.reg_read_i32(uc.ARM_REG_R5)
}
function enc_pw(e) {
    var _ = stoh(atob(getBase64Image("frei")))
      , t = 4096
      , r = 8192
      , m = 12288
      , R = new uc.Unicorn(uc.ARCH_ARM,uc.MODE_ARM);
    R.reg_write_i32(uc.ARM_REG_R8, r),
    R.reg_write_i32(uc.ARM_REG_R9, m),
    R.reg_write_i32(uc.ARM_REG_R10, e.length),
    R.mem_map(t, 4096, uc.PROT_ALL);
    for (var a = 0; a < o2.length; a++)
        R.mem_write(t + a, [_[o2[a]]]);
    R.mem_map(r, 4096, uc.PROT_ALL),
    R.mem_write(r, stoh(e)),
    R.mem_map(m, 4096, uc.PROT_ALL);
    var o = t
      , u = t + o2.length;
    return R.emu_start(o, u, 0, 0),
    htos(R.mem_read(m, e.length))
}
function get_pw() {
    for (var e = stoh(atob(getBase64Image("templar"))), _ = "", t = 0; t < o3.length; t++)
        _ += String.fromCharCode(e[o3[t]]);
    return _
}
```
Calling `get_pw()` in the console returns us `"XYzaSAAX_PBssisodjsal_sSUVWZYYYb"`. It seems like this will be useful later.
Remember that in the screenshot above we saw that the login form has this function:
```javascript
function login(){
  var input = document.getElementById('password').value;
  var enc = enc_pw(input);                //throw entered password into enc_pw
  var pw = get_pw();                      //pw = get_pw(); 
  //get enc_pw == get_pw
  if(test_pw(enc, pw) == 1){
    alert('Well done!');
  }
  else{
    alert('Try again ...');
  }
}
```

Leaving that aside for now, we look next at util.js.
```javascript
// From util.js

// Basically, split t up into arrays and for each array[i],
// return its charCode
function stoh(t) {
    return t.split("").map(function(t) {
        return t.charCodeAt(0)
    })
}

//Convert a unicode array into a String
function htos(t) {
    return String.fromCharCode.apply(String, t)
}

//
function getBase64Image(t) {
    var e = document.getElementById(t)
      , a = document.createElement("canvas");
    a.width = e.width,
    a.height = e.height;
    var n = a.getContext("2d");
    n.drawImage(e, 0, 0);
    var r = a.toDataURL("image/png");
    return r.replace(/^data:image\/(png|jpeg);base64,/, "")
}
```
As the name suggests, util.js contains auxilary functions for use.


### Unicorn JS
[UnicornJS](https://alexaltea.github.io/unicorn.js/) is an emulator framework for architectures such as ARM, and will be the most important piece of our puzzle.
Visit the project page in question and read the demo to understand how its being used. We then realize that the emulator must be taking in some ARM code.

ARMed with knowledge that UnicornJS is being used, we can better translate what `secret.js` is doing.

#### Understanding secret.js
```javascript
function test_pw(e, _) {
    var t = stoh(atob(getBase64Image("eye")))
      , r = 4096
      , m = 8192
      , R = 12288
      , a = new uc.Unicorn(uc.ARCH_ARM,uc.MODE_ARM);
    // Write registers and set up memory
    a.reg_write_i32(uc.ARM_REG_R9, m),  //mem start location for password
    a.reg_write_i32(uc.ARM_REG_R10, R), // mem start locations for enc pw (input)
    a.reg_write_i32(uc.ARM_REG_R8, _.length), //using the length of password here.
    a.mem_map(r, 4096, uc.PROT_ALL);
    for (var o = 0; o < o1.length; o++) //o1 is 128 long.
        a.mem_write(r + o, [t[o1[o]]]); // <<< CODE for emulator!

    a.mem_map(m, 4096, uc.PROT_ALL),  //  mapping and writing _
    a.mem_write(m, stoh(_)),
    a.mem_map(R, 4096, uc.PROT_ALL), //  mapping and writing e
    a.mem_write(R, stoh(e));
    // m = charcode version of _
    // R = charcode version of e
    var u = r
      , c = r + o1.length;
    //begin = r = 4096 (address)
    //until = 4096 + 128  (address)
    //start emulator and reads from Register5
    return a.emu_start(u, c, 0, 0),
    a.reg_read_i32(uc.ARM_REG_R5)
```
Remember that this function is called with the parameters `test_pw(enc_pw(userInput), get_pw())`
From `a.emu_start(u, c, 0, 0)`, we can understand that somehow, whatever is written in that memory region can be translated into ARM code.

Hence, inorder to reverse this challenge, we must retrieve the ARM code.
To do this:
```javascript
function getARM1(){
  var x = stoh(atob(getBase64Image("frei")));
  var output = new Array();
  for(var i = 0; i < o2.length ; i++){
    output[i] = x[o2[i]];
  }
  return output;
} 

//Looking at o2, we observe that our output will be in integers. 
//Lets try converting them to hex values.

function toHexString(byteArray) {
  return Array.from(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('')
}
```
By doing `toHexString(getARM1())`, we get this `0800a0e10910a0e10a20a0e10030a0e30050a0e30040d0e5010055e30100001a036003e2064084e0064084e2015004e20040c1e5010080e2011081e2013083e2020053e1f2ffffba0000a0e30010a0e30020a0e30030a0e30040a0e30050a0e30060a0e30070a0e30090a0e300a0a0e3`
We then paste this hex-string into an online converter to receive:
```Assembly
    ; FROM test_pw:

    MOV R0, SB       ; R0 = SB, Static base register. This is a synonym for R9. #R0 = R9 = m. (the secret password is here)
    MOV R1, SL       ; R1 = SL, Stack Limit register. This is a synonym for R10. #R1 = R10 = R (the input password is here)
    MOV R3, R8       ; R8 = input password length
    MOV R4, #0
    MOV R5, #0
    MOV IP, #0
    LDRB  R2, [R0]       ; Load secret password
    LDRB  R6, [R1]       ; Load input password 
    ADD R6, R6, #5       ; Will do +5
    AND IP, R4, #1       ; ip == R4 and 1
    CMP IP, #0           
    BEQ #0x34             ; Will jump when IP is 0, or rather when R4 is even 
    SUB R6, R6, #3        ; Will do -3 this when R4 is odd.
    CMP R2, R6            ; 0x34 here, if R4 is even, just compare.
    BNE #0x54             ; R2 needs == R6
    ADD R0, R0, #1
    ADD R1, R1, #1
    ADD R4, R4, #1        ; Increment all. R4 is a counter
    CMP R4, R3            ; Check if counter < input length
    BLT #0x18
    MOV R5, #1      ; We need this!
    MOV R0, #0      ; 0x54 here
    MOV R1, #0
    MOV R2, #0
    MOV R3, #0
    MOV R4, #0
    MOV R6, #0
    MOV R7, #0
    MOV R8, #0
    MOV SB, #0
    MOV SL, #0
    MOV IP, #0

    ; Repeating this with enc_pw give us ;
    ; FROM enc_pw:

    MOV R0, R8          ; R8 -> R0, R0 = 8192
    MOV R1, SB          ; R1 = SB, Static base register. This is a synonym for R9. #R1 = R9 = m. (we should read final result from here)
    MOV R2, SL          ; R2 = SL, Stack Limit register. This is a synonym for R10. #R2 = R10 = e.length (input length)
    MOV R3, #0
    MOV R5, #0
    LDRB  R4, [R0]      ; Load register byte. #0x14 here
    CMP R5, #1          ; IS R5 = 1? 
    BNE #0x28           
    AND R6, R3, #3      
    ADD R4, R4, R6
    ADD R4, R4, #6      ; 0x28 is here. If R5 is 0, come here
    AND R5, R4, #1      ; R5 == 1 if R4 is odd.
    STRB  R4, [R1]      ; store register byte
    ADD R0, R0, #1      
    ADD R1, R1, #1
    ADD R3, R3, #1
    CMP R3, R2
    BLT #0x14           ; Go back if R3 < input length. R3 is a counter
    MOV R0, #0
    MOV R1, #0
    MOV R2, #0
    MOV R3, #0
    MOV R4, #0
    MOV R5, #0
    MOV R6, #0
    MOV R7, #0
    MOV SB, #0
    MOV SL, #0
```
If you are new to assembly, the roughly translated functions can be found at the bottom of the post.[Here](http://armconverter.com/hextoarm/) is the online converter I used.

Knowing how the functions work now, we can quickly create a function to help us find what we need to pass `test_pw`.

```javascript
function findReqR6(){
  var pw = stoh("XYzaSAAX_PBssisodjsal_sSUVWZYYYb"); //We found this string above, from get_pw();
  var required = new Array();
  for(var i = 0 ; i < pw.length; i ++ ){
      var a = pw[i];
      a = a - 5;            // We do this to find out what the original input needs to be.
      if(i & 1 == 1){
        a = a + 3;          // Because the test adds 5, and might sub 2 in some cases
      }                     // according to the assembly above.
      required[i] = a;
  }
  return required;
}
```

`htos(findReqR6())` Will give us ``` SWu_N?<VZN=qngnm_hn_g]nQPTRXTWT` ```. 

But this is not enough, remember that the login is done as such `test_pw(enc_pw(userInput), get_pw())`.

So we construct a function to find the original input we need.
```javascript
function reverseEnc(argarray){
  var test = 0;
  var output = new Array();
  
  for(var i = 0 ; i < argarray.length ; i++){
    var x = argarray[i];
    if(test == 1){
      var sub = (i & 3);
      x = x - sub;      //Once again we find this by reading through the assembly.
    }
    x = x - 6;
    test = (argarray[i] & 1);
    output[i] = x;
  }
  return output;
}
```
Finally, doing `htos(reverseEnc(findReqR6()))` gives us `MPmVH94PTH7hhafgYahYaVfKJNLRNQLZ`, the flag itself.


Thanks for reading!
Please do not hesitate to contact me for any clarifications :)
(send me a message on ctftime, I'm still sorting things out over here.)

#### Appendix
Here are the javascript 'replica' versions of the ARM code. 
While it will not directly translate to what the ARM code is doing, it is a rough version of whats going on.

I hope whoever is reading this might find it useful.

```Javascript
function pwTestReplica(input){
    var pw = stoh("XYzaSAAX_PBssisodjsal_sSUVWZYYYb");
    var output = new Array();
    for(var i = 0; i < input.length; i++){
      var a = input[i];
      var b = pw[i];
      a = a+5;
      var helper = (i & 1);
      if(!(helper == 0 )){
        a = a - 3;
      }
      console.log("We need a = " + pw[i]);
      console.log("We got a = " + a);
      output[i] =a;
      
      if(a != b){
        console.log("failed at " + i);
      } 
    }
    return output;
}


function encReplica(argstring){
  var test = 0 ;
  var argarray = stoh(argstring);
  var output = new Array();
  for( var i = 0 ; i < argarray.length ; i++){
    var x = argarray[i];
    if(test == 1){
      var adder = (i & 3);
      x = x + adder;
    }
    x = x +6;
    test = (x & 1);
    output[i] = x;
  }
  return output;
}
```
Thank you for reading!
