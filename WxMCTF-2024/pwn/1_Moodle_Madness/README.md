# WxMCTF '24 Pwn 1 - Moodle Madness

> It recently came to light from an anonymous source that "Moodle," the math assignment program made famous by Ms. Gugoiu, has an exploit to see the answers to questions. Buddhathe18th, always reluctant to do homework, decided to investigate this exploit himself for the notorious 3.2 STACK Part 2 Challenge. He vaguely recalls that it involves inputting a string into the answer box, but with 1 hour left, he needs some help. Could you help him find the exploit?

Using the `strings` command on linux by running `strings ./moodle`, it revealed a few lines of interest:
```
cmxw    H
m{ft    H
ld00    H
4m_3    H
r3t5    H
dn1m    H
}!!!    H
```

Reversing each line one by one, excluding the `H` at the end, and concatenating the reversed strings sequentially reveals the flag:

`wxmctf{m00dl3_m45t3rm1nd!!!}`