Notepad--
=========

This challenge was part of the VolgaCTF 2020 Qualifier.

Category: pwn.

Challenge file: `notepad`. `libc` was not given.

Description: 
```
Notepad-- is the app to store your most private notes, with an extremely lightweight UI. Check it out!

nc notepad.q.2020.volgactf.ru 45678
```

### Solution

Connecting to the challenge gives the following menu:
```
Welcome to Notepad--
Pick an existing notebook or create a new one
[p]ick    notebook
[a]dd     notebook
[d]elete  notebook
[l]ist    notebook
[q]uit

>
```

In this challenge you can manage notebooks.
This includes adding, deleting, and listing notebooks.
Picking an added notebook results in the following menu:

```
Operations with notebook "MyNotebook"
[a]dd     tab
[v]iew    tab
[u]pdate  tab
[d]elete  tab
[l]ist    tabs
[q]uit

>
```

So, every Notebook can hold 'tabs'.
We can add, view, change, and delete tabs in the selected notebook.
Note that listing all notebooks prints their names while viewing a single notebook shows its contents.

Let's load the binary in a decompiler and look at the datastructures.
After adding some names you can come to the following structs:

```c
struct notebook {
	char name[16];
	int64_t number_of_tabs;
	struct tab tabs[64];
};

struct tab {
	char name[16];
	int64_t c_size;
	char *content;
};
```

Thus, the sizes are `sizeof(struct tab) == 0x20` and `sizeof(struct notebook) == 0x818`.
All notebooks are stored in an array `struct notebook notebooks[16]` in the bss segment.
The content of a tab is stored in malloc'd memory and its size is kept in the `c_size` member.

So far, so good. But where is the vulnerability?
Looking at the function for adding a notebook you can see that the name of the notebook is read by `scanf("%s", buffer)`.
Thus, you can easily overflow into the `number_of_tabs` member and change its value.
By setting it to a large number, one is able to read and write out of the bounds of the tab array.

Let's have a closer look at the memory layout.
Since everything (except the tab content) is stored in a linear layout, overflowing the tab array results in access to the subsequent notebooks data (e.g. `notebooks[1]` is `notebooks[0].tab[64]`).
Fortunatelly, the size of the notebook is not a multiple of the tab size, so this access is misaligned by 8 bytes.
In the following graphic you can see that `notebooks[0].tab[65]` is no longer at the beginning of a tab but points in the middle of a tab name.

```
notebooks[0]
   |
   +----------->   0x0 +----------------+
                       | name           |
                   0x8 +----------------+
                       | name           |
notebooks[0].tab[0]    +----------------+
   |                   | number_of_tabs |
   +---------->   0x18 +----------------+                               -+
                       | tab[0].name    |                                |
                       +----------------+                                |
                       | tab[0].name    |                                |
                       +----------------+                                |
                       | tab[0].c_size  |                                |
notebooks[0].tab[1]    +----------------+                                |
   |                   | tab[0].content |-----> (malloc'd memory)        |
   +---------->   0x38 +----------------+                                |
                       | tab[1].name    |                                |
                       +----------------+                                |  This part contains
                       | tab[1].name    |                                +- the 64 (0x40) tab structs
                       +----------------+                                |  of notebooks[0]
                       | tab[1].c_size  |                                |
                       +----------------+                                |
                       | tab[1].content |-----> (malloc'd memory)        |
                  0x58 +----------------+                                |
                       | ...            |                                |
                       +----------------+                                |
                       |                |                                |
                       |                |                                |
notebooks[1]           |                |                                |
   |                   |                |                                |
   +--------->   0x818 +----------------+                               -+
                       | name           |
                       +----------------+
                       | name           |
                       +----------------+
                       | number_of_tabs |
notebooks[0].tab[65]   +----------------+
   |                   | tab[0].name    |
   +--------->   0x838 +----------------+
                       | tab[0].name    |
                       +----------------+
                       | tab[0].c_size  |
                       +----------------+
                       | tab[0].content |---->... (malloc'd memory)
notebooks[0].tab[66]   +----------------+
   |                   | ...            |
   +--------->   0x858 +----------------+
                       |                |
```

Going further, in `notebook[3]` this index points to the `content` member of the tabs.
Therefore, we can first read that pointer in the `content` member to get a heap leak and then overwrite it (by updating the tap out of bounds) to get arbitrary read and write.

For the heap leak let's create four notebooks:
```
notebook_add("A"*0x10 + "\xc4")
notebook_add("B"*0x8)
notebook_add("C"*0x8)
notebook_add("D"*0x8)
```

Note: Indices in user interaction are one-based, which is mapped to zero-based array access.
In this writeup all indices are zero-based.

The first notebook is now capable of accessing the contents of the subsequent notebooks.
By adding a tab to `notebooks[3]` and listing all tabs of `notebooks[0]` we receive a heap address since 
the access to the name of `notebooks[0].tab[195]` results in the access of the `content` member of `notebooks[3].tab[0]`.

The tab which was added to `notebooks[3]` in the previous step should have a content of length 8.
This makes the implementation of arbitrary read and write easier since this is the size which will be passed to `read` and `write` syscalls later.

Arbitrary read and write can now be implemented by updating the name of `notebooks[0].tab[195]` with the target address.
This overwrites the `content` pointer of `notebooks[3].tab[0]` with the desired address.
By viewing (arbitrary read) or updating (arbitrary write) `notebooks[3].tab[0]` we can now read or write the target address. 

Given these primitives it goes straight forward to starting a shell.
By first adding and then removing a couple of taps (at least 8) one can get a libc address on the heap, which can be leaked with the arbitrary read.

Since the version of libc is not given, one must fingerprint the entries of the `notepad`s got.
From the libc address we can retrieve a pointer to the binary itself, which is located close to the libc address we leaked.

Then one might overwrite the `__free_hook` with `system`, add a tab with `/bin/sh` as content and pop a shell by deleting the tab.

Flag: `VolgaCTF{i5_g1ibc_mall0c_irr3p@rable?}`.

### Exploit

The exploit can be found in `x.py`.

I used Ubuntu glibc 2.27-3ubuntu1 (`BuildID[sha1]=b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0`), which you can find [here](https://packages.ubuntu.com/bionic/amd64/libc6/download).

You can use `run.py` to host this challenge on your local machine both with and without `gdbserver`.
