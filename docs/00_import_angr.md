# import angr

## Table of Contents

1. [What is angr?](#about)
2. [angr's Components](#components)
3. [angr's Documentation/Getting help](#documentation)
4. [Installing angr](#installation)
5. [import angr](#import)

## Before You Import Angr <a name="about" />

Before importing angr, it's somewhat useful to know what angr is. Shellphish tell it
extremely well in the
[paper](https://sites.cs.ucsb.edu/~vigna/publications/2016_SP_angrSoK.pdf),
so I will quote them. angr is "a binary analysis framework that integrates many of the
state-of-the-art binary analysis techniques in the literature". In my own experience,
if there is something you want to do with a binary, angr will either:

- Already do it
- Give you the tools to do it

And so we can base a lot of diverse binary analysis techniques and tools on this one
framework. This is great, because it gives researchers a common set of tooling to work
from and improve in the process. Hence, I'm doing this partially to raise awareness in
the hopes that someone reading this will go to
[the repo](https://github.com/angr/angr.git) and start contributing!

## angr's Components <a name="components" />

Importing angr is simple, but we should be aware that there are several sub-packages in
angr that provide very useful functionality. Some (like cle) are included by default,
and some (like angrop, which we'll look at later) are not.

### Main Components

- [archinfo](https://github.com/angr/archinfo.git): Architecture information provider,
  tells us:
  - What registers the CPU uses
  - What memory looks like
  - Endianness
  - And much, much more.
- [cle](https://github.com/angr/cle.git): CLE Loads Everything, is the loader used by
  angr to load:
  - ELF files
  - PEs
  - Mach-O
  - Blob/shellcode
- [claripy](https://github.com/angr/claripy.git): angr's solver engine, does symbolic
  stuff. We'll talk a lot more about this later as we get into it, but we can mostly
  think of it as a z3 wrapper. If you don't know what that is, that's ok.
- [angr](https://github.com/angr/angr.git): What you came here for. Puts everything
  together and provides:
  - Symbolic execution of binaries
  - Concrete execution (emulation) of binaries
  - Static analysis
  - Taint analysis
  - Graphs!
  - And again, a lot more stuff.

### Secondary Components

There are a few more that we will touch upon, including:

- [angrop](https://github.com/angr/angrop.git): ROPchain tool based on angr.
- [pyvex](https://github.com/angr/pyvex.git): Lifter from machine code to VEX IL
  (Intermediate Language) in python.
- [patcherex](https://github.com/angr/patcherex.git): Binary patching tool based on
  angr.
- [archr](https://github.com/angr/archr.git): Target-oriented orchestration system for
  angr to interface with docker (and other) targets.
- [rex](https://github.com/angr/rex.git): angr's AEG (Automated Exploit Generation)
  system.

### Third Party Components

Finally, angr uses a lot of existing code. We'll need to interface with some of that
existing code, so we'll want to know about:

- [capstone](https://github.com/capstone-engine/capstone.git): A simple and powerful
  disassembler.
- [keystone](https://github.com/keystone-engine/keystone.git): A simple and powerful
  assembler, by the same folks as capstone.
- [unicorn](https://github.com/unicorn-engine/unicorn.git): A simple and...you get the
  idea. Emulator.
- [qiling](https://github.com/qilingframework/qiling.git): angr actually doesn't use
  this, but we will.

## angr's Documentation/Getting Help <a name="documentation" />

A lot of people will tell you that "the code is the documentation" when it comes to
angr, but that isn't actually true. angr has excellent docstrings on almost all of its
functions, and it has a decent number of type hints as well. This makes the API doc
about as good as LLVM's Doxygen, which is really not bad. That API is
[here](https://angr.io/api-doc/index.html). Some things are, of course, not in the API
or they are not well explained in the API, so you will need to look at the source.
Where time allows throughout this month, I'll do that with you to show you how to
efficiently search the source code.

Generally, the order of "how do I do this in angr" should go:

1. Check [the main site](https://angr.io/). If it's simple, it might just tell you how
   outright.
2. Check [the API](https://angr.io/api-doc/index.html). Everything is on one page, so
   CTRL+F is your absolute best friend here. If you don't know where to look, start by
   going to the (angr|claripy|cle|pyvex|archinfo) sections.
3. Google your question. angr has a lot of [issues](https://github.com/angr/angr/issues)
   and it's possible someone else has had your question before.
4. Ask on the angr slack. Invitation is on the main site.
5. Ask me! You can @ or DM me on Twitter `@novafacing` or on Discord `@novafacing#7892`
6. Create an issue AKA Ask [rhelmot](https://github.com/rhelmot). Last line of defense,
   but if you have an angr question, xe can answer it.

## Installing angr <a name="installation" />

First, don't try to do this on a weird architecture or a weird python version or
whatever. Use x86_64, use python>=3.7,<4.0. If you don't have that...sorry! It might
still work?

There are two options for installing angr, the "normal" or user way (which I actually
use less often) and the "developer" way. I'm going to cover both, because it is pretty
useful to know about both of them if you're going to do any significant work with angr.

### The Normal Way

This is how I've installed angr for this guide and will probably be the way I install it
for the rest of this month, because it's a bit easier and simpler. Just take your
favorite [python](https://github.com/pyenv/pyenv.git)
[package](https://github.com/conda/conda.git)
[manager](https://github.com/python-poetry/poetry.git) and install the packages listed
above like normal. So for example:

`python3 -m pip install angr`

Or

`poetry add angr`

Or...I don't use the others, you can figure it out.

### The Dev Way

If you want to get serious and use angr like the core devs (or you want to use it in a
[docker container](https://github.com/novafacing/ctf-docker.git)), do this:

1. Make sure you have virtualenv and stuff installed! The install will bork otherwise.

```sh
python3 -m pip install virtualenv virtualenvwrapper setuptools
```

2. Make sure that `mkvirtualenv` works, so:

```sh
cd /tmp
mkdir test
cd test
mkvirtualenv test_venv
workon test_venv
deactivate
```

If that all works, you're good to go for:

3. Install angr-dev

```sh
git clone https://github.com/angr/angr-dev.git
cd angr-dev
./setup -e angr -i -u
```

4. Test that it worked:

```sh
workon angr
python3
>>> import angr
```

### Following Along

Whatever way you choose, I'll be using
[poetry](https://github.com/python-poetry/poetry.git) for the rest of the month (side
note, check out my crappy template initializer
[pyquick](https://github.com/novafacing/pyquick.git) if you want to *really* follow along
. I ran:

```sh
# Install random dependencies
sudo apt-get install graphviz build-essential python3 python3-pip \
  libffi-dev graphviz-dev
```

```sh
# Install our python environment and hope I don't miss anything
python3 -m pyquick -d angr -d archinfo -d cle -d claripy -d angrop -d pyvex \
    -d archr -d capstone -d keystone-engine -d unicorn -d ptpython -d networkx \
    -d pygraphviz p ./advent_of_angr -n
```

to initialize this project.

### Making A Test Binary

We'll write a quick little program:

```c
#include <stdio.h>
#include <stdlib.h>

#define ERROR (1)
#define OK (0)

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <message>\n", argv[0]);
        return ERROR;
    }

    printf("%s\n", argv[1]);
    return OK;
}
```

Pretty simple, just echoes the CLI argument. You can find that file
[here](/binaries/00_import_angr/00_import_angr.c) and compile it with `make`.

## Okay, Lets Import Angr <a name="import" />

```sh
poetry shell
ptpython
```

```python
>>> import angr
>>>
```

That's it! Wasn't that easy? We're actually done now and we can all go home.

Kidding. Let's do what angr tells us we should do:

```python
>>> import angr
>>> from pathlib import Path
>>> binary = Path(".") / "binaries" / "00_import_angr" / "00_import_angr"
>>> p = angr.Project(str(binary.resolve()))
WARNING | 2021-11-30 17:56:35,009 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
```

So what did we just do? angr has a concept of *Projects*, where a project is usually made
up of a binary, anything it loads (like libraries), all of the *knowledge* about it, and
any *state*, which we may have many of. When we construct a `Project`, we tell angr to
load the *thing*.

By *thing*, I mean, of course:

```python
>>> import angr
>>> print(angr.Project.__doc__)
...snip...
:param thing:                       The path to the main executable object to analyze, or a CLE Loader object.
...snip...
```

If you did the above (you should!) you'll see that we have a *ton* of options to mess with.
Take a look at them to see what angr lets us do even from the get-go, we'll be coming
back to look at all this in great depth later.
