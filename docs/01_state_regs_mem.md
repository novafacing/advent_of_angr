# state/regs/mem

We'll be looking at how to view and control the state of the program during execution,
including examining and setting registers and memory, how to deal with symbolic and
concrete values, and how to manage multiple states. We'll also look at a pretty
exhaustive list of state options, which are one of the main ways we can affect angr's
behavior as it steps through our program.

## Table of Contents

1. [Shameless Plugs](#plugs)
2. [The State Object](#stateobj)
3. [Initial States](#initial)
4. [Viewing the State](#viewing)
5. [Symbolic Values, Z3, Solving](#solving)
6. [Modifying the State](#modifying)
7. [State Options](#options)
8. [State Callbacks/Inspect](#inspect)
9. [Citations](#citations)

## Shameless Plugs <a name="plugs" />

Before we go into how to create and use a `SimState`, I want to mention two tools I will
be using extensively and recommend that you do as well when working with angr.

### ptpython

[ptpython](https://github.com/prompt-toolkit/ptpython) is an enhanced REPL for python
somewhat similar to IPython or bpython, but in my opinion it is *way* better than either
one. The largest advantages of ptpython over other options *specifically for angr* are the
fact that it has way better autocomplete formatting:

```
>>> import angr
>>> p = angr.Project("binaries/00_import_angr/00_import_angr")
>>> p.concrete_target
        analyses                     execute()                    hook_symbol()
        arch                         factory                      hooked_by()
        concrete_target              filename                     is_hooked()                  >
        entry                        hook()                       is_java_jni_project
```

(I hate screenshots but you get the idea, the columns are a big help!)

It also allows us to up-arrow code *blocks* instead of individual lines. You've probably
written a loop in the normal `python3` repl and had to change one of the lines in it,
only to be dismayed when you have to hit the up arrow and enter twenty times each to
accomplish that. Not so with `pytpython` and since we'll be doing many loops, that's
a big time saver.

Finally, it can autocomplete arguments to functions and display docstrings inline. So
if we start typing a function, we get the docs!

```
>>> state = p.factory.blank_state(
                                  blank_state(**kwargs)




─────────────────────────────────────────────────────────────────────────────────────────────────────────────
Returns a mostly-uninitialized state object. All parameters are optional.

:param addr:            The address the state should start at instead of the entry point.
:param initial_prefix:  If this is provided, all symbolic registers will hold symbolic values with names
                        prefixed by this string.
:param fs:              A dictionary of file names with associated preset SimFile objects.
:param concrete_fs:     bool describing whether the host filesystem should be consulted when opening files.
:param chroot:          A path to use as a fake root directory, Behaves similarly to a real chroot. Used only
                        when concrete_fs is set to True.
 [F4] Vi (VISUAL)  204/204 [F3] History [F6] Paste mode                           [F2] Menu - CPython 3.8.10
```

Anyway, I shouldn't need to say much more, it's pretty epic. No shame about shilling
for this one. You can also embed it with
`from ptpython.repl import embed; embed(globals(), locals())`.

## objexplore

[objexplore](https://kylepollina/objexplore) is just a super simple tool for exploring
APIs. angr happens to have a huge API though, so exploring it with nice fuzzy search is
another big timesaver. `explore(angr)` is all you need to do for this one.


## The State Object <a name="stateobj" />

Lets use the same binary we briefly looked at "yesterday" (RIP my schedule, sorry
folks). The "State" in angr is generally an `angr.sim_state.SimState` object, and we can
think of it as a representation of the state of whatever system we are working on,
including memory, registers, IO, network, etc. Of course, angr is emulating our binary,
so there are some differences. Most notably, syscalls are not passed down to the OS like
they would be if we were running it directly, and there are a few other differences we
will look at as we get deeper in the angrverse.

Before we can check out everything the `SimState` object gives us access to, we need to
initialize one!

## Initial States <a name="initial" />

There are many options for creating initial states in angr, but the primary functions
for doing so are:

* `Project.factory.entry_state`
* `Project.factory.blank_state`
* `Project.factory.full_init_state`
* `project.factory.call_state`

### entry_state

Entry state is what you probably want to use *most* of the time unless there is a good
reason for using one of the others. This state simulates what the state of the program
looks like when you are just about to run starting from the entrypoint of your program.
In an ELF executable, that'll be from whatever address is specified in the ELF file
header (you can read a lot about the ELF format
[here](https://github.com/b01lers/bootcamp-training-2020/blob/master/rev/day_1/slides/day_1.pdf)).

#### A detour into SimOS

If we take a look at the code in
`angr/angr/factory.py::AngrObjectFactory.entry_state` we see that (and this is true of
all of the state factory methods), we actually just call into
`self.project.simos.state_(entry|blank|full_init|call)`. This makes sense, because the
definition of a "state initialized" is different for different operating systems
(Windows doesn't set up the stack for you the same way as Linux, plus many other
differences). To understand the code in the `SimOS`, we first need to understand what
exactly the `SimOS` is. Luckily, Audrey has gone ahead and put this together for us. The
[angr-platforms](https://github.com/angr/angr-platforms.git)[^fn1] repo contains a lot of the
information we need to know about in order to understand how a `SimOS` works and what we
need in order to correctly simulate an operating system (or architecture...the two
concepts are pretty thoroughly blended). I won't repeat the prior work, because it is
quite thorough, I'll just mention a few things that the `SimOS` implementation provides:

* Architecture description including:
  * Bitness
  * Endness
  * Arch name
  * Register names, sizes
    * Special register info for SP/IP/FP, etc.
  * Alignment rules for data/instructions
  * Memory mapping rules
  * System call library
* Loader
* Lifter
* Functions defining blank/entry/etc state setup procedures

So it's pretty important! Of course, the angr devs were nice and defined Linux, Windows,
the JVM, and Cyber Grand Challenge for us, so we won't need to do any of this ourselves
until we get later in the month and decide to make our own!

Now that we kind of know what a SimOS is, let's look at how the Linux (my turf! I won't
talk about W\*ndows *at all* this month, so I'm sorry if you were excited) SimOS sets up
the `entry_state`. If we look at `angr/angr/simos/linux.py::SimLinux.state_entry`, we
see it:

1. Set argc to the length of the arguments (Notice that argc is a `BVV`! Hold tight on
   that.
2. Set up argc, argv, envp on the stack in the right spot.
3. Set up argument registers to the entrypoint to point to the argv/envp `**`s
4. Set the symbols `__progname_full`, `__progname`, `__environ`, `environ`,
   `__libc_stack_end` to the correct values.

That's actually pretty much it, believe it or not...CLE does a lot more than this, of
course, but as far as the *operating system* goes, not too much to do to start a binary.

So our state consists of: argument registers and stack pointer/base pointer/instruction
pointer set up how we want them, and of course the program loaded and memory mapped
correctly (this is done by CLE though, *not* by the SimOS).

#### entry_state (for real now)

## Viewing the State <a name="viewing" />

## Symbolic Values, Z3, Solving <a name="solving" />

## Modifying the State <a name="modifying" />

## State Options <a name="options" />

## State Callbacks / Inspect <a name="inspect" />

## Citations <a name="citations" />

[^fn1]: subwire, lockshaw, rhelmot, ltfish. "angr-platforms"
[angr-platforms](https://github.com/angr/angr-platforms)
