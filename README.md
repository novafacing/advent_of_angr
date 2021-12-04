# Advent Of angr

![A pine tree, decorated for the holidays with yellow, pink, blue, and red lights. It has a cartoon face superimposed on it with angry red eyes and a smirking mouth.](res/logo.svg)

Advent of angr is my attempt at making [angr](https://github.com/angr/angr.git) a little
more accessible. The idea is essentially this (shamelessly quoted from my own discord
message):

"it's really easy to do almost anything you want in angr but there are so many gotchas
and the docs are so impenetrable a lot of people don't really try lol"

So I thought, why not take the time I'd usually spend doing
[useless puzzles](https://adventofcode.com/) and do something productive for myself and
anyone who wants to start using angr (or maybe find some nice features you didn't know
about before).

I won't be doing a new thing *every* day, because I am a student and Finals are a thing,
so instead I will take what I expect are the appropriate number of days per thing to
do the thing, write it up, and post it. I'm also not doing videos this year, sorry. Way,
WAY too much work to fit in! Maybe next year :)

## Advent Calendar

| M                          | T                            | W                                         | R                        | F                 | S               | S                    |
| -------------------------- | ---------------------------- | ----------------------------------------- | ------------------------ | ----------------- | --------------- | -------------------- |
| Nov 29                     | Nov 30                       | [00: import angr](docs/00_import_angr.md) | 01: state/regs/mem/oh my | 02: run a program | 03: nm, strings | 04: readelf, objdump |
| 05: classic ctf techniques | 06: some ctf problems (hell) | 07: static analysis                       |                          |                   |                 |                      |
|                            |                              |                                           |                          |                   |                 |                      |
|                            |                              |                                           |                          |                   |                 |                      |
|                            |                              |                                           |                          |                   |                 |                      |

## Descriptive Summaries!

0. [import angr](docs/00_import_angr.md): What angr is, sub-components, docs and help,
   installation, and importing and constructing a `Project`
1. state/regs/mem oh my: Inspecting and controlling the program state during execution.
   More on constraints, symbolic and concrete values, the solver, SimOS and interacting
   with virtual hardware memory and registers, states and state options.
2. run a program: How to run a program in angr, do IO with args, stdin/out, files, and
   network. Examining execution, controlling execution, and learning about path
   explosion. How to run concretely with Unicorn. Pre-constrained execution (with stdin,
   we'll look at other things later).
3. nm, strings: We'll implement the nm and strings programs using pure angr with the
   help of CLE and archinfo to get to know those tools better.
4. readelf, objdump: We'll implement some of the functionality of readelf and objdump
   using pure angr, again with CLE and archinfo, plus capstone.
5. classic ctf techniques: We'll quickly go through patterns you've probably seen
   from the excellent [angr_ctf](https://github.com/jakespringer/angr_ctf) and explain
   how they work, how to do the basics, and a couple of example CTF challenges.
6. some ctf problems (hell): I'll attempt to show some more advanced solutions to ctf
   challenges including the Hell challenge from SigPWNY because I was asked to. After
   that, we'll mostly be doing analysis stuff, not really CTF so much.
7. static analysis: We'll do an overview of most of the static analysis technqiues in
   the angr *knowledge base* and how we can use them to create very useful (and tractable)
   analyses of programs, even real world ones (woah!). We will look at some real
   code for this one and see if we can re-discover some known CVEs.

## Miscellaneous ideas (not assigned a day yet)

- Symbion, writing a backend (qdb?).
- Using archr for complex environment setup.
- Symbolic tracing and taint tracking.

## How to Install This Repo

To install this repo, you'll need to:

```sh
apt-get update -y && \
   apt-get install -y \
   libffi-dev \
   graphviz-dev
```

to install the dependencies for `angr`.

Then, you will need to install `poetry` from here: [poetry](https://github.com/python-poetry/poetry.git).

Finally, just run `poetry install` to install the dependencies, and you'll be able
to follow along!
