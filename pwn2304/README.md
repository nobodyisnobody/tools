## PWN2304 docker for pwning task, based on ubuntu 23.04

this is a docker with all the tools setup and configured for pwning tasks in ctf.

here are various tools installed for pwning tasks

gdb, gdbserver, gdb-multiarch, pwntools, gef variant from bata24 (https://github.com/bata24/gef) z3-solver, seccomp-tools, one_gadget, ROPGadget , ropper, pwndbg, 
decomp2dbg (https://github.com/mahaloz/decomp2dbg) to have IDA/ghidra/binary ninja symbols and decompiled output in gef...
pwninit (with a standard pwninit template that you can edit) various config file , for tmux, screen, to allowed scroll with mouse, edit lines..

libc for various arch, arm, mips, aarch64, riscv64, etc... qemu-binfmt set for running executable from any arch from pwntools

qemu for debugging kernels and emulate binaries of various arch ltrace, sotrace, and may other things

all is setup , configured , and should work "out of the box"

if you found any problems, report it to me

any improvements,...same..

### usage

So first build the docker with the script build.sh

you can run the docker with run.sh script

copy the pwn2304 script in your $PATH, to launch it when you need

the current directory will be mapped to /host directory in the docker

the docker run command export /dev/kvm to the docker for debugging kernels with qemu and the various directories needed for running X application from inside the docker

before using the docker, you will have to execute in your terminal

xhost +

to authorize X client connection from localhost

in pwninit-template.py , there is a template that will be use when you call pwninit to create a solve.py, you can adjust the template like you want

pwninit will automatically add binary name, library name, etc.. in it to produce the solve.py exploit customized template

