# xhost + for graphical
dir=${0%/*}
#docker run -it --rm --cap-add sys_ptrace -p 1235:1235 -p 6666:6666 --security-opt seccomp=unconfined --ipc=host --env="_X11_NO_MITSHM=1" -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix -v $(pwd):/host pwn2204
docker run -it --cap-add sys_ptrace --device=/dev/kvm --network host --security-opt seccomp=unconfined --ipc=host --env="_X11_NO_MITSHM=1" -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix -v $(pwd):/host pwn2204
