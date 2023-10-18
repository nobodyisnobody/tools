FROM ubuntu:23.04

RUN dpkg --add-architecture i386 && apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -qy  \
    git nasm yasm python3 software-properties-common \
    python3-dev python3-setuptools python3-pyelftools python3-pip \
    libc6-dbg  \
    libc6-dbg:i386 \
    gdb gdbserver elfutils debuginfod  \
    wget \
    netcat-traditional \
    curl \
    cargo \
    bash \
    ltrace \
    strace \
    python3-capstone \
    socat \
    ruby ruby-dev \
    vim nano tmux \
    libncurses5:i386 libstdc++6:i386 \
    lxterminal xfce4-terminal libbrlapi-dev libssl-dev libreadline-dev libncursesw5-dev libsqlite3-dev tk-dev libgdbm-dev  libnss3-dev libffi-dev zlib1g-dev libntirpc-dev liblzo2-dev libpam0g-dev libffi-dev liblzma-dev lzma-dev libcacard0 libusbredirparser1 libusb-1.0-0 librdmacm1 libaio1 libiscsi-bin librbd1 libnuma1 qemu-system qemu-kvm qemu-user qemu-user-binfmt &&  \
    apt-get clean

RUN add-apt-repository ppa:aslatter/ppa -y && DEBIAN_FRONTEND=noninteractive apt-get install -qy alacritty

RUN wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb && wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl-dev_1.1.1f-1ubuntu2_amd64.deb  && dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb && dpkg -i libssl-dev_1.1.1f-1ubuntu2_amd64.deb

RUN python3 -m pip install --break-system-packages --upgrade pip
RUN python3 -m pip install --break-system-packages --upgrade pwntools
RUN python3 -m pip install --break-system-packages z3-solver

RUN DEBIAN_FRONTEND=noninteractive apt-get install -qy libbz2-dev checkinstall 
RUN wget https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tgz && tar xzf Python-2.7.18.tgz && cd Python-2.7.18 && ./configure --enable-optimizations && make -j $(( $(nproc) + 1 )) && checkinstall -D make altinstall &&  ln -s "/usr/local/bin/python2.7" "/usr/bin/python2"

RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output /tmp/get-pip.py && python2 /tmp/get-pip.py && \ 
    python2 -m pip install -U pip && \
    python2 -m pip install pyelftools==0.29 &&  \
    python2 -m pip install pwntools pathlib2

RUN gem install seccomp-tools && \
    gem install one_gadget

RUN cd ~/ && mkdir gdb.plugins && cd gdb.plugins &&  \
    git clone https://github.com/pwndbg/pwndbg.git && \
    cd pwndbg && git submodule update --init --recursive && \
    sed -i "s/^git submodule/#git submodule/" ./setup.sh && \
    DEBIAN_FRONTEND=noninteractive ./setup.sh && ./setup-dev.sh

RUN cd ~/gdb.plugins && git clone https://github.com/jerdna-regeiz/splitmind
RUN cd ~/gdb.plugins && git clone https://github.com/bata24/gef && git clone https://github.com/hugsy/gef-extras.git && ln -s gef gef.bata24.git && cd gef && ./install-minimal.sh && \
    python3 -m pip install --break-system-packages --upgrade lz4 zstandard git+https://github.com/clubby789/python-lzo@b4e39df && \
    python3 -m pip install --break-system-packages --upgrade git+https://github.com/marin-m/vmlinux-to-elf && \   
    python3 -m pip install --break-system-packages crccheck unicorn capstone ropper keystone-engine

RUN cd ~/gdb.plugins && git clone https://github.com/mahaloz/decomp2dbg.git && cd decomp2dbg && python3 -m pip install --break-system-packages . && python3 setup.py install && cp d2d.py /root/.d2d.py

RUN cargo install pwninit

COPY pwninit-template.py /root/gdb.plugins/
COPY .tmux.conf /root/.tmux.conf
COPY .screenrc /root/.screenrc
COPY .bashrc /root/.bashrc
COPY .gef.rc /root/.gef.rc
RUN mkdir -p /root/.config/xfce4/terminal
COPY terminalrc /root/.config/xfce4/terminal/
COPY gdb-gef /usr/bin/
COPY gdb-pwndbg /usr/bin/
COPY .gdbinit /root/.gdbinit

RUN apt install -qy  libc6-arm64-cross libc6-dbg-arm64-cross libstdc++6-11-dbg-arm64-cross libstdc++-11-pic-arm64-cross libc6-armhf-cross libc6-dbg-armhf-cross libstdc++6-11-dbg-armhf-cross libstdc++-11-pic-armhf-cross gcc-aarch64-linux-gnu g++-aarch64-linux-gnu gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf autoconf automake libtool flex bison
RUN mkdir /etc/qemu-binfmt && ln -s /usr/aarch64-linux-gnu /etc/qemu-binfmt/aarch64 && ln -s /usr/arm-linux-gnueabihf /etc/qemu-binfmt/arm

ENV LANG C.UTF-8

VOLUME ["/host"]
WORKDIR /host
CMD ["/bin/bash"]
