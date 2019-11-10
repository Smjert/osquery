FROM ubuntu:18.04 as cppcheck
RUN apt update -q -y && apt upgrade -q -y && apt install -q -y --no-install-recommends \
  git \
  make \
  tar \
  gcc \
  g++ \
  libpcre3-dev \
  ca-certificates \
  cmake \
  python \
  python3

WORKDIR /root
RUN git clone https://github.com/danmar/cppcheck.git

WORKDIR /root/cppcheck
RUN git checkout 1.89 && mkdir build

WORKDIR ./build
RUN cmake ../ -DCMAKE_BUILD_TYPE=Release -DHAVE_RULES=ON -DUSE_MATCHCOMPILER=ON
RUN make -j$(nproc)
RUN mkdir ../../cppcheck-1.89-bin && make install DESTDIR=../../cppcheck-1.89-bin

WORKDIR /root
RUN tar -C cppcheck-1.89-bin/usr/local -czf cppcheck-1.89-bin.tar.gz .


FROM ubuntu:18.04
WORKDIR /root
COPY *.deb ./
COPY --from=cppcheck /root/cppcheck-1.89-bin.tar.gz .
RUN apt update -q -y && apt upgrade -q -y && apt install -q -y --no-install-recommends \
  git \
  make \
  ccache \
  python \
  python3 \
  sudo \
  wget \
  ca-certificates \
  tar \
  icu-devtools \
  flex \
  bison \
  xz-utils \
  python-setuptools \
  python-pexpect \
  python-psutil \
  python-pip \
  python-six \
  rpm \
  dpkg-dev \
  file \
  elfutils \
  locales \
&& dpkg -i linux-base_1.0_all.deb linux-firmware_1.0_all.deb linux-generic_1.0_all.deb \
&& apt clean && rm -rf /var/lib/apt/lists/* \
&& sudo pip install timeout_decorator
RUN wget https://github.com/Kitware/CMake/releases/download/v3.14.6/cmake-3.14.6-Linux-x86_64.tar.gz \
&& sudo tar xvf cmake-3.14.6-Linux-x86_64.tar.gz -C /usr/local --strip 1 && rm cmake-3.14.6-Linux-x86_64.tar.gz \
&& wget https://github.com/osquery/osquery-toolchain/releases/download/1.0.0/osquery-toolchain-1.0.0.tar.xz \
&& sudo tar xvf osquery-toolchain-1.0.0.tar.xz -C /usr/local && rm osquery-toolchain-1.0.0.tar.xz \
&& sudo tar xvf cppcheck-1.89-bin.tar.gz -C /usr/local && rm cppcheck-1.89-bin.tar.gz
RUN locale-gen en_US.UTF-8
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'
