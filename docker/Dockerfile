FROM ubuntu:16.04

MAINTAINER mislav.novakovic@sartura.hr

RUN \
      apt-get update && apt-get install -y \
      # general tools
      git \
      cmake \
      build-essential \
      vim \
      supervisor \
      # libyang
      libpcre3-dev \
      pkg-config \
      # sysrepo
      libavl-dev \
      libev-dev \
      libprotobuf-c-dev \
      protobuf-c-compiler \
      # netopeer2 \
      libssh-dev \
      libssl-dev \
      # bindings
      swig \
      python-dev

# add netconf user
RUN \
      adduser --system netconf && \
      echo "netconf:netconf" | chpasswd

# generate ssh keys for netconf user
RUN \
      mkdir -p /home/netconf/.ssh && \
      ssh-keygen -A && \
      ssh-keygen -t dsa -P '' -f /home/netconf/.ssh/id_dsa && \
      cat /home/netconf/.ssh/id_dsa.pub > /home/netconf/.ssh/authorized_keys

# use /opt/dev as working directory
RUN mkdir /opt/dev
WORKDIR /opt/dev

# libyang
RUN \
      git clone https://github.com/CESNET/libyang.git && \
      cd libyang && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_BUILD_TESTS=OFF .. && \
      make -j2 && \
      make install && \
      ldconfig

# libredblack
RUN \
      git clone https://github.com/sysrepo/libredblack.git && \
      cd libredblack && \
      ./configure --prefix=/usr && \
      make && \
      make install && \
      ldconfig

# sysrepo
RUN \
      git clone https://github.com/sysrepo/sysrepo.git && \
      cd sysrepo && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_TESTS=OFF -DREPOSITORY_LOC:PATH=/etc/sysrepo -DUSE_AVL_LIB:BOOL=FALSE  .. && \
      make -j2 && \
      make install && \
      ldconfig

# libssh
RUN \
      git clone http://git.libssh.org/projects/libssh.git && \
      cd libssh && mkdir build && cd build && \
      cmake .. && \
      make -j2 && \
      make install && \
      ldconfig

# libnetconf2
RUN \
      git clone https://github.com/CESNET/libnetconf2.git && \
      cd libnetconf2 && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_BUILD_TESTS=OFF .. && \
      make -j2 && \
      make install && \
      ldconfig

# keystore
RUN \
      cd /opt/dev && \
      git clone https://github.com/CESNET/Netopeer2.git && \
      cd Netopeer2 && \
      cd keystored && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
      make -j2 && \
      make install && \
      ldconfig

# netopeer2
RUN \
      cd /opt/dev && \
      cd Netopeer2/server && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
      make -j2 && \
      make install && \
      cd ../../cli && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
      make -j2 && \
      make install

RUN \
      apt-get update && apt-get install -y \
      valgrind \
      gdb

RUN \
       apt-get update && apt-get install -y \
       libjson0 \
	   libjson0-dev \
	   lua5.1-dev \
	   lua5.1

# ubox
RUN \
      cd /opt/dev && \
      git clone  git://git.openwrt.org/project/libubox.git && \
      cd libubox && mkdir build && cd build && \
	  git checkout fd57eea9f37e447814afbf934db626288aac23c4 && \
	  cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" .. && \
	  make -j2 && \
	  make install

# uci
RUN \
      cd /opt/dev && \
	  git clone git://nbd.name/uci.git && \
	  cd uci && \
	  cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" -DBUILD_LUA=OFF . && \
	  make -j2 && \
	  make install

# ubus
RUN \
      cd /opt/dev && \
      git clone https://git.openwrt.org/project/ubus.git && \
      cd ubus && \
	  cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF . && \
	  make -j2 && \
	  make install

# rpcd
RUN \
      cd /opt/dev && \
      git clone https://git.openwrt.org/project/rpcd.git && \
      cd rpcd && \
	  cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" -DIWINFO_SUPPORT=NO . && \
	  make -j2 && \
	  make install && \
	  mkdir /usr/lib/rpcd && \
	  cp file.so /usr/lib/rpcd

# sip plugin
RUN \
      cd /opt/dev && \
	  git clone https://github.com/sartura/sip-plugin.git && \
	  cd sip-plugin && mkdir build && cd build && \
	  cmake .. && \
	  make -j2 && \
	  make install && \
	  sysrepoctl -i -g ../yang/terastream-sip@2017-08-09.yang

ENV EDITOR vim
EXPOSE 830

COPY voice_client /etc/config/voice_client

COPY asterisk.sip /usr/libexec/rpcd/asterisk.sip

RUN chmod +x /usr/libexec/rpcd/asterisk.sip

RUN echo '#!/bin/sh' > /etc/init.d/voice_client && chmod +x /etc/init.d/voice_client

RUN echo '#!/bin/sh' > /etc/init.d/asterisk && chmod +x /etc/init.d/asterisk

COPY supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
