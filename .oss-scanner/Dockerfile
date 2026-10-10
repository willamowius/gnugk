FROM ubuntu:24.04 AS buildstage

LABEL maintainer="jan@willamowius.de"

EXPOSE 1719/udp 1720 3000-3001/udp 7000 20000-20100 30000-30500/udp

RUN apt-get update && apt-get install -y \
	automake \
	bison \
	build-essential \
	firebird-dev \
	flex \
	git \
	libcurl4-gnutls-dev \
	libgeoip-dev \
	libhiredis-dev \
	libldap2-dev \
	liblua5.3-dev \
	libmosquitto-dev \
	libmysqlclient-dev \
	libpq-dev \
	librabbitmq-dev \
	libsqlite3-dev \
	libssh-dev \
	libssl-dev \
	nlohmann-json3-dev \
	pkg-config \
	unixodbc-dev

RUN ln -s /usr/lib/x86_64-linux-gnu/liblua5.3.a /usr/lib/x86_64-linux-gnu/liblua.a

RUN cd ~ && \
	git clone https://github.com/willamowius/ptlib.git && \
	cd ptlib && \
	./configure --enable-ipv6 --disable-odbc --disable-sdl --disable-lua --disable-expat && \
	make optnoshared

RUN cd ~ && \
	git clone https://github.com/willamowius/h323plus.git && \
	cd h323plus && \
	./configure --enable-h235 --enable-h46017 --enable-h46026 --enable-h46019m && \
	make optnoshared

RUN cd ~ && \
	git clone https://github.com/willamowius/gnugk.git && \
	cd gnugk && \
	./configure --enable-h46018 --disable-netsnmp --with-lua-include-dir=/usr/include/lua5.3/ --enable-large-fdset && \
	make optnoshared

RUN cd ~ && \
	git clone https://github.com/willamowius/check_h323.git && \
	cd check_h323 && \
	make optnoshared

FROM ubuntu:24.04 AS workingstage

RUN apt-get update && apt-get install -y \
	firebird3.0-common \
	libcurl4t64 \
	libgeoip1t64 \
	libldap2 \
	liblua5.3-0 \
	libmysqlclient21 \
	librabbitmq4 \
	libsqlite3-0 \
	libssh-4

RUN ln -s /usr/lib/x86_64-linux-gnu/liblua5.3.a /usr/lib/x86_64-linux-gnu/liblua.a

COPY --from=buildstage /root/gnugk/obj_linux_x86_64_s/gnugk /usr/local/bin/
COPY --from=buildstage /root/check_h323/obj_linux_x86_64_s/check_h323 /usr/local/bin/

COPY gnugk.ini /etc/gnugk.ini

ENTRYPOINT ["/usr/local/bin/gnugk"]

HEALTHCHECK CMD /usr/local/bin/check_h323 127.0.0.1

