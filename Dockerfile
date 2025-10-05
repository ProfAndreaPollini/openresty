# Dockerfile

# Usa un'immagine base con gli strumenti di compilazione
FROM debian:bookworm

# Installa le dipendenze necessarie
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcre2-dev \
    libssl-dev \
    zlib1g-dev \
    wget \
    git \
    unzip \
    libkrb5-dev \
    luarocks \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Aggiungi questa sezione per installare Rust 🦀
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

ENV PCRE2_DIR=/usr

# Definisci le versioni
ARG OPENRESTY_VERSION=1.25.3.1
ARG SPNEGO_MODULE_VERSION=master

# Scarica i sorgenti di OpenResty e del modulo SPNEGO
RUN wget https://openresty.org/download/openresty-${OPENRESTY_VERSION}.tar.gz && \
    tar -xzvf openresty-${OPENRESTY_VERSION}.tar.gz && \
    git clone https://github.com/stnoonan/spnego-http-auth-nginx-module.git && \
    wget https://github.com/chobits/ngx_http_proxy_connect_module/archive/refs/heads/master.zip && \
    unzip master.zip && \
    mv ngx_http_proxy_connect_module-master ./ngx_http_proxy_connect_module

# Installa le librerie Lua necessarie (ldap e http client)
RUN luarocks install lua-resty-ldap \
    && luarocks install lua-resty-http \
    && luarocks install lua-cjson \
    && luarocks install lua-resty-openssl \
    && luarocks install casbin \
    && luarocks install lua-resty-casbin

# Compila OpenResty con il modulo SPNEGO
RUN cd openresty-${OPENRESTY_VERSION} && \
    cd bundle/nginx-1.25.3 && \
    patch -p1 < ../../../../ngx_http_proxy_connect_module/patch/proxy_connect_rewrite_102101.patch && \
    cd ../.. && \
    chmod +x configure && \
    ./configure --with-compat --add-dynamic-module=../spnego-http-auth-nginx-module  --add-module=../ngx_http_proxy_connect_module && \
    make && \
    make install

# Copia i file di configurazione
# COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
# COPY user_groups.lua /usr/local/openresty/nginx/conf/user_groups.lua
# Assicurati di avere il tuo file keytab nella stessa directory del Dockerfile
# COPY http.keytab /etc/nginx/http.keytab

# Esponi la porta del proxy
EXPOSE 3128

# Comando di avvio
CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]