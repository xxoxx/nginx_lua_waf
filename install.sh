yum install unzip onenssl-devel gcc gcc-c++ libstdc++-devel automake cmake lua lua-devel -y
rm -rf /data/src
rm -rf /usr/local/lj2/
rm -rf /usr/local/nginx/
rm -rf /lib64/libluajit*
mkdir -p /data/src
mkdir -p /etc/nginx/wafconf/
cd /data/src
if [ ! -x "LuaJIT-2.0.2.tar.gz" ]; then  
wget http://luajit.org/download/LuaJIT-2.0.2.tar.gz
fi
tar zxvf LuaJIT-2.0.2.tar.gz
cd LuaJIT-2.0.2
make
make install PREFIX=/usr/local/lj2
ln -s /usr/local/lj2/lib/libluajit-5.1.so.2 /lib64/
cd /data/src
if [ ! -x "ngx_devel_kit-master.zip" ]; then  
wget https://github.com/simpl/ngx_devel_kit/archive/master.zip -O ngx_devel_kit-master.zip
fi
unzip ngx_devel_kit-master.zip 
if [ ! -x "lua-nginx-module-master.zip" ]; then  
wget https://github.com/chaoslawful/lua-nginx-module/archive/master.zip -O lua-nginx-module-master.zip
fi
unzip lua-nginx-module-master.zip
cd /data/src
if [ ! -x "nginx-1.5.7.tar.gz" ]; then
wget 'http://nginx.org/download/nginx-1.5.7.tar.gz'
fi
tar -xzvf nginx-1.5.7.tar.gz
cd nginx-1.5.7/
export LUAJIT_LIB=/usr/local/lj2/lib/
export LUAJIT_INC=/usr/local/lj2/include/luajit-2.0/
ldconfig
./configure --user=nginx --group=nginx --prefix=/usr/local/nginx/ --with-http_stub_status_module --with-http_sub_module --with-http_gzip_static_module --without-mail_pop3_module --without-mail_imap_module --without-mail_smtp_module  --add-module=../ngx_devel_kit-master/ --add-module=../lua-nginx-module-master/
make -j8
make install 
#rm -rf /data/src
cd /data/src
wget https://github.com/loveshell/ngx_lua_waf/archive/master.zip --no-check-certificate
unzip master
mv ngx_lua_waf-master/* /etc/nginx/wafconf/
rm -rf ngx_lua_waf-master
mkdir -p /data/logs/hack
chmod -R 775 /data/logs/hack
