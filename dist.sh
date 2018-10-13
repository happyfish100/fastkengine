#! /bin/sh

if [ $# -ge 1 ]; then
  base_path=$1
  if [ ! -d "$base_path" ]; then
    echo "$base_path not exist"
    exit 2
  fi
else
  base_path=$(pwd)
fi

uname=$(uname)
if [ "$uname" = 'Darwin' ]; then
  html_path=/usr/local/html
else
  html_path=/usr/html
fi

local_ip=$(ifconfig -a | grep -w inet | awk '{print $2;}' | grep -v '127.0.0.1')

cp -R $base_path/src/nginx-module/template /etc/fken/
cp -R $base_path/conf/unix /etc/fken/

cp $base_path/src/nginx-module/template/index.html $html_path/
if [ ! -d $html_path/resource ]; then
  mkdir -p $html_path/resource
fi
cp $base_path/src/shell/fastken.sh $html_path/resource/

perl -pi -e 's/\$\{question\}//g' $html_path/index.html
perl -pi -e 's/\$\{answer\}//g' $html_path/index.html
perl -pi -e 's/\$\{display_answer\}/none/g' $html_path/index.html
perl -pi -e "s/\\\$\{server_ip\}/$local_ip/g" $html_path/index.html
