#! /bin/sh

if [ $# -lt 1 ]; then
  echo "Usage: $0 <question>"
  exit 1
fi
uname=$(uname)
if [ $uname = 'Linux' ]; then
  osname=$(cat /etc/os-release | grep -w NAME | awk -F '=' '{print $2;}' | awk -F '"' '{if (NF==3) {print $2} else {print $1}}' | awk '{print $1}')
  if [ $osname = 'CentOS' ]; then
    version=$(cat /etc/system-release | awk '{print $4}')
  fi
  if [ -z $version ]; then
    version=$(cat /etc/os-release | grep -w VERSION_ID | awk -F '=' '{print $2;}' | awk -F '"' '{if (NF==3) {print $2} else {print $1}}')
  fi
else
  osname=$uname
  version=$(uname -r)
fi

major_version=$(echo $version | awk -F '.' '{print $1}')
minor_version=$(echo $version | awk -F '.' '{print $2}')
vars="uname=[[$uname]] osname=[[$osname]] major_version=[[$major_version]] minor_version=[[$minor_version]]"

question=$*
host=www.fastken.com
host=39.106.8.170
curl --data "question=[[$question]] vars=[[$vars]]" http://$host/fastken
