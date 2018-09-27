#! /bin/sh

if [ $# -lt 1 ]; then
  echo "Usage: $0 <question>"
  exit 1
fi

question=$*
curl --data "question=[[$question]] conditions=[[uname=[[$(uname)]]]]" http://www.fastken.com/fastken
