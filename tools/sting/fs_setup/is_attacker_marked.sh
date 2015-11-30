#!/bin/sh

if [ $# -ne 1 ] 
then
	echo "$0 [directory to search under]"
	exit 1
fi

find $1/ -exec sting_marked {} \;
