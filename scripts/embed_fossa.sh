#!/bin/sh
#
# This script embeds fossa directly into the source file.
# The source file must have a placeholder for the fossa code,
# two following lines:

# // fossa start
# // fossa end
#
# Fossa code will be inserted between those two lines.

if ! test -f "$1" ; then
  echo "Usage: $0 <source_file>"
  exit 1
fi

D=`dirname $0`

F1=$D/../fossa.h
F2=$D/../fossa.c

sed '/#include "fossa.h"/d' $F2 > /tmp/$$
F2=/tmp/$$

A='\/\/ fossa start'
B='\/\/ fossa end'

sed -i .$$.bak -e "/$A/,/$B/ { /$A/{ n; r $F1" -e "r $F2" -e "}; /$B/!d; }" "$1"
