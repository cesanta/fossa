#!/bin/sh
#
# This script embeds net_skeleton directly into the source file.
# The source file must have a placeholder for the net_skeleton code,
# two following lines:

# // net_skeleton start
# // net_skeleton end
#
# Net skeleton code will be inserted between those two lines.

if ! test -f "$1" ; then
  echo "Usage: $0 <source_file>"
  exit 1
fi

D=`dirname $0`
TMP=/tmp/.$$.tmp

(
sed -n "1,/\/\/ net_skeleton start/p" "$1"
echo
cat $D/../net_skeleton.h
sed '/#include "net_skeleton.h"/d' $D/../net_skeleton.c
echo
sed -n "/\/\/ net_skeleton end/,\$p" "$1"
) > $TMP

mv "$1" "$1".$$.bak
mv $TMP "$1"
