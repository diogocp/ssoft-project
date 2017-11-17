#!/bin/bash

if [ -f test.txt ]
then
	rm test.txt
fi

for i in ../slices/slice*.json
do
	echo $i >> test.txt
	../analyzer.py $i >> test.txt 2>&1
done

diff test.txt result.txt
