#!/bin/bash

rm integrations.txt
for integration in `ls -d */`; do
	integration=${integration%%/}
	rm -v ${integration}.zip
	cd ${integration}
	zip -9vr ../${integration}.zip *
	cd ..
	echo ${integration} >> integrations.txt
done