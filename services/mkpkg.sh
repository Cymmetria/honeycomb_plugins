#!/bin/bash

rm services.txt
for service in `ls -d */`; do
	service=${service%%/}
	rm -v ${service}.zip
	cd ${service}
	zip -9vr ../${service}.zip *
	cd ..
	echo ${service} >> services.txt
done