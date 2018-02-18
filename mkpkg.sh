#!/bin/bash

for service in `ls -d */`; do
	service=${service%%/}
	rm -v ${service}.zip
	cd ${service}
	zip -9vr ../${service}.zip *
	cd ..
done