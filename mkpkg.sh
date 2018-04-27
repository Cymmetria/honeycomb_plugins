#!/bin/bash
set -e

rm -rf dist
for type in `ls -d */`; do
    type=${type%%/}
    mkdir -p dist/${type}
    pushd ${type}
    for plugin in `ls -d */`; do
        plugin=${plugin%%/}
        pushd ${plugin}

        zip -9vr ../../dist/${type}/${plugin}.zip *
        echo ${plugin} >> ../../dist/${type}.txt
        popd
    done
    popd
done
