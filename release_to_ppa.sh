#!/bin/bash
# For changelog entries & signing
export GPGKEY=9BB3D8B0
export DEBEMAIL="kedazo@gmail.com"
export DEBFULLNAME="David Kedves"

RELS="precise trusty vivid wily xenial"
for REL in $RELS; do
    echo "=============== $REL"
    debchange --distribution $REL --team "$REL packaging"
    dpkg-buildpackage -S -k${GPGKEY}
done

# Upload
cd ..
put ppa:kedazo/libssh-master-group-exchange libssh*.changes
