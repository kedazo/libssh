#!/bin/bash
# For changelog entries & signing
export GPGKEY=BDD65CD6
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
dput ppa:kedazo/libssh-master-group-exchange libssh*.changes
