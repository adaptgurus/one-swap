#!/bin/bash

# -------------------------------------------------------------------------- #
# Copyright 2002-2025, OpenNebula Project, OpenNebula Systems                #
# Licensed under the Apache License, Version 2.0.                             #
# -------------------------------------------------------------------------- #

ARGS=$*

usage() {
 echo
 echo "Usage: install.sh [-d ONE_LOCATION] [-h] [-l] [-m]"
 echo
 echo "-d: OpenNebula's CLI folder. Must be an absolute path."
 echo "-l: create only symlinks"
 echo "-m: generate and install man page for oneswap"
 echo "-h: prints this help"
}

PARAMETERS="hlmu:g:d:"

if [ $(getopt --version | tr -d " ") = "--" ]; then
    TEMP_OPT=`getopt $PARAMETERS "$@"`
else
    TEMP_OPT=`getopt -o $PARAMETERS -n 'install.sh' -- "$@"`
fi

if [ $? != 0 ] ; then
    usage
    exit 1
fi

eval set -- "$TEMP_OPT"

LINK="no"
MANPAGE="no"
SRC_DIR=$PWD

while true ; do
    case "$1" in
        -h) usage; exit 0;;
        -l) LINK='yes'; shift ;;
        -m) MANPAGE='yes'; shift ;;
        -d) ROOT="$2" ; shift 2 ;;
        --) shift ; break ;;
        *)  usage; exit 1 ;;
    esac
done

if [ -z "$ROOT" ] ; then
    LIB_LOCATION="/usr/lib/one"
    SHARE_LOCATION="/usr/share/one"
    BIN_LOCATION="/usr/bin"
    VAR_LOCATION="/var/lib/one"
    ETC_LOCATION="/etc/one"
    SCRIPTS_LOCATION="$LIB_LOCATION/oneswap/scripts"
else
    LIB_LOCATION="$ROOT/lib"
    SHARE_LOCATION="$ROOT/share"
    BIN_LOCATION="$ROOT/bin"
    VAR_LOCATION="$ROOT/var"
    ETC_LOCATION="$ROOT/etc/one"
    SCRIPTS_LOCATION="$LIB_LOCATION/oneswap/scripts"
fi

LIB_DIRS="$LIB_LOCATION/ruby/cli/one_helper"
MAN_LOCATION="/usr/share/man/man1"
MAKE_DIRS="$BIN_LOCATION $SHARE_LOCATION $LIB_LOCATION $ETC_LOCATION
           $VAR_LOCATION $LIB_DIRS $SCRIPTS_LOCATION"

INSTALL_FILES=(
    BIN_FILES:$BIN_LOCATION
    ONE_CLI_LIB_FILES:$LIB_LOCATION/ruby/cli/one_helper
    CONF_FILES:$ETC_LOCATION
    SCRIPTS_FILES:$SCRIPTS_LOCATION
)

BIN_FILES="oneswap oneswap-hyperv sesparse"
ONE_CLI_LIB_FILES="esxi_client.rb \
                   esxi_vm.rb \
                   hyperv_helper.rb \
                   hyperv_hot_helper.rb \
                   hyperv_hot_hardening.rb \
                   hyperv_hot_edge_hardening.rb \
                   hyperv_state_hardening.rb \
                   hyperv_source_security_hardening.rb \
                   hyperv_virtio_hardening.rb \
                   netapp_shift_helper.rb \
                   oneswap_helper.rb \
                   oneswap_logger.rb \
                   vsphere_client.rb \
                   windows_tuner.rb"
CONF_FILES="oneswap.yaml"
SCRIPTS_FILES="scripts/*"

if [ "$MANPAGE" = "yes" ]; then
    echo "# oneswap(1) -- OpenNebula OneSwap Tool" > oneswap.1.ronn
    echo >> oneswap.1.ronn
    $BIN_LOCATION/oneswap --help >> oneswap.1.ronn
    ronn --style toc --manual="oneswap(1) -- OpenNebula OneSwap Tool" oneswap.1.ronn
    gzip -c oneswap.1 > oneswap.1.gz
    cp oneswap.1.gz $MAN_LOCATION
    rm -f oneswap.1.ronn oneswap.1.gz
    exit 0
fi

for d in $MAKE_DIRS; do
    mkdir -p $DESTDIR$d
done

INSTALL_SET="${INSTALL_FILES[@]}"

do_file() {
    if [ "$LINK" = "yes" ]; then
        ln -s $SRC_DIR/$1 $DESTDIR$2
    else
        cp -RL $SRC_DIR/$1 $DESTDIR$2
    fi
}

for i in ${INSTALL_SET[@]}; do
    SRC=$`echo $i | cut -d: -f1`
    DST=`echo $i | cut -d: -f2`
    eval SRC_FILES=$SRC
    for f in $SRC_FILES; do
        do_file $f $DST
    done
done

chmod +x "$DESTDIR$BIN_LOCATION/oneswap" "$DESTDIR$BIN_LOCATION/oneswap-hyperv" "$DESTDIR$BIN_LOCATION/sesparse"
