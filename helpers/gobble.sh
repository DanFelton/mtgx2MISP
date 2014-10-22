#!/bin/sh
for f in files_to_gobble/*.mtgx;
do
    ../mtgx2MISP.py f
done