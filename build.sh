#!/bin/bash
#we installed every library we need. Proceeding to build OMN...
echo "Building OMN..."
cd src-norm-1.5.9/makefiles/ 
#make -f Makefile.linux clean
make -f Makefile.linux

cd ..
cd ..

cd omn
#make clean
make

