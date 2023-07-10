fullapp: master.out slave.out installer 

installer: installer/OMN_import_for_slave.out installer/OMN_gen_and_export_keypairs.out


master.out: ./master/master.cpp ./master/OMN_masters.cpp ./master/OMN_masters.h stack.o OMN_common.o OMN_db.o
	g++ ./master/master.cpp ./master/OMN_masters.cpp  -I./ -I../src-norm-1.5.9/include/ -I../src-norm-1.5.9/protolib/include/ ../src-norm-1.5.9/lib/libnorm.a ../src-norm-1.5.9/protolib/lib/libprotokit.a -lpthread OMN_db.o stack.o OMN_common.o -o master.out `gpgme-config --cflags --libs` `libgcrypt-config --libs` `ncurses5-config --libs`

slave.out: ./slave/slave.cpp ./slave/OMN_slaves.cpp ./slave/OMN_slaves.h stack.o OMN_common.o OMN_db.o
	g++ ./slave/slave.cpp ./slave/OMN_slaves.cpp  -I./ -I../src-norm-1.5.9/include/ -I../src-norm-1.5.9/protolib/include/ ../src-norm-1.5.9/lib/libnorm.a ../src-norm-1.5.9/protolib/lib/libprotokit.a -lpthread stack.o OMN_common.o OMN_db.o -o slave.out `gpgme-config --cflags --libs` `libgcrypt-config --libs`

OMN_common.o: OMN_common.h OMN_common.cpp ../src-norm-1.5.9/lib/libnorm.a ../src-norm-1.5.9/protolib/lib/libprotokit.a
	g++ -c OMN_common.cpp `gpgme-config --cflags` -I../src-norm-1.5.9/include/ -I../src-norm-1.5.9/protolib/include/ -lpthread -o OMN_common.o `gpgme-config --cflags --libs` `libgcrypt-config --libs`

stack.o: stack.h stack.cpp ../src-norm-1.5.9/lib/libnorm.a ../src-norm-1.5.9/protolib/lib/libprotokit.a
	g++ -c stack.cpp -I../src-norm-1.5.9/include/ -I../src-norm-1.5.9/protolib/include/ -lpthread -o stack.o

OMN_db.o: OMN_db.cpp OMN_db.h OMN_common.h
	g++ -c OMN_db.cpp -I../src-norm-1.5.9/include/ -I../src-norm-1.5.9/protolib/include/ -lpthread -o OMN_db.o

installer/OMN_gen_and_export_keypairs.out:  installer/OMN_create_keys_and_config.cpp OMN_common.o ../src-norm-1.5.9/lib/libnorm.a ../src-norm-1.5.9/protolib/lib/libprotokit.a
	g++ installer/OMN_create_keys_and_config.cpp OMN_common.o -Iinstaller/ -I./ `gpgme-config --cflags` -I../src-norm-1.5.9/include/ -I../src-norm-1.5.9/protolib/include/ ../src-norm-1.5.9/lib/libnorm.a ../src-norm-1.5.9/protolib/lib/libprotokit.a -lpthread `gpgme-config --cflags --libs` `libgcrypt-config --libs` -o installer/OMN_gen_and_export_keypairs.out 

installer/OMN_import_for_slave.out: installer/OMN_SLAVE_import_keys.cpp OMN_common.o ../src-norm-1.5.9/lib/libnorm.a ../src-norm-1.5.9/protolib/lib/libprotokit.a
	g++ installer/OMN_SLAVE_import_keys.cpp OMN_common.o -Iinstaller/ -I./ `gpgme-config --cflags` -I../src-norm-1.5.9/include/ -I../src-norm-1.5.9/protolib/include/ ../src-norm-1.5.9/lib/libnorm.a ../src-norm-1.5.9/protolib/lib/libprotokit.a -lpthread `gpgme-config --cflags --libs` `libgcrypt-config --libs` -o installer/OMN_import_for_slave.out 


clean:
	rm slave.out
	rm master.out
	rm stack.o
	rm OMN_db.o
	rm OMN_common.o
	rm installer/OMN_import_for_slave.out
	rm installer/OMN_gen_and_export_keypairs.out
