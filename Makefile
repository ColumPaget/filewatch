CC=gcc
OBJ=servant.o common.o users.o event.o files_db.o stats.o backup.o process.o actions.o config_file.o
FLAGS=-g -DUSE_XATTR=1 -D_FILE_OFFSET_BITS=64 $(CFLAGS) -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DHAVE_STDIO_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_STRINGS_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_UNISTD_H=1 -DSTDC_HEADERS=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBSSL=1 -DHAVE_LIBZ=1 -DHAVE_LIBUSEFUL_5=1 -DHAVE_FANOTIFY_H=1
BUNDLED_LIBS=
LIBS=-lUseful-5 -lz -lssl -lcrypto 
prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sysconfdir=${prefix}/etc
DEFAULT_CONFIG_PATH=$(sysconfdir)/filewatch.conf

all: $(OBJ) main.c $(BUNDLED_LIBS)
	$(CC) $(FLAGS) -o filewatch main.c $(OBJ) $(BUNDLED_LIBS) $(LIBS) -DDEFAULT_CONFIG_PATH=\"$(DEFAULT_CONFIG_PATH)\"

files_db.o: files_db.c files_db.h
	$(CC) $(FLAGS) -c files_db.c

users.o: users.c users.h
	$(CC) $(FLAGS) -c users.c

event.o: event.c event.h
	$(CC) $(FLAGS) -c event.c

process.o: process.c process.h
	$(CC) $(FLAGS) -c process.c

stats.o: stats.c stats.h
	$(CC) $(FLAGS) -c stats.c

backup.o: backup.c backup.h
	$(CC) $(FLAGS) -c backup.c

actions.o: actions.c actions.h
	$(CC) $(FLAGS) -c actions.c

servant.o: servant.c servant.h
	$(CC) $(FLAGS) -c servant.c

common.o: common.c common.h
	$(CC) $(FLAGS) -c common.c

config_file.o: config_file.c config_file.h
	$(CC) $(FLAGS) -c config_file.c

libUseful/libUseful.a: 
	$(MAKE) -C libUseful

install:
	mkdir -p $(DESTDIR)$(sysconfdir)
	mkdir -p $(DESTDIR)$(bindir)

clean:
	rm -f *.o */*.o */*.so */*.a *.orig .*.swp

test:
	echo "no tests"
