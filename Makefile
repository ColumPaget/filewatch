CC=gcc
OBJ=servant.o common.o users.o event.o files_db.o stats.o process.o config_file.o
FLAGS=-g -DUSE_XATTR=1 -D_FILE_OFFSET_BITS=64 $(CFLAGS)
BUNDLED_LIBS=libUseful-4/libUseful.a
LIBS=
prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
sysconfdir=${prefix}/etc
DEFAULT_CONFIG_PATH=$(sysconfdir)/filewatch.conf

all: $(OBJ) main.c $(BUNDLED_LIBS)
	$(CC) $(FLAGS) -o filewatch main.c $(OBJ) $(LIBS) $(BUNDLED_LIBS) -DDEFAULT_CONFIG_PATH=\"$(DEFAULT_CONFIG_PATH)\"

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

servant.o: servant.c servant.h
	$(CC) $(FLAGS) -c servant.c

common.o: common.c common.h
	$(CC) $(FLAGS) -c common.c

config_file.o: config_file.c config_file.h
	$(CC) $(FLAGS) -c config_file.c

libUseful-4/libUseful.a: 
	$(MAKE) -C libUseful-4

install:
	mkdir -p $(DESTDIR)$(sysconfdir)
	mkdir -p $(DESTDIR)$(bindir)

clean:
	rm -f *.o */*.o */*.a
