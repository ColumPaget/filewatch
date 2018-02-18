#ifndef FILEWATCH_FILESDB_H
#define FILEWATCH_FILESDB_H


#include "common.h"
#include "event.h"

TFileEvent *FilesDBAdd(const char *Path, int Flags, pid_t pid);
TFileEvent *FilesDBGet(const char *Path);
void FilesDBRemove(const char *Path);
void FilesDBHousekeep();

#endif
