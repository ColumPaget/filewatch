#ifndef FILEWATCH_EVENT_H
#define FILEWATCH_EVENT_H

#include "common.h"
#include "process.h"
#include "stats.h"

typedef struct
{
time_t When;
time_t MTime;
time_t CTime;
off_t FSize;
pid_t pid;
int fd;
int Flags;
char *Path;
char *StoredPath;
char *TimeStr;
mode_t FMode;
TStats *PidStats;
TStats *UserStats;
TStats *IPStats;
TStats *ProgStats;
TProcess *Process;
} TFileEvent;

void FileEventDestroy(TFileEvent *FE);

#endif
