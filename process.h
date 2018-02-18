#ifndef FILEWATCH_PROCESS_H
#define FILEWATCH_PROCESS_H

#include "common.h"

typedef struct
{
pid_t pid;
pid_t ppid;
uid_t uid;
gid_t gid;
char *ProgName;
char *User;
char *IP;
} TProcess;

char *ProcessGetIP(char *RetStr, pid_t pid);
TProcess *ProcessGetDetails(pid_t pid);

void CheckProcessIsLive(int pid);
void ProcessDBHousekeep();

#endif
