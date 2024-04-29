
//This module relates to the servant process that handles actions triggered
//by an event. We have to use a servant process to seperate out the part of
//the system that grants permissions from the part that does things, 
//otherwise we can get deadlocked waiting for permissiong from ourselves
#ifndef FILEWATCH_SERVANT_H
#define FILEWATCH_SERVANT_H

#include "common.h"

int ServantProcess(void *Nothing, int Flags);

#endif
