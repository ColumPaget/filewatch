#ifndef FILEWATCH_ACTIONS_H
#define FILEWATCH_ACTIONS_H

#include "common.h"


void ProcessAction(int Act, ListNode *Vars);
void FilePostProcess(const char *Path, ListNode *Vars);

#endif
