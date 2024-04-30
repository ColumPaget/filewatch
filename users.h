#ifndef FILEWATCH_USERS_H
#define FILEWATCH_USERS_H

#include "common.h"

void LoadUserList();
const char *FindUserName(const char *UidStr);
int FindUserID(const char *Name);
int FindGroupID(const char *Name);

#endif

