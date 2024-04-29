
#ifndef FILEWATCH_COMMON_H
#define FILEWATCH_COMMON_H

#ifdef HAVE_LIBUSEFUL4
#include "libUseful-4/libUseful.h"
#else
  #ifdef HAVE_LIBUSEFUL5
  #include "libUseful-5/libUseful.h"
  #else //ELSE USE BUNDLED
  #include "libUseful/libUseful.h"
  #endif
#endif

#include <fcntl.h>
#include <linux/fanotify.h>

#define VERSION "2.0"

#define MATCH_MODIFY       1
#define MATCH_CLOSE        2
#define MATCH_CLOSE_WRITE  4
#define OPEN_ALLOW 8
#define OPEN_DENY  16
#define EXEC_ALLOW 32
#define EXEC_DENY  64
#define MATCH_EXECUTABLE 512
#define MATCH_NEW 1024
#define MATCH_RENAME 2048
#define SYSLOG_CRIT 4096
#define SYSLOG_WARN 8192

#define FLAG_NEW 1
#define FLAG_MODIFY 2
#define FLAG_CLOSE  4
#define FLAG_RENAME 16
#define FLAG_REMOTE 32
#define FLAG_EXECUTABLE 64
#define FLAG_IGNORE 4096
#define FLAG_PROCESSED 8192


#define GFLAG_SHOW_OPENS 1
#define GFLAG_SHOW_MODS  2
#define GFLAG_DEBUG      4

typedef enum {STARTBRACE, ENDBRACE, RULESET, ACT_CALL, ACT_IGNORE, ACT_SYSLOG_CRIT, ACT_SYSLOG_WARN, ACT_SYSLOG, ACT_LOG, ACT_EXEC, ACT_XATTR, ACT_DIRLOG, ACT_SEND, ACT_MAIL, ACT_ALLOW, ACT_DENY, ACT_ADDLIST, ACT_XACHANGELAST, ACT_XACHANGELOG, ACT_FREEZEPROC, ACT_FREEZEPARENT, ACT_KILLPROC, ACT_KILLPARENT, ACT_FILEBACKUP, ACT_RETURN, ACT_MD5, ACT_SHA1, ACT_SHA256} TAction;


//most of the things in this structure are values to be matched against
typedef struct
{
int Flags;
char *Path;
char *Prog;
char *User;
char *Time;
uint64_t MinAge;
uint64_t MaxAge;
int PidMaxPerSec;
int PidMaxPerMin;
int PidMaxPerHour;
int UserMaxPerSec;
int UserMaxPerMin;
int UserMaxPerHour;
int IPMaxPerSec;
int IPMaxPerMin;
int IPMaxPerHour;
TAction Action;
char *ActionArg;
char *Extra;
} TFileAction;


extern const char *ActionTypes[];

extern ListNode *RuleChains;
extern ListNode *Rules;

//Events that are needed to satisfy config file requirements
extern uint64_t EventMask;
extern time_t Now;

extern int GlobalFlags;

#endif
