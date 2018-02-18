#define _GNU_SOURCE
#include <fcntl.h>
#include <fnmatch.h>
#include <glob.h>
#include "servant.h"
#include "config_file.h"
#include "common.h"
#include "event.h"
#include "users.h"
#include "files_db.h"
#include "stats.h"
#include "process.h"

#define FANOTIFY_BUFFER_SIZE 8192
typedef struct fanotify_event_metadata FANOTIFY_METADATA;

unsigned int FaNotifyClass=0;
time_t LastHousekeep=0;
int FaNotifyFD=-1;

extern ListNode *DB, *Processes;

/*  Permissions feature is not currently used, as it can deadlock the kernel
void SendPermission(int Flags, int fd, int Permission)
{
struct fanotify_response response;

if (Flags & (FAN_OPEN_PERM | FAN_ACCESS_PERM)) 
{
	response.fd=fd;
	response.response=Permission;
	write(FaNotifyFD,(char *) &response,sizeof(response));
	//printf("PERM: %d %d\n",fd,Permission);
}
}
*/

int FaNotifyAddWatch(const char *Path)
{

if (FaNotifyFD==-1) return(FALSE);

//Event Mask MUST be a 64bit number. Previous attempts to use fanotify over the years 
//all failed I didn't realize this!!
if (fanotify_mark(FaNotifyFD, FAN_MARK_ADD | FAN_MARK_MOUNT, EventMask , AT_FDCWD, Path) ==0) return(TRUE);

return(FALSE);
}





int MatchList(const char *Match, const char *Target)
{
char *Token=NULL;
const char *ptr;

	//blank matches
	if (StrEnd(Match)) return(TRUE);
	if (StrEnd(Target)) return(FALSE);

	ptr=GetToken(Match,",",&Token,GETTOKEN_QUOTES);
	while (ptr)
	{
	if (fnmatch(Token, Target, 0)==0) 
	{
		Destroy(Token);
		return(TRUE);
	}
	ptr=GetToken(ptr,",",&Token,GETTOKEN_QUOTES);
	}

Destroy(Token);
return(FALSE);
}


int ProgMatch(const char *Match, const char *Prog)
{
	//this is equivalent to '*'
	if (! StrValid(Match)) return(TRUE);

	if (MatchList(Match, Prog)) return(TRUE);
	if (MatchList(Match, GetBasename(Prog))) return(TRUE);

	return(FALSE);
}

int EventMatches(TFileAction *Act, TFileEvent *Event)
{

	if (Act->Flags & MATCH_EXECUTABLE)
	{
		if (! (Event->FMode & ( S_IXUSR |  S_IXGRP |  S_IXOTH)) ) return(FALSE);
	}

	if (Act->Flags & MATCH_MODIFY)
	{
		if (! (Event->Flags & FAN_MODIFY)) return(FALSE);
	}

	if (Act->Flags & MATCH_CLOSE)
	{
		if (! (Event->Flags & FAN_CLOSE)) return(FALSE);
	}


	if ( (Act->Flags & MATCH_NEW) && (! (Event->Flags & FLAG_NEW)) ) return(FALSE);
	if ( (Act->Flags & MATCH_RENAME) && (! (Event->Flags & FLAG_RENAME)) ) return(FALSE);

	if (! MatchList(Act->Path, Event->Path)) return(FALSE);
	if (! MatchList(Act->Time, Event->TimeStr)) return(FALSE);

	if (Event->Process)
	{
	if (! ProgMatch(Act->Prog, Event->Process->ProgName)) return(FALSE);
	if (! MatchList(Act->User, Event->Process->User)) return(FALSE);
	}

	if ( (Act->MinAge > 0) && (Event->MTime > (Now + Act->MinAge)) ) return(FALSE);
	if ( (Act->MaxAge > 0) && (Event->MTime < (Now + Act->MaxAge)) ) return(FALSE);
if (Act->MinAge) printf("AGE: %s %ld %ld %ld\n",Event->Path, (long) Event->MTime, (long) Act->MinAge, (long) Now);

	if ((Act->PidMaxPerSec  > 0) && ((! Event->PidStats) || (Event->PidStats->per_sec  < Act->PidMaxPerSec))) return(FALSE);
	if ((Act->PidMaxPerMin  > 0) && ((! Event->PidStats) || (Event->PidStats->per_min  < Act->PidMaxPerMin))) return(FALSE);
	if ((Act->PidMaxPerHour > 0) && ((! Event->PidStats) || (Event->PidStats->per_hour < Act->PidMaxPerHour))) return(FALSE);

	if ((Act->UserMaxPerSec  > 0) && ((! Event->UserStats) || (Event->UserStats->per_sec  < Act->UserMaxPerSec))) return(FALSE);
	if ((Act->UserMaxPerMin  > 0) && ((! Event->UserStats) || (Event->UserStats->per_min  < Act->UserMaxPerMin))) return(FALSE);
	if ((Act->UserMaxPerHour > 0) && ((! Event->UserStats) || (Event->UserStats->per_hour < Act->UserMaxPerHour))) return(FALSE);

	if ((Act->IPMaxPerSec  > 0) && ((! Event->IPStats) || (Event->IPStats->per_sec  < Act->IPMaxPerSec))) return(FALSE);
	if ((Act->IPMaxPerMin  > 0) && ((! Event->IPStats) || (Event->IPStats->per_min  < Act->IPMaxPerMin))) return(FALSE);
	if ((Act->IPMaxPerHour > 0) && ((! Event->IPStats) || (Event->IPStats->per_hour < Act->IPMaxPerHour))) return(FALSE);


	return(TRUE);
}







char *FormatSendArgs(char *RetStr, TFileAction *Act, const char *Access, TFileEvent *FE)
{
char *p_ActName="", *p_ActArg="";

if (Act)
{
p_ActName=(char *) ArrayGetItem(ActionTypes, Act->Action);
p_ActArg=Act->ActionArg;
}

if (FE->Process) RetStr=FormatStr(RetStr, "%s '%s' access=%s path=%s user=%s program=%s pid=%ld ppid=%ld ip=%s",p_ActName, p_ActArg, Access, FE->Path, FE->Process->User, FE->Process->ProgName, FE->pid, FE->Process->ppid, FE->Process->IP);
else RetStr=FormatStr(RetStr, "%s '%s' access=%s path=%s pid=%ld", p_ActName, p_ActArg, Access, FE->Path, FE->pid);

if (FE->Flags & FLAG_NEW) RetStr=CatStr(RetStr, " new=y");
if (FE->Flags & FLAG_REMOTE) RetStr=CatStr(RetStr, " remote=y");
if (FE->Flags & FLAG_EXECUTABLE) RetStr=CatStr(RetStr, " executable=y");
if (FE->Flags & FLAG_RENAME) RetStr=MCatStr(RetStr, " rename='", FE->StoredPath,"'", NULL);
if (Act && StrValid(Act->Extra)) RetStr=MCatStr(RetStr, " extra='", Act->Extra,"'", NULL);

RetStr=CatStr(RetStr, "\n");


return(RetStr);
}


int IsRepeatEvent(TFileEvent *FE, pid_t pid, int Flags, time_t Now)
{
if (! FE) return(FALSE);
if (! (FE->Flags & FLAG_PROCESSED)) return(FALSE);
if (pid != FE->pid) return(FALSE);
if ((Now - FE->When) > 10) return(FALSE);
if ( (Flags & FAN_MODIFY) && (! (FE->Flags & FLAG_MODIFY)) ) return(FALSE);

return(TRUE);
}



void ProcessEventRules(STREAM *ServantS, ListNode *Rules, const char *Type, TFileEvent *FE)
{
ListNode *Curr, *Node;
TFileAction *Act;
char *Msg=NULL;

		Curr=ListGetNext(Rules);
		while (Curr)
		{
			Act=(TFileAction *) Curr->Item;

			if (EventMatches(Act, FE))
			{
					switch (Act->Action)
					{
					case ACT_CALL:
						Node=ListFindNamedItem(RuleChains, Act->ActionArg);
						if (Node) ProcessEventRules(ServantS, (ListNode *) Node->Item, Type, FE);
					break;

					case ACT_RETURN:
						Curr=NULL;
					break;

					case ACT_IGNORE: 
						FE->Flags |= FLAG_IGNORE;
						Curr=NULL; 
					break;

					case ACT_ALLOW:
						//AllowDeny=FAN_ALLOW;
//						printf("ALLOW %d\n",FE->fd);
					break;

					case ACT_DENY:
						//AllowDeny=FAN_DENY;
//						printf("DENY %d\n",FE->fd);
					break;


					default:
						Msg=FormatSendArgs(Msg, Act, Type, FE);
						STREAMWriteLine(Msg, ServantS);
					break;
					}
			}

		Curr=ListGetNext(Curr);
		}

Destroy(Msg);
}


void ProcessEvent(STREAM *ServantS, int Flags, int fd, pid_t pid)
{
int AllowDeny=FAN_ALLOW;
char *Tempstr=NULL, *Token=NULL, *Item=NULL;
const char *ptr, *p_Type="open";
STREAM *S;
int len;
FANOTIFY_METADATA fa_data;
TFileEvent *FE=NULL;
float val;

Now=GetTime(0);
Tempstr=FormatStr(Tempstr,"/proc/self/fd/%d",fd);
Item=SetStrLen(Item, PATH_MAX);
len=readlink(Tempstr, Item, PATH_MAX);
if (len > -1)
{
	Item[len]='\0';
	FE=FilesDBGet(Item);
	if (! FE) 
	{
		FE=FilesDBAdd(Item, Flags, pid);
	}
	if (FE->Flags & FLAG_IGNORE) FE=NULL;
}

if (FE && (! IsRepeatEvent(FE, pid, Flags, Now)))
{
	FE->When=Now;
	FE->TimeStr=CopyStr(FE->TimeStr, GetDateStrFromSecs("%H:%M:%S", Now, NULL));
	FE->Flags |= FLAG_PROCESSED;

	FE->Process=ProcessGetDetails(FE->pid);
  if (FE->Process && StrValid(FE->Process->IP)) FE->Flags |= FLAG_REMOTE;

	
	if (Flags & FAN_MODIFY)
	{
	p_Type="modify";

	//only count modifications to a file that are new. When a file is modified there is often a
	//storm of mods but these are individual writes during one file modification
	if (! FE->Flags & FLAG_MODIFY)
	{
	Tempstr=FormatStr(Tempstr,"modify-pid:%ld",FE->pid);
	FE->PidStats=StatsIncr(Tempstr);

	if (FE->Process) 
	{
		Tempstr=MCopyStr(Tempstr,"modify-user:",FE->Process->User, NULL);
		FE->UserStats=StatsIncr(Tempstr);

		Tempstr=MCopyStr(Tempstr,"modify-program:",FE->Process->ProgName, NULL);
		FE->ProgStats=StatsIncr(Tempstr);

		if (FE->Flags & FLAG_REMOTE)
		{
		Tempstr=MCopyStr(Tempstr,"modify-ip:",FE->Process->IP, NULL);
		FE->IPStats=StatsIncr(Tempstr);
		}
	}
	}

	FE->Flags |= FLAG_MODIFY;
	/*
	if (FE->Flags & FLAG_NEW)
	{
	Tempstr=MCopyStr(Tempstr, "user-new:",FE->User, NULL);
	val=StatsIncr(Tempstr,1);
	Tempstr=FormatStr(Tempstr, "pid-new:%d",FE->pid, NULL);
	val=StatsIncr(Tempstr,1);
	}
	*/
	}  
	//must do this here, as 'modify' and 'close' can both be set!
	else if (Flags & FAN_CLOSE) p_Type="close";

	ProcessEventRules(ServantS, Rules, p_Type, FE);

	if (isatty(1))
	{
		Tempstr=FormatSendArgs(Tempstr, NULL, p_Type, FE);
		if (
				((FE->Flags & FAN_MODIFY) && (GlobalFlags & GFLAG_SHOW_MODS)) ||
				(GlobalFlags & GFLAG_SHOW_OPENS) 
			) printf("%s",Tempstr);
	}
//  Permissions feature is not currently used, as it can deadlock the kernel
//		SendPermission(FE->Flags, fd, AllowDeny);


if (Flags & FAN_CLOSE) 
{
	FilesDBRemove(FE->Path);
}

}


if ((Now - LastHousekeep) > 10) 
{
	FilesDBHousekeep();
	ProcessDBHousekeep();
	LastHousekeep=Now;
}


Destroy(Tempstr);
Destroy(Token);
Destroy(Item);
}



void Process()
{
FANOTIFY_METADATA *metadata, *metaptr;
char *Tempstr=NULL, *Path=NULL, *ptr;
struct stat Stat;
int len, lastfd=-1, BuffLen, result;
pid_t self, servant;
STREAM *ServantS;


//We must spawn off a helper process and have it handle some of the work, otherwise we
//get deadlocked. We'll try to open a file, and the kernel will ask us to confirm permission
//for ourselves to open the file. But we can't because we're waiting for the file to open.
//This doesn't just deadlock our process, but the kernel too, rendering the system unusable.
ServantS=STREAMSpawnFunction(ServantProcess, NULL, "");
self=getpid();
ptr=STREAMGetValue(ServantS, "PeerPID");
if (ptr) servant=atoi(ptr);

Path=SetStrLen(Path,PATH_MAX);
BuffLen=sizeof(FANOTIFY_METADATA) * 10;
metadata=(FANOTIFY_METADATA *) calloc(1, BuffLen);
while (1)
{
 result=FDSelect(FaNotifyFD, SELECT_READ, NULL);
 if (result > 0)
 {
		len=read(FaNotifyFD, metadata, BuffLen);
		metaptr=metadata;
		while (FAN_EVENT_OK(metaptr, len))
    {
			//there may be multiple instances of the same fd in the metadata
			//if we've dealt with it we don't want to do so again
			//the fd number won't be reused because we've taken the metadata
			//all in one go
      if (fcntl(metaptr->fd, F_GETFD) > -1) 
			{
				/* Permissions feature is not currently used, ans it can deadlock the kernel
				if ((metaptr->pid == self) || (metaptr->pid == servant)) SendPermission(metaptr->mask, metaptr->fd, FAN_ALLOW);
				else 
				*/

				ProcessEvent(ServantS, metaptr->mask, metaptr->fd, metaptr->pid);
				lastfd=metaptr->fd;
			}
			close(metaptr->fd);
     metaptr = FAN_EVENT_NEXT (metaptr, len);
    }
 }
}

Destroy(Tempstr);
Destroy(Path);
}




void ParseCommandLine(int argc, char *argv[], char **ConfigPath, char **WatchPath)
{
int i;

for (i=1; i < argc; i++)
{
	if (strcmp(argv[i],"-c")==0) *ConfigPath=CopyStr(*ConfigPath,argv[++i]);
	else if (strcmp(argv[i],"-d")==0) demonize();
	else if (strcmp(argv[i],"-show")==0) GlobalFlags |= GFLAG_SHOW_OPENS | GFLAG_SHOW_MODS;
	else if (strcmp(argv[i],"-show-write")==0) 
	{
		GlobalFlags |= GFLAG_SHOW_MODS;
		EventMask |= FAN_MODIFY;
	}
	else if (strcmp(argv[i],"-mx")==0)
	{
		LibUsefulSetValue("SMTP:Server", argv[i+1]);
		i++;
	}
	else *WatchPath=MCatStr(*WatchPath, argv[++i], ":",NULL);
}

}



int main(int argc, char *argv[])
{
char *WatchPath=NULL, *ConfigPath=NULL, *Token=NULL;
const char *ptr;


if (getuid() !=0)
{
printf("ERROR: filewatch must be run as root, unfortunately, because it needs access to information on all processes and files\n");
exit(1);
}

ConfigPath=CopyStr(ConfigPath, "/etc/filewatch.conf");

ParseCommandLine(argc, argv, &ConfigPath, &WatchPath);
LoadConfig(ConfigPath);

if (! StrValid(WatchPath)) WatchPath=CopyStr(WatchPath, "/");
LoadUserList();
if (EventMask & FAN_OPEN_PERM) 
{
	FaNotifyClass=FAN_CLASS_CONTENT;
	//the permissions feature is too risky for use. It can dealock the kernel
	//EventMask |= FAN_OPEN_PERM;
}

FaNotifyFD=fanotify_init(FAN_CLOEXEC | FaNotifyClass, O_RDONLY | O_CLOEXEC | O_LARGEFILE);

ptr=GetToken(WatchPath,":",&Token,0);
while (ptr)
{
FaNotifyAddWatch(Token);
ptr=GetToken(ptr,":",&Token,0);
}

Process();

DestroyString(WatchPath);
DestroyString(ConfigPath);
DestroyString(Token);
}
