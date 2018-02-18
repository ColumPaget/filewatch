#include "process.h"
#include "users.h"
#include <glob.h>

ListNode *Processes=NULL;


void TProcessDestroy(void *p_Proc)
{
TProcess *Proc;

Proc=(TProcess *) p_Proc;
Destroy(Proc->ProgName);
Destroy(Proc->User);
Destroy(Proc->IP);
Destroy(Proc);
}



void ParseTCP(const char *Data, int *Inode, uint32_t *IP)
{
char *Token=NULL, *UID=NULL;
uint32_t SrcPort=0, DestPort=0;
int RetVal=FALSE;
const char *ptr;
char *tptr;

  ptr=Data;
  while (isspace(*ptr)) ptr++;
  ptr=GetToken(ptr,"\\S",&Token,0);

  ptr=GetToken(ptr,"\\S",&Token,0);
  //*IP=strtoul(Token,&tptr,16);
  //if (*tptr==':') tptr++;
  //SrcPort=strtoul(tptr,NULL,16);

  ptr=GetToken(ptr,"\\S",&Token,0);
  *IP=strtoul(Token,&tptr,16);
  if (*tptr==':') tptr++;
  DestPort=strtoul(tptr,NULL,16);

  ptr=GetToken(ptr,"\\S",&Token,0);
  ptr=GetToken(ptr,"\\S",&Token,0);
  ptr=GetToken(ptr,"\\S",&Token,0);
  ptr=GetToken(ptr,"\\S",&Token,0);
  ptr=GetToken(ptr,"\\S",&UID,0);
  ptr=GetToken(ptr,"\\S",&Token,0);
  ptr=GetToken(ptr,"\\S",&Token,0);
  *Inode=strtoul(Token,NULL,10);


Destroy(UID);
Destroy(Token);
}



char *LookupIP(char *RetStr, unsigned long ReqInode)
{
char *Tempstr=NULL;
uint32_t Inode, IP, LocalIP;
STREAM *S;

LocalIP=StrtoIP("127.0.0.1");
S=STREAMFileOpen("/proc/net/tcp",SF_RDONLY);
if (S)
{
  Tempstr=STREAMReadLine(Tempstr, S);
  while (Tempstr)
  {
	ParseTCP(Tempstr, &Inode, &IP);

	if (Inode==ReqInode && (IP > 0) && (IP != LocalIP) )
	{
		RetStr=CopyStr(RetStr, IPtoStr(IP));
	}
  Tempstr=STREAMReadLine(Tempstr, S);
  }
  STREAMClose(S);
}

DestroyString(Tempstr);
return(RetStr);
}




char *ProcessGetIP(char *RetStr, pid_t pid)
{
char *Tempstr=NULL, *Buffer=NULL;
unsigned long Inode=0, Pid=0;
int fd, i, result;
char *ptr, *end;
ListNode *Node;
glob_t Glob;

RetStr=CopyStr(RetStr, "");
Tempstr=FormatStr(Tempstr, "/proc/%d/fd/*", pid);
glob(Tempstr,0,0,&Glob);
for (i=0; i < Glob.gl_pathc; i++)
{
  Buffer=SetStrLen(Buffer, 255);
  readlink(Glob.gl_pathv[i], Buffer, 255);
  if (strncmp(Buffer, "socket:[", 8)==0)
  {
    Inode=strtoul(Buffer+8,NULL,10);
		RetStr=LookupIP(RetStr, Inode);
  }
}
globfree(&Glob);

Destroy(Tempstr);
Destroy(Buffer);

return(RetStr);
}


void ProcessGetOwners(pid_t pid, pid_t *ppid, uid_t *uid, gid_t *gid)
{
char *Tempstr=NULL;
STREAM *S;

	if (ppid) *ppid=0;
	if (uid) *uid=0;
	if (gid) *gid=0;

	Tempstr=FormatStr(Tempstr,"/proc/%d/status",pid);
	S=STREAMOpen(Tempstr, "r");
	if (S)
	{
		Tempstr=STREAMReadLine(Tempstr, S);
		while (Tempstr)
		{
			if (ppid && (strncmp(Tempstr,"PPid:", 5)==0)) *ppid=atoi(Tempstr+5);
			if (uid && (strncmp(Tempstr,"Uid:", 4)==0)) *uid=atoi(Tempstr+4);
			if (gid && (strncmp(Tempstr,"Gid:", 4)==0)) *gid=atoi(Tempstr+4);
			Tempstr=STREAMReadLine(Tempstr, S);
		}

		STREAMClose(S);
	}	
Destroy(Tempstr);
}


TProcess *ProcessGetDetails(pid_t pid)
{
char *Tempstr=NULL;
int len, i;
pid_t ppid;
ListNode *Node;
TProcess *Proc;

	if (! Processes) Processes=MapCreate(101, LIST_FLAG_CACHE);
	Tempstr=FormatStr(Tempstr,"/proc/%d/exe",pid);
	Node=ListFindNamedItem(Processes, Tempstr);
	if (Node) return((TProcess *) Node->Item);

	Proc=(TProcess *) calloc(1,sizeof(TProcess));
	Proc->pid=pid;
	ListAddNamedItem(Processes, Tempstr, Proc);

//printf("PROC ADD: %d\n",ListSize(Processes));
	Proc->ProgName=SetStrLen(Proc->ProgName, PATH_MAX);
	len=readlink(Tempstr, Proc->ProgName, PATH_MAX);
	if (len > -1) Proc->ProgName[len]='\0';
		
	ProcessGetOwners(pid, &Proc->ppid, &Proc->uid, &Proc->gid);
   //this relates to the program opening the file, not the file
  Tempstr=FormatStr(Tempstr, "%d", Proc->uid);
  Proc->User=CopyStr(Proc->User, FindUserName(Tempstr));

	Proc->IP=ProcessGetIP(Proc->IP, pid);
	ppid=Proc->ppid;
	while (! StrValid(Proc->IP) && (ppid > 1) ) 
	{
		Proc->IP=ProcessGetIP(Proc->IP, ppid);
		ProcessGetOwners(ppid, &ppid, NULL, NULL);
	}

	
DestroyString(Tempstr);

return(Proc);
}


int ProcessExists(int pid)
{
char *Tempstr=NULL;
int result;

Tempstr=FormatStr(Tempstr,"/proc/%d",pid);
if (access(Tempstr,F_OK)==0) result=TRUE;
else result=FALSE;

DestroyString(Tempstr);
return(result);
}


void CheckProcessIsLive(int pid)
{
ListNode *Node;
char *Tempstr=NULL;
void *Item;

if (! ProcessExists(pid))
{
	Tempstr=FormatStr(Tempstr,"/proc/%d/exe",pid);
	Node=ListFindNamedItem(Processes, Tempstr);
	Item=ListDeleteNode(Node);
	TProcessDestroy(Item);
}

DestroyString(Tempstr);
}



void ProcessDBHousekeep()
{
ListNode *Curr, *Next;
TProcess *Proc;

Curr=MapGetNthChain(Processes, rand() % MapChainCount(Processes));
Curr=ListGetNext(Curr);
while (Curr)
{
Next=ListGetNext(Curr);
Proc=(TProcess *) Curr->Item;
if (! ProcessExists(Proc->pid))
{
	ListDeleteNode(Curr);
	TProcessDestroy(Proc);
}
Curr=Next;
}


}
