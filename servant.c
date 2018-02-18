//This module relates to the servant process that handles actions triggered
//by an event. We have to use a servant process to seperate out the part of
//the system that grants permissions from the part that does things, 
//otherwise we can get deadlocked waiting for permissiong from ourselves

#include "servant.h"

//so we can close it
extern int FaNotifyFD;



void ServantListAdd(const char *Config)
{
char *List=NULL, *Item=NULL, *Tempstr=NULL;
const char *ptr;
STREAM *S;

	//get directory name to log into	
	ptr=GetToken(Config, " ", &List, GETTOKEN_QUOTES);
	ptr=GetToken(ptr, " ", &Item, GETTOKEN_QUOTES);
	S=STREAMOpen(List, "rw");
	if (S)
	{
			Tempstr=STREAMReadLine(Tempstr, S);
			while (Tempstr)
			{
			StripTrailingWhitespace(Tempstr);
			if (strcmp(Tempstr, Item)==0) break;
			Tempstr=STREAMReadLine(Tempstr, S);
			}

			if (! Tempstr)
			{
			Item=CatStr(Item,"\n");
			STREAMWriteLine(Item, S);
			}

			STREAMClose(S);
	}

Destroy(Tempstr);
Destroy(Item);
Destroy(List);
}

void ServantDirectoryLog(const char *Config)
{
char *Token=NULL, *Tempstr=NULL, *wptr;
STREAM *S;

	//get directory name to log into	
	GetToken(Config, " ", &Token, GETTOKEN_QUOTES);
	wptr=strrchr(Token,'/');
	if (wptr)
	{
		wptr++;
		*wptr='\0';
		Token=CatStr(Token,".filewatch.log");
		S=STREAMOpen(Token, "a");
		if (S)
		{
			Tempstr=MCopyStr(Tempstr, GetDateStr("%Y/%m/%d %H:%M:%S",NULL), " ", Config, "\n", NULL);
			STREAMWriteLine(Tempstr, S);
			STREAMClose(S);
		}
	}

Destroy(Tempstr);
Destroy(Token);
}

void SignalProcess(const char *PidStr, int Sig)
{
pid_t pid;

pid=(pid_t) strtoul(PidStr,NULL, 10);

//do not signal/kill pid 1 (init) nor ourselves, nor our parent
if ( (pid > 1) && (pid != getpid()) && (pid != getppid()) ) kill(pid, Sig);
}

int ServantParseMsg(const char *Msg, ListNode *Vars)
{
char *Name=NULL, *Value=NULL;
const char *ptr;
int Action=0;

ListClear(Vars, Destroy);
Value=MCatStr(Value, "filewatch@", OSSysInfoString(OSINFO_HOSTNAME), NULL);
SetVar(Vars, "sender", Value);
Value=MCatStr(Value, "filewatch event at ", OSSysInfoString(OSINFO_HOSTNAME), NULL);
SetVar(Vars, "subject", Value);
SetVar(Vars, "when", GetDateStr("%Y/%m/%d %H:%M:%S",NULL));

ptr=GetToken(Msg, "\\S", &Value, 0);
Action=MatchTokenFromList(Value, ActionTypes, 0);
ptr=GetToken(ptr, "\\S", &Value, GETTOKEN_QUOTES);
SetVar(Vars, "ActionArg", Value);
ptr=GetNameValuePair(ptr, " ", "=", &Name, &Value);
while (ptr)
{
SetVar(Vars, Name, Value);
ptr=GetNameValuePair(ptr, " ", "=", &Name, &Value);
}

ptr=GetVar(Vars,"program");
if (StrValid(ptr))
{
  SetVar(Vars, "prog", ptr);
  SetVar(Vars, "progname", GetBasename(ptr));
}

ptr=GetVar(Vars,"ip");
if (! StrValid(ptr)) SetVar(Vars, "ip", "local");

ptr=GetVar(Vars,"path");
if (StrValid(ptr)) SetVar(Vars, "name", GetBasename(ptr));


DestroyString(Name);
DestroyString(Value);

return(Action);
}


void ServantProcess(void *Nothing)
{
char *Tempstr=NULL, *Line=NULL, *Token=NULL, *Value=NULL;
int val, Act;
size_t filesize;
const char *ptr;
STREAM *S, *Input;
ListNode *Vars=NULL;

close(FaNotifyFD);
close(1);
dup(open("/dev/null",O_WRONLY));

Vars=ListCreate();
Input=STREAMFromDualFD(0,1);

Line=STREAMReadLine(Line, Input);
while (Line)
{
StripTrailingWhitespace(Line);
if (StrValid(Line))
{
Act=ServantParseMsg(Line,  Vars);
filesize=strtoul(GetVar(Vars, "filesize"),NULL,10);

switch (Act)
{
			case ACT_SYSLOG: 
			case ACT_SYSLOG_CRIT: 
			case ACT_SYSLOG_WARN: 
				if (Act==ACT_SYSLOG) val=LOG_INFO;
				else if (Act==ACT_SYSLOG_WARN) val=LOG_WARNING;
				else if (Act==ACT_SYSLOG_CRIT) val=LOG_CRIT;
				Token=CopyStr(Token, GetVar(Vars, "ActionArg"));
				Tempstr=SubstituteVarsInString(Tempstr, Token,  Vars, 0);
				syslog(val, Tempstr);
			break;

			case ACT_LOG:
				Token=CopyStr(Token,GetVar(Vars,"extra"));
				if (! StrValid(Token)) Token=CopyStr(Token, "/var/log/filewatch.log");
				S=STREAMOpen(Token, "a");
				if (S)
				{
				Tempstr=MCopyStr(Tempstr, GetDateStr("%Y/%m/%d %H:%M:%S",NULL), " ", NULL);
				STREAMWriteLine(Tempstr, S);
				Token=CopyStr(Token, GetVar(Vars, "ActionArg"));
				Tempstr=SubstituteVarsInString(Tempstr, Token,  Vars, 0);
				STREAMWriteString(Tempstr, S);
				STREAMWriteLine("\n", S);
				STREAMClose(S);
				}
			break;


			case ACT_EXEC:
//				Tempstr=FormatStr(Tempstr, "%s '%s' '%s' '%s' '%d' '%d'",Act->ActionArg, FE->Path,FE->User,FE->Prog,FE->pid,FE->ppid);
//				Spawn(Tempstr,"","","");
			break;

			case ACT_DIRLOG:
				ServantDirectoryLog(ptr);
			break;

			case ACT_ADDLIST:
				ServantListAdd(ptr);
			break;

			case ACT_SEND:
				//FileWatchSend();
			break;

			case ACT_MAIL:
				Tempstr=SubstituteVarsInString(Tempstr, "$(access) $(path) by $(user)@$(ip) program $(program):$(pid) at $(when)" , Vars, 0);
				SMTPSendMail(GetVar(Vars,"sender"), GetVar(Vars, "ActionArg"), GetVar(Vars, "subject"), Tempstr, 0);
			break;

			case ACT_FREEZEPROC:
				SignalProcess(GetVar(Vars,"pid"), SIGSTOP);
			break;

			case ACT_KILLPROC:
				SignalProcess(GetVar(Vars,"pid"), SIGKILL);
			break;

			case ACT_FREEZEPARENT:
				SignalProcess(GetVar(Vars,"pid"), SIGSTOP);
				SignalProcess(GetVar(Vars,"ppid"), SIGSTOP);
			break;

			case ACT_KILLPARENT:
				SignalProcess(GetVar(Vars,"pid"), SIGKILL);
				SignalProcess(GetVar(Vars,"ppid"), SIGKILL);
			break;

			#ifdef USE_XATTR
			case ACT_XATTR:
			Token=CopyStr(Token,GetVar(Vars,"extra"));
			if (StrValid(Token))
			{
			Tempstr=SubstituteVarsInString(Tempstr, GetVar(Vars, "ActionArg") ,  Vars, 0);
			if (StrValid(Tempstr)) FileSetXAttr(GetVar(Vars, "path"), Token, Tempstr);
			}
			break;


			case ACT_XCHANGELOG:
			Tempstr=SubstituteVarsInString(Tempstr, "$(when) $(user)@$(ip) $(program):$(pid) |",  Vars, 0);
			Token=FileGetXAttr(Token, GetVar(Vars, "path"), "trusted.filewatch-log");
			Tempstr=CatStr(Tempstr,Token);
			if (StrLen(Tempstr) > 1024) Tempstr[1024]='\0';
			FileSetXAttr(GetVar(Vars, "path"), "trusted.filewatch-log", Tempstr);
			break;

			case ACT_MD5:
				HashFile(&Token, "md5", GetVar(Vars,"path"), ENCODE_HEX);
				Tempstr=FormatStr(Tempstr,"%lu:%llu:%s",(unsigned long) Now,(unsigned long long) filesize, Token);
				FileSetXAttr(GetVar(Vars, "path"), "trusted.hashrat:md5", Tempstr);
			break;

			case ACT_SHA1:
				HashFile(&Token, "sha1", GetVar(Vars,"path"), ENCODE_HEX);
				Tempstr=FormatStr(Tempstr,"%lu:%llu:%s",(unsigned long) Now,(unsigned long long) filesize, Token);
				FileSetXAttr(GetVar(Vars, "path"), "trusted.hashrat:sha1", Tempstr);
			break;

			case ACT_SHA256:
				HashFile(&Token, "sha256", GetVar(Vars,"path"), ENCODE_HEX);
				Tempstr=FormatStr(Tempstr,"%lu:%llu:%s",(unsigned long) Now,(unsigned long long) filesize, Token);
				FileSetXAttr(GetVar(Vars, "path"), "trusted.hashrat:sha256", Tempstr);
			break;
			#endif
		}
}

Line=STREAMReadLine(Line, Input);
}


Destroy(Tempstr);
Destroy(Token);
Destroy(Value);
Destroy(Line);
}


