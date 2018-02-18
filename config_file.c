#include "config_file.h"


time_t ParseFileAge(const char *Value)
{
const char *ptr;
long val;

val=strtol(Value, &ptr, 10);
while (*ptr==' ') ptr++;
switch (*ptr)
{
case 'm': val *= 60; break;
case 'h': val *= 3600; break;
case 'd': val *= (3600 * 24); break;
case 'w': val *= (3600 * 24 * 7); break;
case 'y': val *= (3600 * 24 * 365); break;
}

return(val);
}


void ParseRuleset(STREAM *S, ListNode *Rules)
{
char *Tempstr=NULL, *Name=NULL, *Value=NULL;
const char *ptr;
TFileAction *Act;
ListNode *Ruleset;
int val;

  Tempstr=STREAMReadLine(Tempstr, S);
	while (Tempstr)
	{
	StripTrailingWhitespace(Tempstr);
	StripLeadingWhitespace(Tempstr);
	ptr=GetToken(Tempstr,"\\S", &Value, GETTOKEN_QUOTES);
	val=MatchTokenFromList(Value, ActionTypes, 0);

	if (val==ENDBRACE) break;
	if (val > -1)
	{
		Act=(TFileAction *) calloc(1,sizeof(TFileAction));
		Act->Action=val;
		switch (Act->Action)
		{
		case RULESET:
			if (! RuleChains) RuleChains=ListCreate();
			Ruleset=ListCreate();
			ptr=GetToken(ptr,"\\S", &Name, GETTOKEN_QUOTES);
			ListAddNamedItem(RuleChains, Name, Ruleset);
			ParseRuleset(S, Ruleset);
		break;

		case ACT_ALLOW:
				Act->Flags |= OPEN_ALLOW;
			//	EventMask |= FAN_OPEN_PERM;
		ListAddItem(Rules, Act);
		break;

		case ACT_DENY:
				Act->Flags |= OPEN_DENY;
			//	EventMask |= FAN_OPEN_PERM;
		ListAddItem(Rules, Act);
		break;

		case ACT_IGNORE:
			ListAddItem(Rules, Act);
		break;


		//no arguments to these
		case ACT_FREEZEPROC:
		case ACT_KILLPROC:
		ListAddItem(Rules, Act);
		break;

		case ACT_ADDLIST:
		ptr=GetToken(ptr,"\\S", &Name, GETTOKEN_QUOTES);
		ptr=GetToken(ptr,"\\S", &Value, GETTOKEN_QUOTES);
		Act->ActionArg=MCopyStr(Act->ActionArg, "'",Name,"' '",Value,"'",NULL);
		ListAddItem(Rules, Act);
		break;

		default:
		ptr=GetToken(ptr,"\\S", &Act->ActionArg, GETTOKEN_QUOTES);
		ListAddItem(Rules, Act);
		break;
		}


		ptr=GetNameValuePair(ptr, "\\S", "=", &Name, &Value);
		while (ptr)
		{
			if (strcasecmp(Name, "path")==0) Act->Path=CopyStr(Act->Path, Value);
			else if (strcasecmp(Name, "program")==0) Act->Prog=CopyStr(Act->Prog, Value);
			else if (strcasecmp(Name, "prog")==0) Act->Prog=CopyStr(Act->Prog, Value);
			else if (strcasecmp(Name, "user")==0) Act->User=CopyStr(Act->User, Value);
			else if (strcasecmp(Name, "executable")==0) Act->Flags |= MATCH_EXECUTABLE;
			else if (strcasecmp(Name, "exec")==0) Act->Flags |= MATCH_EXECUTABLE;
			else if (strcasecmp(Name, "new")==0) Act->Flags |= MATCH_NEW;
			else if (strcasecmp(Name, "rename")==0) Act->Flags |= MATCH_RENAME;
			else if (strcasecmp(Name, "time")==0) Act->Time=CopyStr(Act->Time, Value);
			else if (strcasecmp(Name, "min-age")==0) Act->MinAge=ParseFileAge(Value);
			else if (strcasecmp(Name, "max-age")==0) Act->MaxAge=ParseFileAge(Value);
			else if (strcasecmp(Name, "pid-per-sec")==0) Act->PidMaxPerSec=atoi(Value);
			else if (strcasecmp(Name, "pid-per-min")==0) Act->PidMaxPerMin=atoi(Value);
			else if (strcasecmp(Name, "pid-per-hour")==0) Act->PidMaxPerHour=atoi(Value);
			else if (strcasecmp(Name, "user-per-sec")==0) Act->UserMaxPerSec=atoi(Value);
			else if (strcasecmp(Name, "user-per-min")==0) Act->UserMaxPerMin=atoi(Value);
			else if (strcasecmp(Name, "user-per-hour")==0) Act->UserMaxPerHour=atoi(Value);
			else if (strcasecmp(Name, "ip-per-sec")==0) Act->IPMaxPerSec=atoi(Value);
			else if (strcasecmp(Name, "ip-per-min")==0) Act->IPMaxPerMin=atoi(Value);
			else if (strcasecmp(Name, "ip-per-hour")==0) Act->IPMaxPerHour=atoi(Value);
			else if (strcasecmp(Name, "warn")==0) Act->Flags |= SYSLOG_WARN;
			else if (strcasecmp(Name, "crit")==0) Act->Flags |= SYSLOG_CRIT;
//			else if (strcasecmp(Name, "format")==0) Act->ActionArg=CopyStr(Act->ActionArg, Value);
			else if (strcasecmp(Name, "modify")==0) 
			{
				Act->Flags |= MATCH_MODIFY;
				EventMask |= FAN_MODIFY;
			}
			else if (strcasecmp(Name, "close")==0) Act->Flags |= MATCH_CLOSE;
			else if (strcasecmp(Name, "logfile")==0) Act->Extra=CopyStr(Act->Extra, Value);
			else if (strcasecmp(Name, "mx")==0) Act->Extra=CopyStr(Act->Extra, Value);
			else if (strcasecmp(Name, "server")==0) Act->Extra=CopyStr(Act->Extra, Value);

			ptr=GetNameValuePair(ptr, "\\S", "=", &Name, &Value);
		}
	}
	
	Tempstr=STREAMReadLine(Tempstr, S);
	}
	Destroy(Value);
	Destroy(Name);
}



void LoadConfig(const char *Path)
{
char *Tempstr=NULL;
STREAM *S;

if (! Rules) Rules=ListCreate();
S=STREAMOpen(Path, "r");
if (S)
{
ParseRuleset(S, Rules);
STREAMClose(S);
}

Destroy(Tempstr);
}


