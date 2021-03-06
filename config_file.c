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


void ParseRuleset(STREAM *S, const char *SetName, ListNode *Rules)
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

	//ignore blank lines, we don't want to trigger 'unrecognized config entry' warnings for them
	if (StrValid(Tempstr))
	{
	ptr=GetToken(Tempstr,"\\S", &Value, GETTOKEN_QUOTES);

	//This returns a value representing an action from action types, so if you're looking
	//in this file for ACT_CALL, ACT_XACHANGELOG, etc, then they're not explicity handled
	//but are instead identified by this line
	val=MatchTokenFromList(Value, ActionTypes, 0);

	if (val==ENDBRACE) break;
	if ((val == -1) && (GlobalFlags & GFLAG_DEBUG)) 
	{
		//if it starts with # it's a comment, otherwise we've no idea what it is
		if (*Value != '#')	printf("WARNING: Unrecognized config entry: %s\n", Tempstr);
	}
	else
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
			ParseRuleset(S, Name, Ruleset);
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

		case ACT_EXEC:
		ptr=GetToken(ptr,"\\S", &Value, GETTOKEN_QUOTES);
		Act->ActionArg=CopyStr(Act->ActionArg, Value);
		ListAddItem(Rules, Act);
		break;

		default:
		ptr=GetToken(ptr,"\\S", &Act->ActionArg, GETTOKEN_QUOTES);
		ListAddItem(Rules, Act);
		break;
		}


		//parse arguments of an action. 
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
	}
	
	Tempstr=STREAMReadLine(Tempstr, S);
	}


	if (GlobalFlags & GFLAG_DEBUG) printf("parsed ruleset: '%s' %d entries\n", SetName, ListSize(Rules));
	Destroy(Value);
	Destroy(Name);
}



static void ConfigCheckRules(ListNode *Rules, ListNode *CalledRuleChains)
{
TFileAction *Act;
ListNode *Curr;

Curr=ListGetNext(Rules);
while (Curr)
{
  Act=(TFileAction *) Curr->Item;
	switch (Act->Action)
	{
		case ACT_CALL:
			if (! ListFindNamedItem(RuleChains, Act->ActionArg)) printf("WARNING: ruleset '%s' called but does not exist\n", Act->ActionArg);
			ListAddNamedItem(CalledRuleChains, Act->ActionArg, NULL);
		break;
	}

	Curr=ListGetNext(Curr);
}

}


//this doesn't really declare a config valid or invalid, rather it prints out warnings about possible
//misconfigurations
static void ConfigCheckValid(ListNode *Rules)
{
ListNode *CalledRuleChains;
ListNode *Curr;

CalledRuleChains=ListCreate();
ConfigCheckRules(Rules, CalledRuleChains);

Curr=ListGetNext(RuleChains);
while (Curr)
{
ConfigCheckRules((ListNode *) Curr->Item, CalledRuleChains);
Curr=ListGetNext(Curr);
}

Curr=ListGetNext(RuleChains);
while (Curr)
{
if (! ListFindNamedItem(CalledRuleChains, Curr->Tag)) printf("WARNING: ruleset '%s' exists but is never called\n");
Curr=ListGetNext(Curr);
}

}



int LoadConfig(const char *Path)
{
char *Tempstr=NULL;
STREAM *S;
int RetVal=FALSE;

if (! Rules) Rules=ListCreate();
S=STREAMOpen(Path, "r");
if (S)
{
	RetVal=TRUE;
	if (GlobalFlags & GFLAG_DEBUG) printf("opened config file: '%s'\n", Path);
	ParseRuleset(S, "root", Rules);
	STREAMClose(S);
}
else if (GlobalFlags & GFLAG_DEBUG) printf("ERROR: Failed to open config file: '%s'\n", Path);

if (GlobalFlags & GFLAG_DEBUG) ConfigCheckValid(Rules);
Destroy(Tempstr);

return(RetVal);
}


