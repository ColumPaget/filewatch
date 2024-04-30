//This module relates to the servant process that handles actions triggered
//by an event. We have to use a servant process to seperate out the part of
//the system that grants permissions from the part that does things,
//otherwise we can get deadlocked waiting for permissiong from ourselves

#include "servant.h"
#include "actions.h"

//so we can close it
extern int FaNotifyFD;


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
    SetVar(Vars, "isodate", GetDateStr("%Y-%m-%dT%H:%M:%S",NULL));
    SetVar(Vars, "date", GetDateStr("%Y-%m-%dT%H:%M:%S",NULL));

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


int ServantProcess(void *Nothing, int Flags)
{
    char *Tempstr=NULL, *Line=NULL, *Token=NULL, *Value=NULL;
    int Act;
    STREAM *Input;
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
            ProcessAction(Act, Vars);
        }

        Line=STREAMReadLine(Line, Input);
    }


    Destroy(Tempstr);
    Destroy(Token);
    Destroy(Value);
    Destroy(Line);

    return(0);
}


