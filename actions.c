#include "actions.h"
#include "backup.h"
#include "users.h"
#include <syslog.h>


void FilePostProcess(const char *Path, ListNode *Vars)
{
    const char *ptr;
    int val;

    ptr=GetVar(Vars, "fileowner");
    if (StrValid(ptr))
    {
        val=FindUserID(ptr);
        if (val > 0) chown(Path, val, -1);
    }

    ptr=GetVar(Vars, "filegroup");
    if (StrValid(ptr))
    {
        val=FindGroupID(ptr);
        if (val > 0) chown(Path, -1, val);
    }

    ptr=GetVar(Vars, "filemode");
    if (StrValid(ptr)) chmod(Path, strtol(ptr, NULL, 8));
}


static void SignalProcess(const char *PidStr, int Sig)
{
    pid_t pid;

    pid=(pid_t) strtoul(PidStr,NULL, 10);

//do not signal/kill pid 1 (init) nor ourselves, nor our parent
    if ( (pid > 1) && (pid != getpid()) && (pid != getppid()) ) kill(pid, Sig);
}


// add something to a list file (only if it doesn't already exist in the file)
static void ActionListAdd(const char *Config)
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



static void ActionHashFile(ListNode *Vars, const char *HashType)
{
    char *Tempstr=NULL, *Name=NULL;
    size_t filesize;

#ifdef USE_XATTR
    filesize=strtoul(GetVar(Vars, "filesize"),NULL,10);
    HashFile(&Name, HashType, GetVar(Vars,"path"), ENCODE_HEX);
    Tempstr=FormatStr(Tempstr,"%lu:%llu:%s",(unsigned long) Now,(unsigned long long) filesize, Name);
    Name=MCopyStr(Name, "trusted.hashrat:", HashType, NULL);
    FileSetXAttr(GetVar(Vars, "path"), Name, Tempstr);
#endif

    Destroy(Tempstr);
    Destroy(Name);
}



static void ActionLog(ListNode *Vars)
{
    char *Path=NULL, *Tempstr=NULL;
    STREAM *S;

    Path=CopyStr(Path,GetVar(Vars,"logpath"));
    if (! StrValid(Path)) Path=CopyStr(Path, "/var/log/filewatch.log");
    MakeDirPath(Path, 0700);
    S=STREAMOpen(Path, "a");
    if (S)
    {
        Tempstr=MCopyStr(Tempstr, GetDateStr("%Y/%m/%d %H:%M:%S",NULL), " ", NULL);
        STREAMWriteLine(Tempstr, S);
        Tempstr=SubstituteVarsInString(Tempstr, GetVar(Vars, "ActionArg"),  Vars, 0);
        STREAMWriteString(Tempstr, S);
        STREAMWriteLine("\n", S);
        STREAMClose(S);
        FilePostProcess(Path, Vars);
    }

    Destroy(Tempstr);
    Destroy(Path);
}


static void ActionDirectoryLog(const char *Config)
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



void ProcessAction(int Act, ListNode *Vars)
{
    char *Token=NULL, *Tempstr=NULL;
    const char *ptr;
    int val;

    switch (Act)
    {
    case ACT_SYSLOG:
    case ACT_SYSLOG_CRIT:
    case ACT_SYSLOG_WARN:
        val=LOG_DEBUG;
        if (Act==ACT_SYSLOG) val=LOG_INFO;
        else if (Act==ACT_SYSLOG_WARN) val=LOG_WARNING;
        else if (Act==ACT_SYSLOG_CRIT) val=LOG_CRIT;
        Token=CopyStr(Token, GetVar(Vars, "ActionArg"));
        Tempstr=SubstituteVarsInString(Tempstr, Token,  Vars, 0);
        syslog(val, "%s", Tempstr);
        break;

    case ACT_LOG:
        ActionLog(Vars);
        break;

    case ACT_EXEC:
        Token=CopyStr(Token, GetVar(Vars, "ActionArg"));
        Tempstr=SubstituteVarsInString(Tempstr, Token,  Vars, 0);
        Spawn(Tempstr,"");
        break;

    case ACT_DIRLOG:
        ActionDirectoryLog(ptr);
        break;

    case ACT_ADDLIST:
        ActionListAdd(ptr);
        break;

    case ACT_SEND:
        //FileWatchSend();
        break;

    case ACT_MAIL:
        Tempstr=SubstituteVarsInString(Tempstr, "$(access) $(path) by $(user)@$(ip) program $(program):$(pid) at $(when)", Vars, 0);
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

    case ACT_FILEBACKUP:
        BackupFile(Vars);
        break;

#ifdef USE_XATTR
    case ACT_XATTR:
        Token=CopyStr(Token,GetVar(Vars,"extra"));
        if (StrValid(Token))
        {
            Tempstr=SubstituteVarsInString(Tempstr, GetVar(Vars, "ActionArg"),  Vars, 0);
            if (StrValid(Tempstr)) FileSetXAttr(GetVar(Vars, "path"), Token, Tempstr);
        }
        break;

    case ACT_XACHANGELAST:
        Tempstr=SubstituteVarsInString(Tempstr, "$(when) $(user)@$(ip) $(program):$(pid)",  Vars, 0);
        FileSetXAttr(GetVar(Vars, "path"), "trusted.filewatch:last", Tempstr);
        break;

    case ACT_XACHANGELOG:
        Tempstr=SubstituteVarsInString(Tempstr, "$(when) $(user)@$(ip) $(program):$(pid) |",  Vars, 0);
        Token=FileGetXAttr(Token, GetVar(Vars, "path"), "trusted.filewatch:log");
        Tempstr=CatStr(Tempstr,Token);
        if (StrLen(Tempstr) > 1024) Tempstr[1024]='\0';
        FileSetXAttr(GetVar(Vars, "path"), "trusted.filewatch:log", Tempstr);
        break;

    case ACT_MD5:
        ActionHashFile(Vars, "md5");
        break;

    case ACT_SHA1:
        ActionHashFile(Vars, "sha1");
        break;

    case ACT_SHA256:
        ActionHashFile(Vars, "sha256");
        break;
#endif
    }

    Destroy(Tempstr);
    Destroy(Token);
}
