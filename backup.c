#include "backup.h"
#include "actions.h"

void BackupFile(ListNode *Vars)
{
    char *Path=NULL, *BackupPath=NULL, *Tempstr=NULL;
    const char *ptr;
    struct stat Stat;

    Path=CopyStr(Path, GetVar(Vars, "path"));

//don't backup zero length files
    stat(Path, &Stat);
    if (Stat.st_size > 0)
    {
        BackupPath=SubstituteVarsInString(BackupPath, GetVar(Vars, "ActionArg"), Vars, 0);

        //if path starts with / it's an absolute path, otherwise it's relative
        //and we need to handle that here
        if (*BackupPath != '/')
        {
            Tempstr=CopyStr(Tempstr, Path);
            StrRTruncChar(Tempstr, '/');
            Tempstr=MCatStr(Tempstr, "/", BackupPath, NULL);
            BackupPath=CopyStr(BackupPath, Tempstr);
        }

        MakeDirPath(BackupPath, 0700);
        FileCopy(Path, BackupPath);
	FilePostProcess(BackupPath, Vars);
    }

    Destroy(BackupPath);
    Destroy(Tempstr);
    Destroy(Path);
}
