#include "users.h"

ListNode *UserList=NULL, *GroupList=NULL;

//load list of users, so
void LoadList(const char *Path, ListNode *List)
{
    STREAM *S;
    char *Tempstr=NULL, *Name=NULL, *Token=NULL;
    const char *ptr;

    S=STREAMOpen(Path, "r");
    Tempstr=STREAMReadLine(Tempstr, S);
    while (Tempstr)
    {
        ptr=GetToken(Tempstr,":",&Name,0);
        ptr=GetToken(ptr,":",&Token,0);
        //UID
        ptr=GetToken(ptr,":",&Token,0);
        SetVar(List, Token, Name);
        Tempstr=STREAMReadLine(Tempstr, S);
    }
    STREAMClose(S);

    Destroy(Tempstr);
    Destroy(Token);
    Destroy(Name);
}


void LoadUserList()
{
    if (! UserList) UserList=ListCreate();
    LoadList("/etc/passwd", UserList);

    if (! GroupList) GroupList=ListCreate();
    LoadList("/etc/group", GroupList);
}


//find user name for a given uid
const char *FindUserName(const char *UidStr)
{
    ListNode *Node;

    Node=ListFindNamedItem(UserList, UidStr);
    if (Node) return((const char *) Node->Item);

    //if user not found, reload userlist and try again
    LoadUserList();
    Node=ListFindNamedItem(UserList, UidStr);
    if (Node) return((const char *) Node->Item);

    return(NULL);
}


int FindID(const char *Name, ListNode *List)
{
    ListNode *Curr;

    Curr=ListGetNext(List);
    while (Curr)
    {
        if (strcmp(Name, (char *) Curr->Item)==0) return(atoi(Curr->Tag));
        Curr=ListGetNext(Curr);
    }

    return(-1);
}


int FindUserID(const char *Name)
{
int id;

id=FindID(Name, UserList);
//if user not found, reload userlist and try again
LoadUserList();
id=FindID(Name, UserList);

return(id);
}

int FindGroupID(const char *Name)
{
int id;

id=FindID(Name, GroupList);
//if user not found, reload userlist and try again
LoadUserList();
id=FindID(Name, GroupList);

return(id);
}


