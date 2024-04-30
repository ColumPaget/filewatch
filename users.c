#include "users.h"

ListNode *UserList=NULL;

//load list of users, so
void LoadUserList()
{
    STREAM *S;
    char *Tempstr=NULL, *Name=NULL, *Token=NULL;
    const char *ptr;

    if (! UserList) UserList=ListCreate();
    S=STREAMOpen("/etc/passwd", "r");
    Tempstr=STREAMReadLine(Tempstr, S);
    while (Tempstr)
    {
        ptr=GetToken(Tempstr,":",&Name,0);
        ptr=GetToken(ptr,":",&Token,0);
        //UID
        ptr=GetToken(ptr,":",&Token,0);
        SetVar(UserList, Token, Name);
        Tempstr=STREAMReadLine(Tempstr, S);
    }
    STREAMClose(S);

    Destroy(Tempstr);
    Destroy(Token);
    Destroy(Name);
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


int FindUserID(const char *Name)
{
ListNode *Curr;

Curr=ListGetNext(UserList);
while (Curr)
{
if (strcmp(Name, (char *) Curr->Item)==0) return(atoi(Curr->Tag));
Curr=ListGetNext(Curr);
}

//if user not found, reload userlist and try again
LoadUserList();
Curr=ListGetNext(UserList);
while (Curr)
{
if (strcmp(Name, (char *) Curr->Item)==0) return(atoi(Curr->Tag));
Curr=ListGetNext(Curr);
}

return(-1);
}
