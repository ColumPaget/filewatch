#include "users.h"

ListNode *UserList=NULL;

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

const char *FindUserName(const char *UidStr)
{
ListNode *Node;

Node=ListFindNamedItem(UserList, UidStr);
if (Node) return((const char *) Node->Item);

return(NULL);
}

