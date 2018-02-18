#include "files_db.h"

#define FILESDB_BUCKET_COUNT 1025

ListNode *DB=NULL;
ListNode *CloseList=NULL;

TFileEvent *FilesDBAdd(const char *Path, int Flags, pid_t pid)
{
TFileEvent *FE;
struct stat Stat;
char *Tempstr=NULL;
STREAM *S;
int len;
uint64_t When;

if (! DB) DB=MapCreate(FILESDB_BUCKET_COUNT, LIST_FLAG_CACHE);

  FE=(TFileEvent *) calloc(1, sizeof(TFileEvent));
  if (Flags & FAN_MODIFY) FE->Flags |= FLAG_MODIFY;
  FE->pid=pid;
  FE->Path=CopyStr(FE->Path, Path);

  if (stat(FE->Path,&Stat)==0)
  {
    FE->FMode=Stat.st_mode;
    FE->FSize=Stat.st_size;
    FE->MTime=Stat.st_mtime;
    FE->CTime=Stat.st_ctime;
		if ((FE->CTime < FE->MTime) && ((Now - FE->CTime) < 3)) FE->Flags |= FLAG_RENAME;

		When=Now - FE->CTime;
		if (When < 60) FE->Flags |= FLAG_NEW;
		if (FE->FMode & S_IXUSR) FE->Flags |= FLAG_EXECUTABLE;
	}
	else 
	{
		//file likely deleted
		FE->MTime=Now;
		FE->CTime=Now;
	}

  #ifdef USE_XATTR
  FE->StoredPath=FileGetXAttr(FE->StoredPath, FE->Path, "trusted.filewatch-path");
  if (StrLen(FE->StoredPath)==0)
  {
     FE->StoredPath=CopyStr(FE->StoredPath, FE->Path);
     FileSetXAttr(FE->Path, "trusted.filewatch-path", FE->StoredPath);
  }
  else if (strcmp(FE->Path, FE->StoredPath) !=0) 
	{
		FE->Flags |= FLAG_RENAME;
	}
  #endif

	ListAddNamedItem(DB, FE->Path, FE);
//printf("LIST ADD: %d %s\n",ListSize(DB),Path);
	Destroy(Tempstr);
	
	return(FE);
}




TFileEvent *FilesDBGet(const char *Path)
{
ListNode *Curr, *Next;
TFileEvent *FE;

if (DB)
{
Curr=ListFindNamedItem(DB, Path);
if (Curr) return((TFileEvent *) Curr->Item);
}

Curr=ListGetNext(CloseList);
while (Curr)
{
Next=ListGetNext(Curr);
FE=(TFileEvent *) Curr->Item;
if (strcmp(Path, Curr->Tag)==0) return(FE);

if ((Now - FE->When) > 10)
{
	ListDeleteNode(Curr);
	FileEventDestroy(FE);
}

Curr=Next;
}

return(NULL);
}


void FilesDBRemove(const char *Path)
{
TFileEvent *FE;
ListNode *Node;

if (DB)
{
Node=ListFindNamedItem(DB, Path);
if (Node)
{
//	printf("DB DEL: %d [%s]\n",Node, Path);
	FE=(TFileEvent *) Node->Item;
	if (! CloseList) CloseList=ListCreate();
	ListAddNamedItem(CloseList, Path, FE);
	ListDeleteNode(Node);
}
}

}



void FilesDBHousekeep()
{
ListNode *Curr, *Next;
TFileEvent *FE;

Curr=MapGetNthChain(DB, rand() % FILESDB_BUCKET_COUNT); 
Curr=ListGetNext(Curr); //go past list head
while (Curr)
{
Next=ListGetNext(Curr);
FE=(TFileEvent *) Curr->Item;
if ((Now - FE->When) > 20)
{
	ListDeleteNode(Curr);
	FileEventDestroy(FE);
}
Curr=Next;
}
}
