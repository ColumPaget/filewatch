#include "event.h"

void FileEventDestroy(TFileEvent *FE)
{
if (! FE) return;

Destroy(FE->Path);
Destroy(FE->StoredPath);
free(FE);
}

