#include "stats.h"

ListNode *StatsList=NULL;


TStats *StatsIncr(const char *Name)
{
    ListNode *Node;
    TStats *Stats;
    uint64_t Diff;

    if (! StatsList) StatsList=MapCreate(101, LIST_FLAG_CACHE);

    Node=ListFindNamedItem(StatsList, Name);
    if (! Node)
    {
        Stats=(TStats *) calloc(1,sizeof(TStats));
        Stats->since_sec=Now;
        Stats->since_min=Now;
        Stats->since_hour=Now;
        Node=ListAddNamedItem(StatsList, Name, Stats);
    }
    else Stats=(TStats *) Node->Item;


    if ((Now - Stats->since_sec) > 0)
    {
        Stats->per_sec=0;
        Stats->since_sec=Now;
    }
    Stats->per_sec++;

    if ((Now - Stats->since_min) > 60)
    {
        Stats->per_min = 0;
        Stats->since_min=Now;
    }
    Stats->per_min++;

    if ((Now - Stats->since_hour) > 3600)
    {
        Stats->per_hour = 0;
        Stats->since_hour=Now;
    }
    Stats->per_hour++;

    return(Stats);
}

