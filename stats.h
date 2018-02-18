
#ifndef FILEWATCH_STATS_H
#define FILEWATCH_STATS_H

#include "common.h"

typedef struct
{
float per_sec;
time_t since_sec;

float per_min;
time_t since_min;

float per_hour;
time_t since_hour;
} TStats;

TStats *StatsIncr(const char *Name);

#endif
