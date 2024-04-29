#include "common.h"

const char *ActionTypes[]= {"{", "}","ruleset","call","ignore","syslog:crit","syslog:warn","syslog","log","exec","xattr", "dirlog", "send", "mail", "allow", "deny", "addlist","xachangelast", "xachangelog","freeze","freeze+parent","kill","kill+parent","backup","return","md5","sha1","sha256",NULL};


ListNode *RuleChains=NULL;
ListNode *Rules=NULL;

//Events that are needed to satisfy config file requirements
uint64_t EventMask= FAN_OPEN | FAN_CLOSE | FAN_ONDIR | FAN_EVENT_ON_CHILD;

int GlobalFlags=0;
time_t Now;


