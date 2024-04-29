[![Build Status](https://travis-ci.com/ColumPaget/filewatch.svg?branch=master)](https://travis-ci.com/ColumPaget/filewatch)

## SUMMARY

	Filewatch is a utility that uses fanotify to watch file open/close/modify events. It can output these events to the terminal or trigger a number of 'actions' in response. 

## DISCLAIMER

  This is free software. It comes with no guarentees and I take no responsiblity if it makes your computer explode or opens a portal to the demon dimensions, or does anything. It is released under the Gnu Public Licence version 3.

	Please note this is the initial release (v0.1) of filewatch. I'm using it, but it's not been extensively tested yet.

## USAGE

	Filewatch is configured via a combination of configuration file and command-line options.

## INVOCATION

	filewatch [options] mount-point [mount-point]

## OPTIONS

```
	-c <path>    Path to config file (default is /etc/filewatch.conf)
	-d           Become a background 'daemon' process
	-D           Print some debugging output
	-show        Show all file events
	-show-write  Show file modification events
	-mx <host>   Mail exchange host for sending notifications
```
	
## CONFIG FILE

The config file describes actions to take in response to file events. Entries have the format:

```
<action> <argument> <qualifiers>
```

The 'qualifiers' section breaks down into arguments that specify which events to match, and arguments that alter the action.

### actions:

```
ignore                   Discard any matching events
log <message>            This action writes an entry in a logfile. The default logfile is /var/log/filewatch.log, though it can be altered with the 'logfile' qualifier
syslog <message>         Send an 'info' message to syslog.
syslog:warn <message>    Send an 'warning' message to syslog.
syslog:crit <message>    Send an 'critical' message to syslog.
exec <command>           Execute a command.
freeze                   If event matches then send 'SIGSTOP' to the associated process, 'freezing' it.
kill                     If event matches then send 'SIGKILL' to the associated process.
freeze                   If event matches then send 'SIGSTOP' to the associated process, 'freezing' it.
freeze+parent            If event matches then send 'SIGSTOP' to the associated process, 'freezing' it AND ITS PARENT.
kill+parent              If event matches then send 'SIGKILL' to the associated process AND ITS PARENT.
backup <path>            Copy file to the given path.
xattr <value>            Set an extended attribute on filesystems that support this.
xachangelast             Use an extended attribute on filesystems that support this to record who/what/when last changed a file.
xachangelog              Use an extended attribute on filesystems that support this to support a changelog of recent changes to a file.
md5                      Use an extended attribute to store an md5 hash of the file (stored in trusted.hashrat:md5  and in hashrat format).
sha1                     Use an extended attribute to store an sha1 hash of the file (stored in trusted.hashrat:sha1 and in hashrat format).
sha256                   Use an extended attribute to store an sha256 hash of the file (stored in trusted.hashrat:sha256 and in hashrat format).
call <ruleset>           call a ruleset
```

### hash actions

'hashrat' format is used for the md5, sha1, and sha256 actions, and this is a format compatible with my 'hashrat' hashing program. The format is:

```
<seconds>:<filesize>:<hash>
```

The 'seconds' argument is the time that the hash was valid for, expressed in seconds since epoch. This and the filesize are used to give some assurance that the file hasn't changed since the hash was taken. 

### xattr actions

The xachangelog and xachangelast actions record details of file changes in file extended attributes. The xachangelast action just records the user, program and time details of the change. The xachangelog action stores a list of such details, fitting as many change records as it can into the extended attribute on a first-in-first-out basis. 

Extended attributes can be viewed by running the 'getfattr -m - -d <filename>' command as root. The '-m -' option is needed to ensure that all attributes (including trusted) are listed, not just 'user' attributes. On XFS filesystems the command 'attr -R -l <filename>' can be used to list extended attributes, and 'attr -R -g <attribute> <filename>' can be used to view the value of an attribute.

There is an issue with the xachangelog action that if a process creates a copy of a file, and then replaces the original, the changelog is not carried over. In such situations the changelog will only contain the last change.

### exec actions

The 'exec' action allows a command to be run in response to a file event. It takes a single argument that defines the command to be run, like so:

```
exec '/usr/bin/aplay /usr/share/sounds/warning.wav' path=/etc/hosts close
```

### arguments:

The 'log', 'syslog' and 'exec' actions take an argument that defines the message or defines the command to be run in the case of 'exec'. This argument can include 'variables' that are substituted with values relating to the event. For example:

```
syslog:crit "executable modified path=$(path) by $(user)@$(ip) $(prog)" exec modify

exec "/usr/local/bin/OrderImport $(path)"  path=/home/dropbox/orders/*.csv modify
```

available variables are:

```
path         path of file the event applies to.
name         basename of file the event applies to.
filesize     size of file the event applies to.
user         user the event applies to
pid          pid of process the event applies to.
ppid         pid of parent process to the process the event applies to.
prog         path of program the event applies to.
progname     basename of program the event applies to.
ip           ip address of remote connection associated with program (if this can be deduced).
new          'y' if the file appears new, 'n' otherwise.
rename       'y' if the file appears to have been renamed, 'n' otherwise.
executable   'y' if the file is executable, 'n' otherwise.
access       'open', 'close' or 'modify'
when         date/time in "%Y/%m/%d %H:%M:%S" format
isodate      date/time in "%Y-%m-%dT%H:%M:%S" format
date         date/time in "%Y-%m-%dT%H:%M:%S" format
```



### qualifiers:

```
path=<path>,<path>...       Match events where the file path matches one in this list (paths can include wildcards)
prog=<path>,<path>...       Match events where the program matches one in this list
program=<path>,<path>...    Match events where the program matches one in this list
user=<username>...          Match events where the username matches one in this list.
exec                        Match events where the file has the executable permission set.
executable                  Match events where the file has the executable permission set.
new                         Match events where the file seems to have been recently created.
rename                      Match events where the file seems to have been renamed.
modify                      Match events where the file is modified.
close                       Match events where the file is closed.
time=<HH:MM:SS>             Match events where the time of event matches (time can include wildcards).
pid-per-sec=<num>           Match events where a process has opened this many files per second.
pid-per-min=<num>           Match events where a process has opened this many files per minute.
pid-per-hour=<num>          Match events where a process has opened this many files per hour.
user-per-sec=<num>          Match events where a user has opened this many files per second.
user-per-min=<num>          Match events where a user has opened this many files per minute.
user-per-hour=<num>         Match events where a user has opened this many files per hour.
ip-per-sec=<num>            Match events where an ip address has opened this many files per second.
ip-per-min=<num>            Match events where an ip address has opened this many files per minute.
ip-per-hour=<num>           Match events where an ip address has opened this many files per hour.

logfile=<path>              Set logfile path to write to.
```


## RULESETS

actions can be grouped together into rulesets, like so:


```
ruleset TooManyPerSecond
{
ignore prog=make,gcc
ignore path=/var/log/log.smbd

log "too many opens per sec $(path) $(prog):$(pid) $(user)@$(ip)" logfile=/var/log/filewatch-ppm.log
freeze 
}

call TooManyPerSecond pid-per-sec=100

```


## EXAMPLE CONFIG FILE

```
ruleset modify-executable
{
syslog:crit "executable file was modified path=$(path) by $(user)@$(ip) $(prog)"
log "$(path) $(user)@$(ip) $(prog)" logfile=/var/log/filewatch-exe.log
}

ruleset modify-etc
{
syslog:crit "file in /etc was modified path=$(path) by $(user)@$(ip) $(prog)"
log "$(path) $(user)@$(ip) $(prog)" logfile=/var/log/filewatch-etc.log
}


ruleset pps
{
ignore "" prog=make,gcc

log "too many file modification per second by program: $(prog) pid: $(pid) user: $(user) ip: $(ip)" logfile=/var/log/filewatch-ppm.log
freeze
}


ruleset modified
{
log "$(path)" logfile=/var/log/progfiles/$(prog).log
call modify-etc path=/etc/* modify
call modify-executable modify executable

log "late night file modification $(path) $(user)@$(ip) $(prog)" time=2?:??:??,0[0-6]:??:?? logfile=/var/log/filewatch-latenight.log
log "$(path)" close logfile=/var/log/filewatch-modified.log
md5 "" close
call pps pid-per-sec=10
xachangelog
}


ignore "" path=/var/log/*,/var/locks/*,/var/run/*,/opt/dominion/log/*,/tmp/*,/var/log.*,/var/state/*/*

log "suspect extension $(path) $(user)@$(ip) $(prog)" path=*.enc,.ecc,*.ezz,*.exx,*.zzz,*.xyz,*.aaa,*.abc,*.ccc,*.vvv,*.xxx,*.ttt,*.micro,*.encrypted,*.locked,*.cry,*.crypto,*_crypt,*.crinf,*.r5a,*.XRNT,*.XTBL,*.crypt,*.R16M01D05,*.pzdc,*.good,*.LOL!,*.OMG!,*.RDM,*.RRK,*.encryptedRSA,*.crjoker,*.EnCiPhErEd,*.LeChiffre,*.keybtc@inbox_com,*.0x0,*.bleep,*.1999,*.vault,*.HA3,*.toxcrypt,*.magic,*.SUPERCRYPT,*.CTBL,*.CTB2,*.locky logfile=/var/log/filewatch-sus.log
log "suspect extension $(path) $(user)@$(ip *$(prog)" path=*[Dd]ecrypt*,*[Rr]ecover*,*[Rr]estor*,*DECRYPT*,*RECOVER*,*RESTORE* logfile=/var/log/filewatch-sus.log

call modified modify
```
