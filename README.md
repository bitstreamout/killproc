#Install

Edit the Makefile (set ***INITDIR*** to the path of the
boot scripts used by the system during boot time),
type ```make``` and ```make install```.

#Processes controlling

This small package provides three tools for process controlling
in scripts by using the virtuell file system /proc/.

These programs 1994 had been initally written 1994 during the
migration from the BSD boot scripts of an old slackware to a
System V R4 boot scheme.

##The syntax is simple

starting programs with checking:

```
   startproc [-v] [-l log_file] [-p pid_file] /full/path/to/program
```

checking for programs:

```
checkproc [-v] [-p pid_file] /full/path/to/program
```

killing programs:


```
   killproc [-v] [-g|-G] [-SIG] /full/path/to/program
```

listing all known signals of killproc:

```
killproc -l
```
