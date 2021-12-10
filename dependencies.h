#ifndef DEPENDENCIES_H
#define DEPENDENCIES_H

// Récupération via pgrep du pid du processus de nom procname, et rangement à l'adresse pid
void get_pid_safely(char* procname, char** pid);

// Attachement à un processus via ptrace(PTRACE_ATTACH, ...)
long attach(int pid);

// Recuperation via nm de l'adresse d'une fonction
uint get_fun_addr(char* pid, char* fun);

// write instruction at the beginning of a function, erasing what is already there
void write_at_function(char* pid, uint fun_addr, unsigned char* text, int length);

#endif
