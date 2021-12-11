#ifndef DEPENDENCIES_H
#define DEPENDENCIES_H

// Récupération via pgrep du pid du processus de nom procname, et rangement à l'adresse pid
void get_pid(char* procname, char** pid);

// macros diverses d'utilisation de ptrace (PTRACE_ATTACH, ...) avec vérification d'erreurs
long attach(int pid);
long cont(int pid);
long getregs(int pid, void* data);
long setregs(int pid, void* data);

// Recuperation via nm de l'adresse d'une fonction
uint get_fun_addr(char* pid, char* fun);

// write instruction at the beginning of a function, erasing what is already there
unsigned char* write_at_function(char* pid, uint fun_addr, unsigned char* text, int length);
unsigned char* write_in_file(char* file_addr, uint pos, unsigned char* text, int length);

#endif
