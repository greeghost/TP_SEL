#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <errno.h>
#include "dependencies.h"


// Récupération via pgrep du pid du processus de nom procname, et rangement à l'adresse pid
void get_pid(char* procname, char** pid) {
  char cmd[strlen("pgrep ") + strlen(procname)];
  sprintf(cmd, "pgrep %s", procname);

  FILE *fh = popen(cmd, "r");
  if (fh == NULL) {
    exit(EXIT_FAILURE);
  }
  size_t len;
  ssize_t read;

  read = getline(pid, &len, fh);
  (*pid)[read - 1] = 0; // enlèvement du \n à la fin
}


// Attachement à un processus via ptrace(PTRACE_ATTACH, ...)
long attach(int pid) {
  long trace = ptrace(PTRACE_ATTACH, pid, 0, 0);
  if (trace != 0) {
    perror("Error: ptrace attach did not succeed:");
    exit(EXIT_FAILURE);
  }
  return trace;
}

long cont(int pid) {
  long trace = ptrace(PTRACE_CONT, pid, 0, 0);
  if (trace != 0) {
    perror("Error: ptrace cont did not succeed:");
    exit(EXIT_FAILURE);
  }
  return trace;
}

long getregs(int pid, void* data) {
  long trace = ptrace(PTRACE_GETREGS, pid, 0, data);
  if (trace != 0) {
    perror("Error: ptrace cont did not succeed:");
    exit(EXIT_FAILURE);
  }
  return trace;
}

long setregs(int pid, void* data) {
  long trace = ptrace(PTRACE_SETREGS, pid, 0, data);
  if (trace != 0) {
    perror("Error: ptrace cont did not succeed:");
    exit(EXIT_FAILURE);
  }
  return trace;
}



// Recuperation via nm de l'adresse d'une fonction
uint get_fun_addr(char* pid, char* fun) {
  char cmd[strlen("nm /proc/") + strlen(pid) + strlen("/exe")];
  sprintf(cmd, "nm /proc/%s/exe", pid);

  size_t len;
  uint fun_addr;
  char type;
  char symbol[64];
  char* buff = NULL;

  FILE *fh = popen(cmd, "r");
  if (fh == NULL) {
    exit(EXIT_FAILURE);
  }

  for (ssize_t read = getline(&buff, &len, fh); read != -1; read = getline(&buff, &len, fh)) {
    buff[read - 1] = 0;
    sscanf(buff, "%x %c %s", &fun_addr, &type, symbol);
    if (strcmp(symbol, fun) == 0) {
      break;
    }
  }
  // on renvoit la dernière adresse trouvée si on n'a pas trouvé la fonction
  return fun_addr;
}

unsigned char* write_in_file(char* file_addr, uint pos, unsigned char* text, int length) {
  FILE* fh = fopen(file_addr, "r+");
  if (!fh) {
    perror("Error when opening file");
    exit(EXIT_FAILURE);
  }

  fseek(fh, pos, 0);

  unsigned char* sauvegarde = malloc(length * sizeof(unsigned char));

  fread(sauvegarde, 1, length, fh);
  fseek(fh, pos, 0);
  fwrite(text, 1, length, fh);
  fclose(fh);
  return sauvegarde;
}

unsigned char* write_at_function(char* pid, uint fun_addr, unsigned char* text, int length) {
  char addr[strlen("/proc/") + strlen(pid) + strlen("/mem") + 1];
  sprintf(addr, "/proc/%s/mem", pid);

  return write_in_file(addr, fun_addr, text, length);
}
