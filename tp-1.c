#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include "dependencies.h"

// fonction main: remplacer la première instruction d'une fonction d'un processus par un trap
int main(int argc, char **argv) {
  if (argc <= 2) {
    printf("Error: Two argument expected (process name & function name)\n");
    exit(EXIT_FAILURE);
  }

  char* pid = NULL;
  get_pid_safely(argv[1], &pid);
  uint fun_addr = get_fun_addr(pid, argv[2]);
  int pid_int = atoi(pid);

  attach(pid_int);
  waitpid(pid_int, 0, 0);

  unsigned char trap = 0xCC;
  write_at_function(pid, fun_addr, &trap, 1);

  free(pid);
  exit(EXIT_SUCCESS);
}
