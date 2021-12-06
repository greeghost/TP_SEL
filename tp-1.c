#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>


void main(int argc, char **argv) {
  if (argc <= 2) {
    printf("Error: Two argument expected (process name & function name)\n");
    exit(EXIT_FAILURE);
  }

  char* pid = NULL;

  // Recuperation via pgrep du pid du processus à tracer
  {
    char cmd[strlen("pgrep " + strlen(argv[1]))];
    sprintf(cmd, "pgrep %s", argv[1]);
    FILE *fh = popen(cmd, "r");
    size_t len;
    ssize_t read;

    if (fh == NULL) {
      exit(EXIT_FAILURE);
    }

    read = getline(&pid, &len, fh);
    pid[read - 1] = 0; // virer le \n à la fin
  }


  printf("pid: %d\n", atoi(pid));
  long trace = ptrace(PTRACE_ATTACH, atoi(pid), 0, 0);
  waitpid(atoi(pid), 0, 0);


  char addr[strlen("/proc/") + strlen(pid) + strlen("/mem") + 1];
  sprintf(addr, "/proc/%s/mem", pid);
  FILE *fh = fopen(addr, "r+");
    if (!fh) {
    fprintf(stdout, "Error : %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }


  char* fun = NULL;
  uint fun_addr;

  // Recuperation via nm de l'adresse de la fonction victime du trap
  {
    char cmd[strlen("nm /proc/" + strlen(pid) + strlen("/exe"))];
    sprintf(cmd, "nm /proc/%s/exe", pid);
    FILE *fh = popen(cmd, "r");
    size_t len;

    if (fh == NULL) {
      exit(EXIT_FAILURE);
    }

    for (ssize_t read = getline(&fun, &len, fh); read != -1; read = getline(&fun, &len, fh)) {
      fun[read - 1] = 0;
      if (strcmp(fun+19, argv[2]) == 0) {
        fun[17] = 0;
        printf("addr: %s\n", fun);

        sscanf(fun, "%x", &fun_addr);
      }
    }
  }

  // trapping
  fseek(fh, fun_addr, 0);
  char trap = 0xCC;
  fwrite(&trap, 1, 1, fh);

  fclose(fh);

  exit(EXIT_SUCCESS);
}
