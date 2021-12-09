#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc <= 3) {
    printf(
        "Error: Three argument expected (process name & 2 function names)\n");
    exit(EXIT_FAILURE);
  }

  char *pid = NULL;

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
  long trace1 = ptrace(PTRACE_ATTACH, atoi(pid), 0, 0);
  if (trace1 != 0) {
    printf("Error: ptrace attach did not succeed (%ld)\n", trace1);
    exit(EXIT_FAILURE);
  }
  waitpid(atoi(pid), 0, 0);

  char *fun = NULL;
  long fun_addr;

  {
    char cmd[strlen("nm /proc/" + strlen(pid) + strlen("/exe"))];
    sprintf(cmd, "nm /proc/%s/exe", pid);
    FILE *fh = popen(cmd, "r");
    size_t len;

    char type;
    char symbol[64]; // a ameliorer

    if (fh == NULL) {
      exit(EXIT_FAILURE);
    }

    for (ssize_t read = getline(&fun, &len, fh); read != -1;
         read = getline(&fun, &len, fh)) {
      fun[read - 1] = 0;
      sscanf(fun, "%lx %c %s", &fun_addr, &type, symbol);
      if (strcmp(symbol, argv[2]) == 0) {
        break;
      }
    }
  }

  char *fun_owo = NULL;
  uint fun_addr_owo;

  {
    char cmd[strlen("nm /proc/" + strlen(pid) + strlen("/exe"))];
    sprintf(cmd, "nm /proc/%s/exe", pid);
    FILE *fh = popen(cmd, "r");
    size_t len;

    char type;
    char symbol[64]; // a ameliorer

    if (fh == NULL) {
      exit(EXIT_FAILURE);
    }

    for (ssize_t read = getline(&fun_owo, &len, fh); read != -1;
         read = getline(&fun_owo, &len, fh)) {
      fun_owo[read - 1] = 0;
      sscanf(fun_owo, "%x %c %s", &fun_addr_owo, &type, symbol);
      if (strcmp(symbol, argv[3]) == 0) {
        break;
      }
    }
  }

  printf("addr 1: %lx\n", fun_addr);
  printf("addr 2: %x\n", fun_addr_owo);

  char addr[strlen("/proc/") + strlen(pid) + strlen("/mem") + 1];
  sprintf(addr, "/proc/%s/mem", pid);
  FILE *fh = fopen(addr, "r+");
  if (!fh) {
    fprintf(stdout, "Error : %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
  printf("fh: %p\n", fh);

  // trapping
  int fsee = fseek(fh, fun_addr, SEEK_SET);
  if (fsee != 0) {
    printf("error fseek\n");
    exit(EXIT_FAILURE);
  }
  long fte = ftell(fh);
  printf("ftell: %lx\n", fte);

  // premier remplacement ici
  char sauvegarde[4];
  int frea = fread(sauvegarde, 1, 4, fh);
  if (frea != 4) {
    perror("Error fread : ");
    exit(1);
  }
  int fsee4 = fseek(fh, fun_addr, SEEK_SET);
  if (fsee4 != 0) {
    printf("error fseek\n");
    exit(EXIT_FAILURE);
  }
  char trapcalltrap[4] = {0xCC, 0xFF, 0xD0, 0xCC};
  int fwri = fwrite(trapcalltrap, 1, 4, fh);
  if (fwri != 4) {
    perror("Error fwrite : ");
    exit(1);
  }
  fclose(fh);

  printf("Wrote trap, call, trap\n");

  long trace4 = ptrace(PTRACE_CONT, atoi(pid), 0, 0);
  if (trace4 != 0) {
    printf("Error: ptrace cont did not succeed (%ld)\n", trace4);
    printf("%d\n", errno);
    exit(EXIT_FAILURE);
  }

  waitpid(atoi(pid), 0, 0);

  printf("arret sur le trap\n");

  struct user_regs_struct data;

  long trace2 = ptrace(PTRACE_GETREGS, atoi(pid), 0, &data);
  if (trace2 != 0) {
    printf("Error: ptrace getregs did not succeed (%ld)\n", trace2);
    printf("%d\n", errno);
    exit(EXIT_FAILURE);
  }

  printf("a priori we succeeded the getregging uwu\n");

  ulong emplacement = data.rsp - sizeof(int);

  FILE *fh2 = fopen(addr, "r+");
  if (!fh2) {
    fprintf(stdout, "Error : %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
  printf("fh2: %p\n", fh2);

  int fsee2 = fseek(fh2, emplacement, SEEK_SET);
  if (fsee2 != 0) {
    printf("error fseek\n");
    exit(EXIT_FAILURE);
  }

  // deuxieme remplacement ici
  int sauvegarde2[4];
  int read_sauvegarde_pointeur = fread(sauvegarde2, sizeof(int), 1, fh);
  if (read_sauvegarde_pointeur != 1) {
    perror("Error fread : ");
    exit(1);
  }
  int fsee5 = fseek(fh, emplacement, SEEK_SET);
  if (fsee5 != 0) {
    printf("error fseek\n");
    exit(EXIT_FAILURE);
  }
  int fortytwo[1] = {42};
  int fwri2 = fwrite(fortytwo, sizeof(int), 1, fh2);
  if (fwri2 != 1) {
    perror("Error fwrite : ");
    exit(1);
  }

  fclose(fh2);

  printf("emplacement: %x\n", emplacement);

  // troisième remplacement ici
  struct user_regs_struct sauvegarde_data;
  memcpy(&sauvegarde_data, &data, sizeof(struct user_regs_struct));
  // sauvegarde_rax = data.rax;
  // sauvegarde_rdi = data.rdi;
  // sauvegarde_rsp = data.rsp;
  // sauvegarde_rip = data.rip;

  data.rax = fun_addr_owo;
  data.rdi = emplacement;
  data.rsp = emplacement;

  long trace3 = ptrace(PTRACE_SETREGS, atoi(pid), 0, &data);
  if (trace3 != 0) {
    printf("Error: ptrace getregs did not succeed (%ld)\n", trace3);
    printf("%d\n", errno);
    exit(EXIT_FAILURE);
  }

  printf("a priori we succeeded the setregging ! uwu\n");

  long trace5 = ptrace(PTRACE_CONT, atoi(pid), 0, 0);
  if (trace5 != 0) {
    printf("Error: ptrace cont did not succeed (%ld)\n", trace4);
    printf("%d\n", errno);
    exit(EXIT_FAILURE);
  }

  waitpid(atoi(pid), 0, 0);

  // Attente sur le deuxième trap
  FILE *fh3 = fopen(addr, "r+");
  if (!fh3) {
    fprintf(stdout, "Error : %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
  int fsee3 = fseek(fh3, fun_addr, SEEK_SET);
  if (fsee3 != 0) {
    printf("error fseek\n");
    exit(EXIT_FAILURE);
  }
  int fwri3 = fwrite(sauvegarde, 1, 4, fh2);
  if (fwri3 != 4) {
    perror("Error fwrite : ");
    exit(1);
  }
  fclose(fh3);

  FILE *fh4 = fopen(addr, "r+");
  if (!fh4) {
    fprintf(stdout, "Error : %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
  int fsee6 = fseek(fh4, emplacement, SEEK_SET);
  if (fsee6 != 0) {
    printf("error fseek\n");
    exit(EXIT_FAILURE);
  }
  int fwri4 = fwrite(sauvegarde2, sizeof(int), 1, fh4);
  if (fwri4 != 1) {
    perror("Error fwrite : ");
    exit(1);
  }
  fclose(fh4);

  long trace7 = ptrace(PTRACE_GETREGS, atoi(pid), 0, &data);
  if (trace7 != 0) {
    printf("Error: ptrace getregs did not succeed (%ld)\n", trace2);
    printf("%d\n", errno);
    exit(EXIT_FAILURE);
  }

  // data.rax = sauvegarde_rax;
  // data.rdi = sauvegarde_rdi;
  // data.rsp = sauvegarde_rsp;
  // data.rip = sauvegarde_rip;

  long trace8 = ptrace(PTRACE_SETREGS, atoi(pid), 0, &sauvegarde_data);
  if (trace8 != 0) {
    printf("Error: ptrace getregs did not succeed (%ld)\n", trace3);
    printf("%d\n", errno);
    exit(EXIT_FAILURE);
  }

  long trace9 = ptrace(PTRACE_CONT, atoi(pid), 0, 0);
  if (trace9 != 0) {
    printf("Error: ptrace cont did not succeed (%ld)\n", trace1);
    exit(EXIT_FAILURE);
  }
  waitpid(atoi(pid), 0, 0);

  exit(EXIT_SUCCESS);

  return 0;
}
