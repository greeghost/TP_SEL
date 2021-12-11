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
#include "dependencies.h"

int main(int argc, char **argv) {
  if (argc <= 3) {
    printf(
        "Error: Three argument expected (process name & 2 function names)\n");
    exit(EXIT_FAILURE);
  }

  char* pid = NULL;
  get_pid(argv[1], &pid);

  attach(atoi(pid));
  waitpid(atoi(pid), 0, 0);

  uint target_addr = get_fun_addr(pid, argv[2]);
  uint intruder_addr = get_fun_addr(pid, argv[3]);

  // rajout des instructions d'appel de fonction
  unsigned char trapcalltrap[4] = {0xCC, 0xFF, 0xD0, 0xCC};
  unsigned char* sauvegarde;
  sauvegarde = write_at_function(pid, target_addr, trapcalltrap, 4);

  cont(atoi(pid));
  waitpid(atoi(pid), 0, 0);

  struct user_regs_struct data;
  getregs(atoi(pid), &data);
  ulong emplacement = data.rsp - sizeof(int);

  // insertion des données que l'on va appeler dans la fonction
  unsigned char* sauvegarde2;
  char addr[strlen("/proc/") + strlen(pid) + strlen("/mem") + 1];
  sprintf(addr, "/proc/%s/mem", pid);
  int fortytwo[1] = {42};
  sauvegarde2 = write_in_file(addr, emplacement, (unsigned char*) fortytwo, sizeof(int));

  // modification des valeurs des registres
  struct user_regs_struct sauvegarde_data;
  memcpy(&sauvegarde_data, &data, sizeof(struct user_regs_struct));


  // mise à jour des registres pour appeler la fonction intrus
  data.rax = intruder_addr;
  data.rdi = emplacement;
  data.rsp = emplacement;
  setregs(atoi(pid), &data);
  cont(atoi(pid));

  waitpid(atoi(pid), 0, 0);

  // récupération de l'état initial du programme
  free(write_at_function(pid, target_addr, sauvegarde, 4));
  free(sauvegarde);
  free(write_in_file(addr, emplacement, sauvegarde2, 1));
  free(sauvegarde2);
  setregs(atoi(pid), &sauvegarde_data);

  cont(atoi(pid));
  free(pid);

  printf("done!\n");

  return 0;
}
