#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include "dependencies.h"
#include "tp-2.h"

int main(int argc, char **argv) {
  if (argc <= 3) {
    printf("Error: Three argument expected (process name, function name, text)\n");
    exit(EXIT_FAILURE);
  }

  char *pid = NULL;
  get_pid(argv[1], &pid);

  attach(atoi(pid));
  waitpid(atoi(pid), 0, 0);


  char addr_maps[strlen("/proc/") + strlen(pid) + strlen("/maps") + 1];
  sprintf(addr_maps, "/proc/%s/maps", pid);

  char find_libc[strlen("cat /proc/" + strlen(pid) + strlen("/maps | grep r-xp | grep libc"))];
  sprintf(find_libc, "cat /proc/%s/maps | grep r-xp | grep libc", pid);
  FILE *fh_libc = popen(find_libc, "r");
  if (fh_libc == NULL) {
    exit(EXIT_FAILURE);
  }

  char* line = NULL;
  size_t length;

  ssize_t read_libc = getline(&line, &length, fh_libc);

  uint start_libc;
  char* leftovers;
  char* addr_libc;
  sscanf(line, "%x-%s/usr%s", &start_libc, leftovers, addr_libc);

  printf("start_libc: %x\n, /usr%s", start_libc, addr_libc);

  int addr_memalign;
  int addr_mprotect;

  char find_funcs[strlen("nm /usr") + strlen(addr_libc)];
  sprintf(find_funcs, "nm /usr%s", addr_libc);
  FILE *fh_funcs = popen(find_funcs, "r");
  if (fh_funcs == NULL) {
    exit(EXIT_FAILURE);
  }
  size_t len;

  long fun_addr0;
  char type0;
  char symbol0[64]; // a ameliorer

  if (fh_funcs == NULL) {
    exit(EXIT_FAILURE);
  }

  char* fun;
  for (ssize_t read = getline(&fun, &len, fh_funcs); read != -1; read = getline(&fun, &len, fh_funcs)) {
    fun[read - 1] = 0;
    sscanf(fun, "%lx %c %s", &fun_addr0, &type0, symbol0);
    if (strcmp(symbol0, "posix_memalign") == 0) {
      addr_memalign = fun_addr0;
    }
    if (strcmp(symbol0, "mprotect") == 0) {
      addr_mprotect = fun_addr0;
    }
  }

  // récupérer la taille d'une page via getpagesize
  int pagesize = getpagesize();




  // Utiliser le challenge 2 pour appeler posix_memalign(p, pagesize, espace qu'on veut (128 octets par exemple))
  uint target_addr = get_fun_addr(pid, argv[2]);
  uint intruder_addr = addr_memalign;

  // rajout des instructions d'appel de fonction
  unsigned char trapcalltrap[7] = {0xCC, 0xFF, 0xD0, 0xCC, 0xFF, 0xD0, 0xCC};
  unsigned char* sauvegarde;
  sauvegarde = write_at_function(pid, target_addr, trapcalltrap, 7);

  cont(atoi(pid));
  waitpid(atoi(pid), 0, 0);

  struct user_regs_struct data;
  getregs(atoi(pid), &data);
  ulong emplacement = data.rsp - sizeof(void*);

  // insertion des données que l'on va appeler dans la fonction
  char addr[strlen("/proc/") + strlen(pid) + strlen("/mem") + 1];
  sprintf(addr, "/proc/%s/mem", pid);
  void* result_ptr;
  free(write_in_file(addr, emplacement, (unsigned char*) result_ptr, sizeof(void*)));

  // modification des valeurs des registres
  struct user_regs_struct sauvegarde_data;
  memcpy(&sauvegarde_data, &data, sizeof(struct user_regs_struct));


  // mise à jour des registres pour appeler la fonction intrus
  data.rax = intruder_addr;
  data.rsp = emplacement;

  data.rdi = emplacement; // premier argument: &result_ptr
  data.rsi = pagesize; // deuxième argument:
  data.rdx = 128; // troisième argument: (taille du texte écrit)
  setregs(atoi(pid), &data);
  cont(atoi(pid));

  waitpid(atoi(pid), 0, 0);

  result_ptr = *((void **) data.rax);

  // récupération de l'état initial du programme
  setregs(atoi(pid), &sauvegarde_data);




  // Utiliser le challenge 2 pour appeler mprotect sur le pointeur p
  uint protect_intruder_addr = addr_mprotect;
  // rajout des instructions d'appel de fonction
  getregs(atoi(pid), &data);
  // modification des valeurs des registres
  memcpy(&sauvegarde_data, &data, sizeof(struct user_regs_struct));

  // mise à jour des registres pour appeler la fonction intrus
  data.rax = protect_intruder_addr;
  data.rdi = (long long unsigned int) result_ptr; // premier argument: result_ptr
  data.rsi = sizeof(void *); // deuxième argument: sizeof(void *)
  data.rdx = PROT_READ && PROT_WRITE && PROT_EXEC; // troisième argument: premissions
  setregs(atoi(pid), &data);
  cont(atoi(pid));
  waitpid(atoi(pid), 0, 0);

  // récupération de l'état initial du programme
  setregs(atoi(pid), &sauvegarde_data);


  // TODO: Écrire le code cache à l'emplacement pointé
  write_in_file(addr, (unsigned int) result_ptr, argv[3], strlen(argv[3]));




  free(write_at_function(pid, target_addr, sauvegarde, 7));
  free(sauvegarde);
  cont(atoi(pid));
  free(pid);
  return 0;
}
