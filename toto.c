#include <stdio.h>
#include <stdlib.h>

int posix_memalign(void **memptr, size_t alignment, size_t size);

int foo(int n) {
  // appel à bar
  printf("foo %d\n", n);
  return n;
}

int bar(int* p) {
  printf("bar %d\n", *p);
  return *p;
}

int main() {
  int n = 0;
  while (1) {
    foo(n);
    n++;
  }
  return 0;
}
