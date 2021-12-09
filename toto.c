#include <stdio.h>
#include <stdlib.h>

int posix_memalign(void **memptr, size_t alignment, size_t size);

int foo(int n) {
  // appel à bar
  printf("foo %d, %p\n", n, foo);
  return n;
}

int bar(int* p) {
  printf("pointeur: %p\n", p);
  printf("bar %d\n", *p);
  return *p;
}

int main() {
  int n = 0;
  // int q = 42;
  // int* p = &q;
  while (1) {
    foo(n);
    n++;
  }
  return 0;
}
