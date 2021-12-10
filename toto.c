#include <stdio.h>

int foo(int n) {
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
