#include <stdio.h>

static int counter = 42;
extern int your();
extern void print(int value);

__attribute__((constructor))
int my() {
  int dudu = 0xDEAD;
  return your() + counter++;
}

__attribute__((destructor))
void finalization() {
  print(counter);

  // This should be in the main executable
  printf("0x%x\n", counter);
}
