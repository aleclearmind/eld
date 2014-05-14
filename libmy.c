static int counter = 42;
extern int your();

__attribute__((constructor))
int my() {
  int dudu = 0xDEAD;
  return your() + counter++;
}
