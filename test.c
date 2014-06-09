#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "support.h"
#include "dl.h"

#define MAX_LIBS 32
#define MAX_LIB_SIZE (1024 * 1024)

struct {
  char *library;
  void *handle;
} libs[MAX_LIBS] = {0};
unsigned int lib_count = 0;

/**
 * Simple test function to be used by test libraries
 *
 * @param value value to print in decimal to stdout.
 */
void print(int value) {
  printf("%d\n", value);
}

/**
 * Reads from stdin a 4-byte little endian integer
 *
 * @return the read integer.
 */
int read_length() {
  unsigned int i = 0, result = 0;
  char input = 0;

  for (; i < 4; i++) {
    read(0, &input, 1);
    result |= (input & 0xff) << i * 8;
  }

  return result;
}

/**
 * Loads libraries reading them from stdin.
 *
 * @return zero, if success, non-zero otherwise.
 */
int load_libs() {
  int result = SUCCESS;

  // Read libraries from stdin
  unsigned int so_length = 0;
  while ((so_length = read_length())) {

    if (lib_count > MAX_LIBS) {
      DBG_MSG("Too many libraries, maximum is %u", MAX_LIBS);
      return -1;
    } else if (so_length > MAX_LIB_SIZE) {
      DBG_MSG("Library is too big (%u bytes), maximum is %d kB", so_length,
	      MAX_LIB_SIZE / 1024);
      return -1;
    }

    // Reserve space for the library
    libs[lib_count].library = (char *) malloc(so_length);
    DBG_MSG("Reading %u bytes at %p...", so_length, libs[lib_count].library);

    // Read the library from stdin
    unsigned char input = 0;
    for (unsigned int i = 0; i < so_length; i++) {
      read(0, &input, 1);
      libs[lib_count].library[i] = input;
    }

    // Open the library
    libs[lib_count].handle = dlopen(libs[lib_count].library, 0);
    RETURN_ON_NULL(libs[lib_count].handle);

    lib_count++;
  }

  return result;
}

/**
 * Unload the previously loaded libraries.
 *
 * @return zero, if success, non-zero otherwise.
 */
int unload_libs() {
  int result = SUCCESS;

  // Close and unload the loaded libraries
  while (lib_count --> 0) {
    RETURN_ON_ERROR(dlclose(libs[lib_count].handle));
    free(libs[lib_count].library);
  }

  return result;
}

int main() {
  int result = SUCCESS;

  RETURN_ON_ERROR(load_libs());

  // Play around with the loaded libraries
  typedef int (*myfunc_ptr)();
  myfunc_ptr myfunc = NULL;
  myfunc = dlsym(NULL, "my");

  int *libyour_variable = dlsym(NULL, "your_variable");

  printf("myfunc() == %d\n", myfunc());
  printf("your_variable == 0x%x\n", *libyour_variable);

  RETURN_ON_ERROR(unload_libs());

  DBG_MSG("Done");

  return result;
}
