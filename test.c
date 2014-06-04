#include <stdio.h>
#include "support.h"
#include "dl.h"

// Test libraries
#include "libmy.so.h"
#include "libyour.so.h"

int main() {
  int result = SUCCESS;

  // Initialize the ELD library
  RETURN_ON_ERROR(eld_init());

  // Load libraries
  void *libyour_handle = NULL;
  RETURN_ON_NULL(libyour_handle = dlopen((char *) libyour_so, 0));

  void *libmy_handle = NULL;
  RETURN_ON_NULL(libmy_handle = dlopen((char *) libmy_so, 0));

  typedef int (*myfunc_ptr)();
  myfunc_ptr myfunc = NULL;
  myfunc = dlsym(NULL, "my");

  int *libyour_variable = dlsym(NULL, "your_variable");

  printf("myfunc() == %d\n", myfunc());
  printf("your_variable == 0x%x\n", *libyour_variable);

  // Close the loaded libraries
  RETURN_ON_ERROR(dlclose(libmy_handle));
  RETURN_ON_ERROR(dlclose(libyour_handle));

  // Finalize the ELD library
  RETURN_ON_ERROR(eld_finish());

  return result;
}
