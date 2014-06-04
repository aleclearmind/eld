#include <stdio.h>

// Error codes
// TODO: prefix with ELD_
#define SUCCESS 0
#define ERROR_GENERIC 1
#define ERROR_BAD_ARGS 2
#define ERROR_LIB_NOT_FOUND 3
#define ERROR_OUT_OF_MEMORY 4
#define ERROR_UNEXPECTED_FORMAT 5
#define ERROR_WEAK_RESULT 6
#define ERROR_SYMBOL_NOT_FOUND 7
#define ERROR_UNKNOWN_RELOCATION_TYPE 8

// TODO: enable some of these only in debug mode

// Proof that macros lead to bad stuffs
#define DBG_MSG(format, ...) printf("[%s:%d] " format "\n", __FILE__, __LINE__, \
    ##__VA_ARGS__ )

#define CHECK_ARGS_RET(condition, ret) \
  do { \
    if (!(condition)) { \
      DBG_MSG("Bad arguments."); \
      return (ret); \
    } \
  } while(0)

#define CHECK_ARGS(condition) CHECK_ARGS_RET(condition, ERROR_BAD_ARGS)

// Using this macro leads to loss of information on the error
#define RETURN_NULL_ON_ERROR(expression)  \
  do { \
    if ((expression) != SUCCESS) { \
      return NULL; \
    } \
  } while (0)

#define ON_ERROR(expression, action) \
  do { \
    if ((result = (expression)) != SUCCESS) { \
      action; \
    } \
  } while (0)
#define RETURN_ON_NULL(expression) \
  do { \
    if (!(expression)) return ERROR_GENERIC; \
  } while(0)

// Assumes a "result" variable has been declared
#define RETURN_ON_ERROR(expression) ON_ERROR(expression, return result)

// Also assumes in the function there's a "fail" label
#define FAIL_ON_ERROR(expression) ON_ERROR(expression, goto fail)

#define STR_PAR(str) (str), (sizeof(str))
