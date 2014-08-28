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
#define ERROR_RELOCATION_TOO_FAR 9

// TODO: enable some of these only in debug mode

// Proof that macros lead to bad stuffs

/**
 * Print a debug message to the standard output.
 *
 * @param format format string for the debug message.
 *
 * @return amount of written characters.
 */
#define DBG_MSG(format, ...) printf("[%s:%d] " format "\n", __FILE__, \
				    __LINE__, ##__VA_ARGS__ )

/**
 * Check a condition and fail with an error in case it's false.
 *
 * @param condition condition to check.
 * @param ret value to return in case of failure.
 */
#define CHECK_ARGS_RET(condition, ret) \
  do { \
    if (!(condition)) { \
      DBG_MSG("Bad arguments."); \
      return (ret); \
    } \
  } while(0)

/**
 * Check a condition and return ERROR_BAD_ARGS in case of failure.
 *
 * @param condition condition to check.
 */
#define CHECK_ARGS(condition) CHECK_ARGS_RET(condition, ERROR_BAD_ARGS)

/**
 * Check an expression, if it's different from SUCCESS return NULL.
 *
 * @param expression expression to check.
 *
 * @note Using this macro leads to loss of information on the error.
 */
#define RETURN_NULL_ON_ERROR(expression)  \
  do { \
    if ((expression) != SUCCESS) { \
      return NULL; \
    } \
  } while (0)

/**
 * Check an expression, if it's different from SUCCESS perform the
 * specified action.
 *
 * @param expression expression to check.
 * @param action action to perform in case of failure.
 */
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

/**
 * Checks an expression, if it's different from SUCCESS return the
 * `result` variable.
 *
 * @param expression expression to check.
 *
 * @note Assumes a "result" variable has been declared.
 */
#define RETURN_ON_ERROR(expression) ON_ERROR(expression, return result)

/**
 * Checks an expression, if it's different from SUCCESS goto the
 * `fail` label.
 *
 * @param expression expression to check.
 *
 * @note Also assumes in the function there's a "fail" label.
 */
#define FAIL_ON_ERROR(expression) ON_ERROR(expression, goto fail)

/**
 * Produce a pair of its string parameter and its length.
 *
 * @param str a constant string.
 *
 * @return a string-size pair.
 */
#define STR_PAR(str) (str), (sizeof(str))
