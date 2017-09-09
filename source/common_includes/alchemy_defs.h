#pragma once

#if defined(__clang__)

#define SET_ANNOTATION(x, ...) __attribute__((annotate(x ## " " ## __VA_ARGS__)))

// marks a parameter as being "in out"
#define OUT_PARAM(x) __attribute__((annotate("out " ## #x)))
// In-out param that needs to be freed. Deallocate method is passed as
// dealloc_fn
#define OUT_PARAM_DEALLOC(param, dealloc_fn) __attribute__((annotate("out-dealloc " ## #param ## " " ## #dealloc_fn)))
// maps a parameter to a function to a command value. Should also be OUT_PARAM
// or OUT_PARAM_DEALLOC
#define PARAM_MAP(field, param) __attribute__((annotate("map " ## #field ## #param)))
// Marks a single entry point
#define ENTRY_POINT __attribute__((annotate("entry-point")))
// Checks to ensure the operation succeeded. Type should be "return", and 
// value should be the value to check for failure.
#define FAIL_IF(type, value) __attribute__((annotate("fail-if " ## #type ## " " ##  #value)))

#else

#define SET_ANNOTATION(x, ...)
#define OUT_PARAM(x)
#define OUT_PARAM_DEALLOC(param, dealloc_fn)
#define PARAM_MAP(field, param)
#define ENTRY_POINT

#endif
