#pragma once

#if defined(__clang__)
#define SET_ANNOTATION(x, ...) __attribute__((annotate(#x ## " " ## __VA_ARGS__)))
#else
#define SET_ANNOTATION(x, ...)
#endif
