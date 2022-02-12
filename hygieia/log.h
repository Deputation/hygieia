#pragma once

#define LOGGING

#ifdef LOGGING
#define LOG(...)                  \
  DbgPrintEx(0, 0, "[Hygieia] "); \
  DbgPrintEx(0, 0, __VA_ARGS__);  \
  DbgPrintEx(0, 0, "\n");
#else
#define LOG
#endif