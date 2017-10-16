#pragma once

#include <alchemy_defs.h>
#include <string>
#include <vector>

#ifdef _WIN32
#include <Windows.h>

#endif

FAIL_IF(throw, runtime_error)
ENTRY_POINT
static std::vector<unsigned char> get_file(const std::string& path) {
  std::vector<unsigned char> buf;

  try {
    auto hf = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL);
    if (INVALID_HANDLE_VALUE == hf)
      throw std::runtime_error("[x] Failed to open!");

    auto size = GetFileSize(hf, nullptr);

    buf.resize(size);

    DWORD dwBytes = 0;
    if(!ReadFile(buf.data(), size, &dwBytes, nullptr) || 0 == dwBytes) {
      CloseHandle(hf);
      throw std::runtime_error("[x] Failed to read!");
    }
  } catch(...) {
    throw std::runtime_error("[x] Operation failed!");
  }

  CloseHandle(hf);
  return buf;
}
