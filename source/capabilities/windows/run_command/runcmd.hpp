#pragma once
#ifdef _WIN32
#include <Windows.h>
#else

#endif

#include <alchemy_defs.h>
#include <string>
#include <vector>


FAIL_IF(throw, runtime_error)
ENTRY_POINT
static std::string run_command(const std::string& cmd) {
    std::string out;
    std::string tmp;
    char buf[1025] = { 0 };
    SECURITY_ATTRIBUTES sa{ 0 };
    PROCESS_INFORMATION pinf{ 0 };
    STARTUPINFOA  sinf{ 0 };
    HANDLE hOut = INVALID_HANDLE_VALUE;
    HANDLE hIn = INVALID_HANDLE_VALUE;
    HANDLE hSin = INVALID_HANDLE_VALUE;
    HANDLE hSout = INVALID_HANDLE_VALUE;

    auto cleanup = [&]() {
        CloseHandle(hOut);
        CloseHandle(hIn);

        if (INVALID_HANDLE_VALUE != hSin)
            CloseHandle(hSin);
        if (INVALID_HANDLE_VALUE != hSout)
            CloseHandle(hSout);
        if (pinf.hThread)
            CloseHandle(pinf.hThread);
        if (pinf.hProcess)
            CloseHandle(pinf.hProcess);
    };

    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sinf.cb = sizeof(sinf);

    tmp = "cmd.exe /c ";
    tmp += cmd;
    if (!CreatePipe(&hIn, &hOut, &sa, 1024)) {
        throw std::runtime_error("[x] Failed to create pipe!");
    }

    if (!SetHandleInformation(hIn, HANDLE_FLAG_INHERIT, 0)) {
        cleanup();
        throw std::runtime_error("[x] Failed to set info!");
    }

    if (!CreatePipe(&hSin, &hSout, &sa, 1024)) {
        cleanup();
        throw std::runtime_error("[x] Failed to create input pipe!");
    }

    if (!SetHandleInformation(hSout, HANDLE_FLAG_INHERIT, 0)) {
        cleanup();
        throw std::runtime_error("[x] Failed to set input info!");
    }

    sinf.hStdOutput = hOut;
    sinf.hStdError = hOut;
    sinf.hStdInput = hSin;
    sinf.dwFlags = STARTF_USESTDHANDLES;

    if (!CreateProcessA(nullptr, &tmp[0], nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &sinf, &pinf)) {
        cleanup();
        throw std::runtime_error("[x] Failed to create proc!");
    }

    DWORD dwBytes = 0;
    DWORD dwBytesAvail = 0;
    if (!ReadFile(hIn, buf, 1024, &dwBytes, nullptr) || 0 == dwBytes) {
        cleanup();
        throw std::runtime_error("[x] Failed to read data!");
    }

    out += buf;
    std::fill(std::begin(buf), std::end(buf), 0x00);
    if(!WriteFile(hSout, "\r\n", 2, &dwBytes, nullptr)){}

    while(PeekNamedPipe(hIn, nullptr, 0, nullptr, &dwBytesAvail, nullptr) && dwBytesAvail) {
        if (!ReadFile(hIn, buf, 1024, &dwBytes, nullptr) || 0 == dwBytes) 
            break;

        out += buf;
        std::fill(std::begin(buf), std::end(buf), 0x00);
    }

    cleanup();
    return out;
}
