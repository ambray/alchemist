#pragma once

#include <alchemy_defs.h>
#include <vector>
#include <string>

#ifdef _WIN32

#include <Windows.h>
#include <winhttp.h>

#pragma comment(lib, "Winhttp.lib")

#else

#endif


class winhttp {
private:
    HINTERNET session_;
    HINTERNET connect_;
    HINTERNET request_;
public:
    winhttp(const std::wstring& url, unsigned short port=80, const std::wstring& path=L"/") {
        if (nullptr == (session_ = WinHttpOpen(nullptr, 0, nullptr, nullptr, 0))) {
            throw std::runtime_error("[x] Failed to open!");
        }

        if (nullptr == (connect_ = WinHttpConnect(session_, url.c_str(), port, 0))) {
            throw std::runtime_error("[x] Failed to connect!");
        }

        if (nullptr == (request_ = WinHttpOpenRequest(connect_, L"POST", path.c_str(), nullptr, nullptr, nullptr, 0))) {
            throw std::runtime_error("[x] Failed to open request!");
        }

    }

    bool send(const std::vector<unsigned char>& data) {
        if (!WinHttpSendRequest(request_, L"content-type:application/x-www-form-urlencoded", (DWORD)-1, (void*)data.data(), static_cast<DWORD>(data.size()), static_cast<DWORD>(data.size()), 0)) {
            return false;
        }

        return true;
    }


    std::vector<unsigned char> recv() {
        std::vector<unsigned char> buf;
        DWORD bytes_avail = 0;
        DWORD bytes_read = 0;

        if (!WinHttpReceiveResponse(request_, nullptr)) {
            throw std::runtime_error("[x] Failed to recv!");
        }


        if (!WinHttpQueryDataAvailable(request_, &bytes_avail)) {
            throw std::runtime_error("[x] Failed to query!");
        }

        buf.resize(bytes_avail);


        if (!WinHttpReadData(request_, (void*)buf.data(), bytes_avail, &bytes_read)) {
            throw std::runtime_error("[x] Failed to read!");
        }

        return buf;
    }

    ~winhttp() {
        if (request_)
            WinHttpCloseHandle(request_);
        if (connect_)
            WinHttpCloseHandle(connect_);
        if (session_)
            WinHttpCloseHandle(session_);
    }

};


FAIL_IF(throw, runtime_error)
ENTRY_POINT
std::vector<unsigned char> send_message(const std::string& url, const std::vector<unsigned char>& data) {
    winhttp http(url);

    if(!http.send(data))
        throw std::runtime_error("[x] Send failed!");

    auto res = http.recv();

    return res;
}
