// Copyright 2026 HookMe Authors.
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include "ProHook/injectors/standard_injector.h"
#include "ProHook/utils/win_utils.h"

namespace fs = std::filesystem;

uint32_t GetProcessIdByName(const std::wstring& name) {
    uint32_t pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry = { sizeof(entry) };
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (name == entry.szExeFile) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

int main() {
    std::wstring target_name = L"notepad.exe";
    fs::path bin_dir = fs::current_path().parent_path().parent_path();
    fs::path dll_path{};

    std::wcout << L"Searching for " << target_name << L"..." << std::endl;
    uint32_t pid = GetProcessIdByName(target_name);

    if (pid == 0) {
        std::wcerr << L"Target not found. Please open Notepad." << std::endl;
        return 1;
    }
    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h_process) return 1;

    switch (prohook::utils::WinUtils::GetProcessArchitecture(h_process)) {
    case prohook::utils::ProcessArch::x64:
        dll_path = bin_dir / "x64/Release/ProHookPayload.dll";
        break;
    case prohook::utils::ProcessArch::x86:
        dll_path = bin_dir / "x86/Release/ProHookPayload.dll";
        break;
    default:
        return 1;
    }
    prohook::injectors::StandardInjector injector;
    if (injector.Inject(pid, dll_path)) {
        std::cout << "Injection successful! Check DebugView for logs." << std::endl;
    }
    else {
        std::cerr << "Injection failed. Check permissions (Admin?)." << std::endl;
    }

    return 0;
}