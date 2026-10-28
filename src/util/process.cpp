#include "process.h"
#include "util/result.h"
#include "xtun.h"

#include <windows.h>

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace libxtun::process
{
    namespace
    {
        std::wstring quote(const std::wstring &arg)
        {
            if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
                return arg;
            }

            std::wstring quoted = L"\"";
            for (auto it = arg.begin();; ++it) {
                std::size_t backslashes = 0;
                while (it != arg.end() && *it == L'\\') {
                    ++it;
                    ++backslashes;
                }

                if (it == arg.end()) {
                    quoted.append(backslashes * 2, L'\\');
                    break;
                }
                quoted.append(*it == L'"' ? backslashes * 2 + 1 : backslashes, L'\\');
                quoted.push_back(*it);
            }
            quoted.push_back(L'"');
            return quoted;
        }

        std::optional<std::wstring> systemDirectory()
        {
            std::wstring directory(MAX_PATH, L'\0');
            const UINT size = ::GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
            if (size == 0 || size >= directory.size()) {
                return std::nullopt;
            }
            directory.resize(size);
            return directory;
        }
    }

    ResultXtun<int> run(const char *binary, const std::vector<std::string> &args)
    {
        const std::optional<std::wstring> directory = systemDirectory();
        if (!directory) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }

        const std::string name = binary;
        const std::wstring path = *directory + L"\\" + std::wstring(name.begin(), name.end());
        std::wstring commandLine = quote(path);
        for (const std::string &arg : args) {
            commandLine += L' ' + quote(std::wstring(arg.begin(), arg.end()));
        }

        STARTUPINFOW startup { sizeof(startup) };
        PROCESS_INFORMATION child {};
        if (!::CreateProcessW(path.c_str(), commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                              nullptr, &startup, &child)) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }
        ::CloseHandle(child.hThread);

        DWORD code = 0;
        const bool finished = ::WaitForSingleObject(child.hProcess, INFINITE) == WAIT_OBJECT_0
                && ::GetExitCodeProcess(child.hProcess, &code);
        ::CloseHandle(child.hProcess);
        if (!finished) {
            return fail(LIBXTUN_ERR_SYSTEM);
        }
        return static_cast<int>(code);
    }
}
