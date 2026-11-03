#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <system_error>
#include <unistd.h>
#include <vector>

// Start the local server automatically for CTest and direct executable invocations.
// Test discovery only lists tests, so it does not need a server or root privileges.
int main(int argc, char **argv)
{
    const bool serverReady = argc > 1 && std::strcmp(argv[1], "--ovpn-server-ready") == 0;
    if (serverReady) {
        for (int i = 1; i + 1 < argc; ++i) {
            argv[i] = argv[i + 1];
        }
        argv[--argc] = nullptr;
    }

    // InitGoogleTest removes its flags from argv; preserve them for the child test process.
    std::vector<std::string> testArguments(argv + 1, argv + argc);
    ::testing::InitGoogleTest(&argc, argv);
    if (serverReady || GTEST_FLAG_GET(list_tests)) {
        return RUN_ALL_TESTS();
    }

    std::error_code error;
    const auto executable = std::filesystem::read_symlink("/proc/self/exe", error);
    if (error) {
        std::fprintf(stderr, "Cannot locate the OpenVPN test executable: %s\n", error.message().c_str());
        return 1;
    }

    std::vector<std::string> command { XTUN_TEST_PYTHON_EXECUTABLE, XTUN_TEST_OVPN_SERVER_SCRIPT,
                                       XTUN_TEST_OPENVPN_EXECUTABLE, executable.string() };
    command.insert(command.end(), testArguments.begin(), testArguments.end());
    std::vector<char *> arguments;
    for (auto &argument : command) {
        arguments.push_back(argument.data());
    }
    arguments.push_back(nullptr);
    ::execv(arguments.front(), arguments.data());
    std::perror("Cannot start the local OpenVPN test server");
    return 1;
}
