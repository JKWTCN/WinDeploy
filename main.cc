#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include "console_utils.h"
#include "pe_parser.h"
#include "dll_analyzer.h"
#include "file_operations.h"
#include "config_loader.h"

int main(int argc, char *argv[])
{
    if (argc < 2 || argc > 10)
    {
        std::cout << "Usage: " << argv[0] << " <executable_path> [options]" << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "  --release [depth]     Release mode: recursively analyze dependencies (default depth: 2)" << std::endl;
        std::cout << "                         and copy DLLs to the executable's directory" << std::endl;
        std::cout << "  --recursive [depth]   Recursively analyze all DLL dependencies (default depth: 20)" << std::endl;
        std::cout << "  --copy <target_dir>   Copy dependent DLLs to specified directory" << std::endl;
        std::cout << "  --copy-exe-dir        Copy dependent DLLs to the executable's directory" << std::endl;
        std::cout << "  --copy-all            Copy all DLLs including system core DLLs" << std::endl;
        std::cout << "  --search-dirs <file>  Load additional search directories from file (one directory per line)" << std::endl;
        std::cout << "  --ignore-dll <file>   Load ignore list from file (DLL names, paths, or directories)" << std::endl;
        std::cout << "\nExamples:" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --release" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --release 3" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --recursive" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --recursive 10" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --recursive --copy C:\\DestDir" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --copy-exe-dir" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --copy-exe-dir --copy-all" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --search-dirs test_path.txt" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --release --ignore-dll ignore.txt" << std::endl;
        std::cout << "  " << argv[0] << " C:\\Path\\To\\YourApp.exe --release --search-dirs test_path.txt --ignore-dll ignore.txt" << std::endl;
        std::cout << "\nNote: When using --recursive with --copy, all dependencies at all levels will be copied." << std::endl;
        std::cout << "      By default, system core DLLs will be skipped during copy." << std::endl;
        std::cout << "      Use --copy-all to include system core DLLs." << std::endl;
        std::cout << "      The --search-dirs file should contain one directory path per line." << std::endl;
        std::cout << "      Lines starting with # or ; are treated as comments and ignored." << std::endl;
        std::cout << "      The --ignore-dll file can contain DLL names, DLL paths, or directory paths." << std::endl;
        std::cout << "      --release mode is equivalent to --recursive 2 --copy-exe-dir" << std::endl;
        return 1;
    }

    auto exe_path = argv[1];
    bool copyMode = false;
    bool recursiveMode = false;
    bool releaseMode = false;
    bool copyAllMode = false;
    std::string destDir;
    std::string searchDirsFile;
    std::string ignoreDllFile;
    std::vector<std::string> extraSearchDirs;

    // 解析命令行参数
    int argIndex = 2;
    while (argIndex < argc)
    {
        if (strcmp(argv[argIndex], "--release") == 0)
        {
            releaseMode = true;
            recursiveMode = true;
            copyMode = true;
            // 获取可执行文件所在目录作为目标目录
            destDir = std::filesystem::path(exe_path).parent_path().string();
            argIndex++;

            // 检查是否指定了递归深度
            if (argIndex < argc && argv[argIndex][0] != '-')
            {
                // 尝试解析为数字
                try
                {
                    int depth = std::stoi(argv[argIndex]);
                    if (depth <= 0)
                    {
                        std::cerr << "Error: Recursion depth must be a positive number, got: " << depth << std::endl;
                        return 1;
                    }
                    SetMaxRecursionDepth(depth);
                    std::cout << "Info: Release mode: Maximum recursion depth set to: " << depth << std::endl;
                    argIndex++;
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Error: Invalid recursion depth value: " << argv[argIndex] << std::endl;
                    return 1;
                }
            }
            else
            {
                // 使用默认值 2
                SetMaxRecursionDepth(2);
                std::cout << "Info: Release mode: Maximum recursion depth set to: 2 (default)" << std::endl;
            }
        }
        else if (strcmp(argv[argIndex], "--recursive") == 0)
        {
            recursiveMode = true;
            argIndex++;

            // 检查是否指定了递归深度
            if (argIndex < argc && argv[argIndex][0] != '-')
            {
                // 尝试解析为数字
                try
                {
                    int depth = std::stoi(argv[argIndex]);
                    if (depth <= 0)
                    {
                        std::cerr << "Error: Recursion depth must be a positive number, got: " << depth << std::endl;
                        return 1;
                    }
                    SetMaxRecursionDepth(depth);
                    std::cout << "Info: Maximum recursion depth set to: " << depth << std::endl;
                    argIndex++;
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Error: Invalid recursion depth value: " << argv[argIndex] << std::endl;
                    return 1;
                }
            }
            else
            {
                // 使用默认值 20
                SetMaxRecursionDepth(20);
            }
        }
        else if (strcmp(argv[argIndex], "--copy") == 0 && argIndex + 1 < argc)
        {
            copyMode = true;
            destDir = argv[argIndex + 1];
            argIndex += 2;
        }
        else if (strcmp(argv[argIndex], "--copy-exe-dir") == 0)
        {
            copyMode = true;
            // 获取可执行文件所在目录
            destDir = std::filesystem::path(exe_path).parent_path().string();
            argIndex++;
        }
        else if (strcmp(argv[argIndex], "--copy-all") == 0)
        {
            copyAllMode = true;
            argIndex++;
        }
        else if (strcmp(argv[argIndex], "--search-dirs") == 0 && argIndex + 1 < argc)
        {
            searchDirsFile = argv[argIndex + 1];
            extraSearchDirs = LoadExtraSearchDirectories(searchDirsFile);
            if (extraSearchDirs.empty())
            {
                std::cout << "Warning: No extra search directories loaded from: " << searchDirsFile << std::endl;
            }
            argIndex += 2;
        }
        else if (strcmp(argv[argIndex], "--ignore-dll") == 0 && argIndex + 1 < argc)
        {
            ignoreDllFile = argv[argIndex + 1];
            LoadIgnoredDLLs(ignoreDllFile);
            argIndex += 2;
        }
        else
        {
            std::cerr << "Error: Invalid command line argument: " << argv[argIndex] << std::endl;
            return 1;
        }
    }

    // 检测目标文件的架构
    ConsoleColors::PrintLn(ConsoleColors::CYAN, "=== Analyzing Target Executable ===");
    PEArchitecture targetArch = DetectPEArchitecture(exe_path);
    if (targetArch == PEArchitecture::Unknown)
    {
        std::cerr << "Error: Unable to detect PE architecture of target file" << std::endl;
        return 1;
    }
    std::cout << "Target file architecture: ";
    ConsoleColors::PrintLn(ConsoleColors::BRIGHT_GREEN, ArchitectureToString(targetArch));

    auto dlls = GetDependentDLLs(exe_path, recursiveMode, extraSearchDirs, targetArch);

    std::cout << "\n";
    ConsoleColors::PrintLn(ConsoleColors::CYAN, "=== Dependent DLL List ===");
    for (const auto &dll : dlls)
    {
        std::cout << dll << std::endl;
    }
    std::cout << "Total: ";
    ConsoleColors::PrintLn(ConsoleColors::BRIGHT_CYAN, std::to_string(dlls.size()) + " DLL(s)");

    // 如果启用了复制模式，则复制DLL文件
    if (copyMode)
    {
        std::cout << "\n";
        ConsoleColors::PrintLn(ConsoleColors::CYAN, "=== Starting to Copy DLL Files ===");
        if (CopyDependentDLLs(dlls, exe_path, destDir, extraSearchDirs, copyAllMode, targetArch))
        {
            ConsoleColors::PrintLn(ConsoleColors::GREEN, "✓ All DLL files copied successfully!");
        }
        else
        {
            ConsoleColors::PrintLn(ConsoleColors::RED, "✗ Some DLL files failed to copy, please check error messages");
            return 1;
        }
    }

    return 0;
}
