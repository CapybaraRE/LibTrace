#include <thread>

#include "CFileParser/CLibFileParser.hpp"

// https://learn.microsoft.com/ru-ru/windows/win32/debug/pe-format#section-table-section-headers

// При сборке .lib файла нужно отключить параметр "Оптимизация всей программы". Это самое важное условие!!!!!!!!!!!!!!!!
// Пример запуска: NewIdenLib.exe "D:\Rider_Projects\TestLibForIdenLib\x64\Release\TestLibForIdenLib.lib" "D:\temp".

//Todo list:
// 1. Обновить Zydis.
// 2. Добавить парсер .pdb файла с последующим анализом PE файла и получением сигнатур. На случай реализации всей логики в .hpp файлах.

int main(const int argc, char* argv[])
{
    CLogger::Init();
    
    CLogger::Log("New impl of IdenLib.\n");
    
#ifdef _DEBUG
    constexpr auto TEST_FILE = R"(D:\Rider_Projects\NewIdenLib\NewIdenLib\json.lib)";
    //constexpr auto TEST_FILE = R"(D:\Rider_Projects\NewIdenLib\NewIdenLib\TestLibForIdenLib.lib)";

    constexpr auto TEST_OUT  = R"(D:\Rider_Projects\NewIdenLib\NewIdenLib)";

    const std::filesystem::path target = TEST_FILE;
    const std::filesystem::path output = TEST_OUT;
#else
    if (argc != 3)
    {
        CLogger::Log(R"(Usage: NewIdenLib.exe "path_to_input.lib" "path_to_output_dir".)");
        CLogger::Log("Processing finished. Exiting in 10 seconds...");

        std::this_thread::sleep_for(std::chrono::seconds(10));
        
        return 1;
    }

    const std::string target = argv[1];
    const std::string output = argv[2];
#endif
    
    CLibFileParser::ParseFile(target, output);
    
    CLogger::Log( "Processing finished. Exiting in 10 seconds...\n");
    
    std::this_thread::sleep_for(std::chrono::seconds(10));
    
    return 0;
}
