#pragma once

#include <format>
#include <iostream>
#include <mutex>
#include <string>
#include <utility>
#include <Windows.h>

class CLogger
{
public:
    static auto Init() -> void
    {
        EnableVirtualTerminalProcessing();
    }
    
    template<typename... Args>
    static auto Log(std::format_string<Args...> fmt, Args&&... args) -> void
    {
        std::lock_guard lock(m_mutex);

        constexpr bool bIsDebugBuild =
#ifdef _DEBUG
            true;
#else
                false;
#endif

        const std::string fmtString = std::format(fmt, std::forward<Args>(args)...);
        
        if constexpr(bIsDebugBuild)
        {
            std::cout << BRIGHT_YELLOW << "[DEBUG] " << RESET << fmtString << '\n';
        }
        else
        {
            std::cout << BRIGHT_GREEN << "[RELEASE] " << RESET << fmtString << '\n';
        }
    }

private:
    static auto EnableVirtualTerminalProcessing() -> void
    {
        DWORD dwMode = {};
        const auto hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        
        if (hOut == INVALID_HANDLE_VALUE)
        {
            return;
        }
        
        if (!GetConsoleMode(hOut, &dwMode))
        {
            return;
        }
        
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        
        SetConsoleMode(hOut, dwMode);
    }
    
    // Ярко-желтый цвет.
    static constexpr std::string_view BRIGHT_YELLOW = "\x1B[93m";
    // Ярко-зелёный цвет.
    static constexpr std::string_view BRIGHT_GREEN  = "\x1B[92m";
    
    // Ресет.
    static constexpr std::string_view RESET         = "\x1B[0m";
    
    static inline std::mutex m_mutex;
};