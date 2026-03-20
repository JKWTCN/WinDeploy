#pragma once

#include <string>
#include <iostream>
#include <windows.h>

namespace ConsoleColors
{
    enum Color
    {
        DEFAULT = 7,        // 默认白色
        GREEN = 10,         // 绿色
        RED = 12,           // 红色
        YELLOW = 14,        // 黄色
        BLUE = 9,           // 蓝色
        CYAN = 11,          // 青色
        MAGENTA = 13,       // 洋红色
        BRIGHT_GREEN = 10,  // 亮绿色
        BRIGHT_RED = 12,    // 亮红色
        BRIGHT_YELLOW = 14, // 亮黄色
        BRIGHT_BLUE = 9,    // 亮蓝色
        BRIGHT_CYAN = 11,   // 亮青色
        BRIGHT_MAGENTA = 13 // 亮洋红色
    };

    // 设置控制台文本颜色
    inline void SetColor(Color color)
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
    }

    // 重置为默认颜色
    inline void Reset()
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), DEFAULT);
    }

    // 带颜色的输出辅助函数
    inline void Print(Color color, const std::string &text)
    {
        SetColor(color);
        std::cout << text;
        Reset();
    }

    inline void PrintLn(Color color, const std::string &text)
    {
        SetColor(color);
        std::cout << text << std::endl;
        Reset();
    }
}
