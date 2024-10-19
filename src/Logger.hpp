#pragma once
#include <iostream>
#include <string>

class Logger {
public:
    enum class Level {
        SSL,
        INFO,
        WARNING,
        ERROR,
    };

    static void log(const std::string& message, Level level = Level::INFO) {
        switch (level) {
            case Level::INFO:
                std::cout << "\033[32m[INFO]\033[0m " << message << std::endl; // Green
                break;
            case Level::SSL:
                std::cout << "\033[35m[SSL]\033[0m " << message << std::endl; // Magenta
                break;
            case Level::WARNING:
                std::cout << "\033[33m[WARNING]\033[0m " << message << std::endl; // Yellow
                break;
            case Level::ERROR:
                std::cerr << "\033[31m[ERROR]\033[0m " << message << std::endl; // Red
                break;
            default:
                std::cout << "[UNKNOWN] " << message << std::endl;
        }
    }
};