#pragma once
#include <string_view>

// Магия: заставляем компилятор засунуть файл в бинарник
asm(".section .rodata\n"
	".global airmon_start\n"
	".type airmon_start, @object\n"
	"airmon_start:\n"
	".incbin \"../../scripts/airmon-ng\"\n" // ПУТЬ К ТВОЕМУ СКРИПТУ
	".byte 0\n" // Нуль-терминатор, чтобы строка не «поплыла»
	".global airmon_end\n"
	"airmon_end:\n"
	".section .text\n");

// Объявляем переменные, которые создали в ассемблере
extern "C" char airmon_start;
extern "C" char airmon_end;

// Теперь у тебя есть готовая строка
namespace Bash
{
inline std::string_view get_airmon_script()
{
	size_t size = (&airmon_end - &airmon_start);
	return std::string_view(&airmon_start, size);
}
} // namespace Bash