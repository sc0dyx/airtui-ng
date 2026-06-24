#include <iterator>
#include <stdbool.h>
#include <stdexcept>
#include <string>
#include <sstream>
#include <string_view>
#include <vector>
#include <map>
#include <clocale>
#include <cstdio>
#include <unistd.h>
#include <array>
#include <cstring>
#include <iostream>
#include <dirent.h>
#include <sys/stat.h>
#include <fstream>
#include <cstdlib>
#include "airmon-ng.hpp"
#include <array>
#include <fstream>
#include <thread>
#include <chrono>
#include <iomanip>
#include <linux/wireless.h>
#define static
#define PCRE2_CODE_UNIT_WIDTH 8
#define HAVE_STRLCPY 1
#define HAVE_STRLCAT 1
extern "C"
{
#include <ncurses.h>
#include "../airodump-ng/airodump-ng.h"
}
#undef static

struct NetworkTarget
{
	std::string bssid = "";
	int channel = 1;
};

class AirBars
{

  protected:
	WINDOW * stdscr;
	std::vector<std::string> modes = {"TOOLS", "CRACK", "LOGS", "SETTINGS"};
	int width_modes = 2; // Отступы по бокам
	int mode = 0;
	std::string bar_str = " AIRTUI-NG ";
	int current_mode = 0;

  public:
	AirBars(WINDOW * win) : stdscr(win) {}

	// Динамическая отрисовка верхнего бара
	void draw_top_bar(int w)
	{
		// 1. Рисуем логотип (AIRTUI-NG)
		attron(A_BOLD | A_REVERSE);
		mvaddstr(0, 0, bar_str.c_str());
		attroff(A_BOLD | A_REVERSE);

		int current_pos = bar_str.length();

		// 2. Рисуем режимы (автоматический сдвиг)
		for (int i = 0; i < (int) modes.size(); ++i)
		{

			// Создаем строку с отступами
			std::string text = std::string(width_modes, ' ') + modes[i]
							   + std::string(width_modes, ' ');

			if (i == current_mode) attron(A_REVERSE);
			mvaddstr(0, current_pos, text.c_str());
			if (i == current_mode) attroff(A_REVERSE);
			current_pos += text.length();
		}

		// 3. Заполняем пустоту до конца экрана (как ljust в Python)
		attron(A_REVERSE);
		for (int i = current_pos; i < w; ++i)
		{
			mvaddch(0, i, ' ');
		}
		attroff(A_REVERSE);
	}
	void
	draw_bar(int h, int w, const std::map<std::string, std::string> & text_map)
	{
		std::string full_bar = " ";

		// Итерируемся по map (аналог dict.items() в Python)
		for (auto const & [key, action] : text_map)
		{
			full_bar += "[" + key + "] " + action + "  ";
		}

		// Включаем инверсию цвета (A_REVERSE)
		wattron(stdscr, A_REVERSE);

		// Рисуем строку в самой нижней строчке (h-1)
		mvwaddstr(stdscr, h - 1, 0, full_bar.c_str());

		// Добиваем строку пробелами до правого края (аналог .ljust(w))
		for (int i = full_bar.length(); i < w; ++i)
		{
			waddch(stdscr, ' ');
		}

		wattroff(stdscr, A_REVERSE);
	}
};

class AirTui : public AirBars
{
  private:
	// int scroll_ap = 0;
	struct NetworkTarget selectNetwork;
	struct AP_info * ap = nullptr;
	volatile bool scan_networks = false;
	volatile bool scan_network = false;
	bool mode = false;
	bool statemon = false;
	int current_row_interfaces = 0;
	int current_row_networks = 0;
	int current_column = 0;
	int count_networks = 0;
	std::string selected_interface = "";
	std::map<std::string, std::string> base_helper;
	std::thread target_capture_thread;
	std::thread capture_thread;
	struct wif * wi = nullptr;
	int fd_raw = -1;
	std::vector<int> channels = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
	int chan_index = 0;
	// Математика get_x_split (авто-расчет ширины левой панели)
	int get_x_split()
	{
		int total = bar_str.length();
		for (const auto & m : modes)
		{
			// Длина текста + отступы с двух сторон
			total += m.length() + (width_modes * 2);
		}
		return total;
	}

	const char * get_enc_str(struct AP_info * ap)
	{
		if (ap->security & AUTH_SAE) return "WPA3";
		if (ap->security & STD_WPA2) return "WPA2";
		if (ap->security & STD_WPA) return "WPA";
		if (ap->security & STD_WEP) return "WEP";
		if (ap->security & STD_OPN) return "OPN";
		return "";
	}

	const char * get_cipher_str(struct AP_info * ap)
	{
		if (ap->security & ENC_CCMP) return "CCMP";
		if (ap->security & ENC_GCMP) return "GCMP";
		if (ap->security & ENC_GMAC) return "GMAC";
		if (ap->security & ENC_TKIP) return "TKIP";
		if (ap->security & ENC_WRAP) return "WRAP";
		if (ap->security & ENC_WEP104) return "WEP104";
		if (ap->security & ENC_WEP40) return "WEP40";
		if (ap->security & ENC_WEP) return "WEP";
		return "";
	}

	const char * get_auth_str(struct AP_info * ap)
	{
		if (ap->security & AUTH_SAE) return "SAE";
		if (ap->security & AUTH_OWE) return "OWE";
		if (ap->security & AUTH_MGT) return "MGT";
		if (ap->security & AUTH_PSK) return "PSK";
		if (ap->security & AUTH_CMAC) return "CMAC";
		if (ap->security & AUTH_OPN) return "OPN";
		return "";
	}
	static std::string exec_airmon(std::string_view cmd = "",
								   bool answer_script = false)
	{
		auto script = Bash::get_airmon_script();

		if (answer_script)
		{
			// --- Путь с получением ответа (через файл) ---
			std::string temp_file = "/tmp/airmon_temp.sh";

			std::ofstream ofs(temp_file, std::ios::binary);
			ofs.write(script.data(), script.size());
			ofs.close();

			// Формируем команду: chmod + запуск. Если cmd пуст, аргументы не добавятся.
			std::string full_cmd = "chmod +x " + temp_file + " && " + temp_file;
			if (!cmd.empty())
			{
				full_cmd += " ";
				full_cmd += cmd;
				full_cmd += " > /dev/null 2>&1";
			}

			FILE * pipe = popen(full_cmd.c_str(), "r");
			if (!pipe) return "Error: popen failed";

			std::string result;
			std::array<char, 256> buffer;
			while (fgets(buffer.data(), buffer.size(), pipe) != nullptr)
			{
				result += buffer.data();
			}

			pclose(pipe);
			std::remove(temp_file.c_str());
			return result;
		}
		else
		{
			// --- Путь без ответа (напрямую в память) ---
			std::string bash_cmd = "bash -s";
			if (!cmd.empty())
			{
				bash_cmd += " -- ";
				bash_cmd += cmd;
				bash_cmd += " > /dev/null 2>&1";
			}

			FILE * pipe = popen(bash_cmd.c_str(), "w");
			if (!pipe) return "Error: popen failed";

			fwrite(script.data(), 1, script.size(), pipe);
			int status = pclose(pipe);

			return "Exit code: " + std::to_string(WEXITSTATUS(status));
		}
	}
	bool isMonitoring()
	{
		// Путь к типу сетевого интерфейса в sysfs ядра Linux
		std::string path = "/sys/class/net/" + selected_interface + "/type";
		std::ifstream file(path);

		// Если интерфейс не существует или нет прав на чтение
		if (!file.is_open())
		{
			return false;
		}

		int type = 0;
		file >> type;
		file.close();

		// 802 — ARPHRD_IEEE80211 (классический монитор)
		// 803 — ARPHRD_IEEE80211_RADIOTAP (монитор с инжекцией/радиотапом, как делает airmon-ng)
		return (type == 802 || type == 803);
	}

	// static void log_to_file(std::string_view message)
	// {
	// 	// std::ios::app — дописывает в конец, не удаляя старое
	// 	std::ofstream log_file("airmon_base.log", std::ios::app);
	//
	// 	if (log_file.is_open())
	// 	{
	// 		// Добавим метку времени для красоты (опционально)
	// 		auto now = std::chrono::system_clock::now();
	// 		auto in_time_t = std::chrono::system_clock::to_time_t(now);
	//
	// 		log_file << std::put_time(std::localtime(&in_time_t),
	// 								  "[%Y-%m-%d %H:%M:%S] ")
	// 				 << message << std::endl;
	//
	// 		log_file.close();
	// 	}
	// }

	std::string mac2str(const unsigned char mac[6])
	{
		char buf[18];
		snprintf(buf,
				 sizeof(buf),
				 "%02X:%02X:%02X:%02X:%02X:%02X",
				 mac[0],
				 mac[1],
				 mac[2],
				 mac[3],
				 mac[4],
				 mac[5]);
		return buf;
	}

  public:
	std::vector<std::string> get_wifi_interfaces()
	{
		std::vector<std::string> ifaces;

		// 1. Получаем ВЕСЬ вывод вшитого скрипта без аргументов
		std::string output = exec_airmon("", true);

		mvaddstr(10, 10, output.c_str());

		if (output.empty() || output.find("Error") == 0) return ifaces;

		// 2. Используем stringstream, чтобы читать вывод построчно
		std::stringstream ss(output);
		std::string line;
		bool header_passed = false;

		while (std::getline(ss, line))
		{
			// Пропускаем шапку таблицы
			if (line.find("PHY") != std::string::npos || line.empty())
			{
				header_passed = true;
				continue;
			}

			if (header_passed)
			{
				// Логика парсинга остается той же: ищем имя интерфейса
				size_t first_tab = line.find('\t');
				if (first_tab != std::string::npos)
				{
					std::string sub = line.substr(first_tab);
					size_t start = sub.find_first_not_of("\t ");
					size_t end = sub.find_first_of("\t ", start);
					if (start != std::string::npos)
					{
						ifaces.push_back(sub.substr(start, end - start));
					}
				}
			}
		}
		return ifaces;
	}
	void start_mon(std::string_view interface)
	{
		std::string cmd = "start ";
		cmd += interface;
		exec_airmon(cmd);
	}
	void stop_mon(std::string_view interface)
	{
		std::string cmd = "stop ";
		cmd += interface;
		exec_airmon(cmd);
	}

	void start_capture(const std::string & iface,
					   const unsigned int channel = 0)
	{
		if (scan_networks or scan_network) return;
		wi = wi_open((char *) iface.c_str());
		if (!wi)
		{
			// ошибка
			return;
		}
		if (channel == 0) wi_set_channel(wi, channel + 1); // канал по умолчанию
		if (channel > 0)
		{
			wi_set_channel(wi, channel);
			lopt.channel[0] = channel;
		}
		fd_raw = wi_fd(wi);
		if (!channel)
		{
			scan_networks = true;
		}
		else
		{
			scan_network = true;
		}
		capture_thread = std::thread(
			[this, channel]()
			{
				while (scan_networks or scan_network)
				{
					fd_set rfds;
					FD_ZERO(&rfds);
					FD_SET(fd_raw, &rfds);
					struct timeval tv = {0, 10000}; // 10 мс
					if (select(fd_raw + 1, &rfds, NULL, NULL, &tv) > 0)
					{
						unsigned char buf[4096];
						struct rx_info ri;
						int caplen
							= wi_read(wi, NULL, NULL, buf, sizeof(buf), &ri);
						if (caplen > 0)
						{
							dump_add_packet_wrapper(buf, caplen, &ri, 0);
						}
					}
					// Обновление статистики раз в 500 мс
					static struct timeval last = {0, 0};
					struct timeval now;
					gettimeofday(&now, NULL);
					if ((now.tv_sec - last.tv_sec) * 1000000L
							+ (now.tv_usec - last.tv_usec)
						> 500000)
					{
						update_rx_quality_wrapper();
						update_dataps_wrapper();
						last = now;
					}
					// Смена канала каждые 250 мс

					if (channel == 0)
					{
						static struct timeval last_hop = {0, 0};
						struct timeval now_hop;
						gettimeofday(&now_hop, NULL);
						if ((now_hop.tv_sec - last_hop.tv_sec) * 1000000L
								+ (now_hop.tv_usec - last_hop.tv_usec)
							> lopt.hopfreq * 1000)
						{
							chan_index = (chan_index + 1) % channels.size();
							wi_set_channel(wi, channels[chan_index]);
							lopt.channel[0] = channels[chan_index];
							last_hop = now_hop;
						}
					}
				}
			});
	}

	void stop_capture()
	{
		if (!scan_networks and !scan_network) return;
		scan_networks = false;
		scan_network = false;
		if (capture_thread.joinable()) capture_thread.join();
		if (wi)
		{
			wi_close(wi);
			wi = nullptr;
		}
		fd_raw = -1;
	}
	AirTui(WINDOW * win) : AirBars(win)
	{
		base_helper = {{"^ v < >", "Nav"},
					   {"Enter", "select interface"},
					   {"q", "Exit"},
					   {"m", "Mode"}};
	}

	// Отрисовка строки состояния над списком интерфейсов (аналог render_bar_over_interfaces)
	void draw_interface_header(int split_x, std::string text)
	{
		attron(A_REVERSE);
		std::string header = "     " + text; // Сдвиг 5 пробелов
		mvaddstr(1, 0, header.c_str());
		// Добиваем реверс-фоном до разделителя
		for (int i = header.length(); i < split_x; ++i) mvaddch(1, i, ' ');
		attroff(A_REVERSE);
	}
	void draw_network_table(int h, int w, int start_x)
	{
		// Информация о выбранной сети
		mvprintw(2,
				 start_x + 2,
				 "Target: %s (CH %d) - waiting for handshake...",
				 selectNetwork.bssid.c_str(),
				 selectNetwork.channel);
		mvprintw(
			3,
			start_x + 2,
			"%-20s %-2s %-3s %-4s %-4s %-3s %-4s %-3s %-2s %-3s %-2s %-14s",
			"BSSID",
			"PWR",
			"RXQ",
			"Beacons",
			"#Data,",
			"#/s",
			"CH",
			"MB",
			"ENC",
			"CHIPHER",
			"AUTH",
			"ESSID");
		// ------

		for (int i = 0; i < w; i++)
		{
			mvprintw(5, start_x + 2 + i, "-");
		}

		// Заголовок таблицы станций
		mvprintw(6,
				 start_x + 2,
				 "%-20s %-6s %-8s %-8s %-8s %-8s %-8s",
				 "STATION",
				 "PWR",
				 "RATE",
				 "LOST",
				 "FRAMES",
				 "NOTES",
				 "PROBES");
		for (int i = 0; i < w; i++)
		{
			mvprintw(7, start_x + 2 + i, "-");
		}
		int row = 8;
		pthread_mutex_lock(&lopt.mx_print);
		struct ST_info * st = lopt.st_1st;
		while (st && row < h - 5)
		{
			// Проверяем, принадлежит ли станция выбранной AP
			if (st->base && mac2str(st->base->bssid) == selectNetwork.bssid)
			{
				// Первый probe (если есть)
				char probe_str[32] = "";
				if (st->ssid_length[0] > 0)
				{
					snprintf(probe_str,
							 sizeof(probe_str),
							 "%.*s",
							 st->ssid_length[0],
							 st->probes[0]);
				}
				mvprintw(row++,
						 start_x + 2,
						 "%-20s %-6d %-8lu %-8.8s",
						 mac2str(st->stmac).c_str(),
						 st->power,
						 st->nb_pkt,
						 probe_str);
			}
			st = st->next;
		}
		pthread_mutex_unlock(&lopt.mx_print);
	}

	void draw_networks_table(int h, int w, int start_x)
	{

		// Заголовок
		// mvprintw(3,
		// 		 start_x + 2,
		// 		 "%-20s %-6s %-4s %-32s",
		// 		 "BSSID",
		// 		 "PWR",
		// 		 "CH",
		// 		 "ESSID");
		const int start_y = 3;
		mvprintw(
			start_y,
			start_x + 2,
			"%-20s %-2s %-3s %-4s %-4s %-3s %-4s %-3s %-2s %-3s %-2s %-14s",
			"BSSID",
			"PWR",
			"RXQ",
			"Beacons",
			"#Data,",
			"#/s",
			"CH",
			"MB",
			"ENC",
			"CHIPHER",
			"AUTH",
			"ESSID");

		for (int i = 0; i < w; i++)
		{
			mvprintw(start_y + 1, start_x + 2 + i, "-");
		}
		int count_networks = 0;

		pthread_mutex_lock(&lopt.mx_print); // блокируем доступ к списку
		mvprintw(2, start_x + 2, "Current channel: %d", lopt.channel[0]);
		struct AP_info * ap = lopt.ap_1st;
		int row = 5;
		int visible_ap_rows = h - row - start_y + 1;
		int current_row = row;
		int current_scroll_offset = current_row_networks - visible_ap_rows;
		int offset = 0;
		if (current_scroll_offset > 0) offset = current_scroll_offset;

		while (ap)
		{
			// if (visible_ap_rows < current_row_networks)
			// {
			// i = current_scroll_offset;
			// }
			// Показываем только AP, которые не "пропали" (tlast + berlin > now)
			if (time(NULL) - ap->tlast <= lopt.berlin)

			{
				if (ap->bssid[0] == 0 && ap->bssid[1] == 0 && ap->bssid[2] == 0
					&& ap->bssid[3] == 0 && ap->bssid[4] == 0
					&& ap->bssid[5] == 0)
				{
					ap = ap->next;
					continue;
				}
				if (ap->bssid[0] == 0xFF && ap->bssid[1] == 0xFF
					&& ap->bssid[2] == 0xFF && ap->bssid[3] == 0xFF
					&& ap->bssid[4] == 0xFF && ap->bssid[5] == 0xFF)
				{

					ap = ap->next;
					continue;
				}

				if (ap->channel == -1 && ap->max_speed == -1)
				{

					ap = ap->next;
					continue;
				}
				if (current_row_networks - offset == current_row - row
					&& current_column == 1)
				{
					selectNetwork.bssid = mac2str(ap->bssid);
					selectNetwork.channel = ap->channel;
					mvprintw(2,
							 start_x + 40,
							 "Selected : %s",
							 selectNetwork.bssid.c_str());
					attron(A_REVERSE);
				}

				if (current_row < h)
				{
					if (current_scroll_offset <= 0)
					{
						mvprintw(current_row++,
								 start_x + 2,
								 "%-20s %-3d %-3d %-7lu %-7ld %-3d %-2d %-3d "
								 "%-5s %-7s "
								 "%-2s "
								 "%-1.32s",
								 mac2str(ap->bssid).c_str(),
								 ap->avg_power,
								 ap->rx_quality,
								 ap->nb_bcn,
								 ap->nb_data,
								 ap->nb_dataps,
								 ap->channel,
								 ap->max_speed,
								 get_enc_str(ap),
								 get_cipher_str(ap),
								 get_auth_str(ap),
								 (ap->essid[0] ? (const char *) ap->essid
											   : "<hidden>"));
					}
					else
					{
						current_scroll_offset--;
					}

					if (current_row_networks - offset == current_row - 1 - row
						&& current_column == 1)
						attroff(A_REVERSE);
				}

				count_networks++;
				this->count_networks = count_networks;
			}

			mvprintw(2, start_x + 25, "AP count: %d", count_networks);

			ap = ap->next;
		}
		pthread_mutex_unlock(&lopt.mx_print);
	}
	void select_interface_loop()
	{

		// lopt.channel[0] = 1;
		// Тут должен быть вызов ArgPars::get_wifi_interfaces()
		std::vector<std::string> interfaces = get_wifi_interfaces();
		while (true)
		{
			int h, w;
			getmaxyx(stdscr, h, w);
			erase();

			int split_x = get_x_split();

			// Отрисовка вертикального разделителя
			for (int y = 1; y < h - 1; ++y) mvaddch(y, split_x, ACS_VLINE);

			draw_top_bar(w);

			// Левая панель: выбор интерфейса
			std::string head_txt = selected_interface.empty()
									   ? "SELECT INTERFACE"
									   : "SELECTED: " + selected_interface;
			draw_interface_header(split_x, head_txt);

			for (int i = 0; i < (int) interfaces.size(); ++i)
			{
				if (current_column == 0 && i == current_row_interfaces)
					attron(A_REVERSE);
				mvprintw(i + 3,
						 4,
						 (current_row_interfaces == i ? "> %s" : "  %s"),
						 interfaces[i].c_str());
				if (current_column == 0 && i == current_row_interfaces)
					attroff(A_REVERSE);
			}

			if (scan_network)
			{
				draw_network_table(h, w, split_x);
			}
			else
			{
				draw_networks_table(h, w, split_x);
			}

			if (!selected_interface.empty())
			{
				base_helper["F1"] = "start monitoring";
				if (statemon)
				{
					if (!scan_networks)
					{
						if (scan_network)
							base_helper["F1"] = "stop target scan";
						else
							base_helper["F1"] = "start scan";
					}
					else
					{
						base_helper["F1"] = "stop scan";
					}
					base_helper["F9"] = "stop monitoring";
				}
				else
				{
					base_helper.erase("F9");
				}
			}
			if (current_column == 1)
			{
				base_helper["Enter"] = "start scan current network";
			}
			else
			{
				base_helper["Enter"] = "select interface";
			}
			draw_bar(h, w, base_helper);
			refresh();

			int key = getch();
			if (key == 'q')
			{
				break;
			}
			else if (key == 'm')
			{
				mode = !mode;
			}
			// Навигация
			// control interface
			else if (key == KEY_F(1) or key == KEY_F(9))
			{
				if (key == KEY_F(1))
				{
					// on monitoring mode
					if (!selected_interface.empty() and !statemon)
					{
						start_mon(selected_interface);
						statemon = true;
						interfaces = get_wifi_interfaces();
						selected_interface += "mon";
					}
					// start capture
					else if (statemon && !scan_networks && !scan_network)
					{

						start_capture(selected_interface);

						timeout(10);
					}
					// stop capture
					else if (statemon && scan_networks)
					{

						stop_capture();

						timeout(-1);
					}
					else if (statemon && scan_network)
					{
						stop_capture();
						mvprintw(20, 20, "stop scan target network");

						start_capture(selected_interface);
					}
				}
				// off monitoring mode
				else if (key == KEY_F(9) and statemon)
				{
					stop_capture();

					timeout(-1);
					stop_mon(selected_interface);
					statemon = false;
					interfaces = get_wifi_interfaces();

					const std::string suffix = "mon";

					if (selected_interface.size() >= suffix.size()
						&& selected_interface.compare(selected_interface.size()
														  - suffix.size(),
													  suffix.size(),
													  suffix)
							   == 0)
					{
						selected_interface.erase(selected_interface.size()
												 - suffix.size());
					}
				}
			}

			// navigation up/down ^ v left/right < >
			// up/down
			else if (key == KEY_DOWN || key == KEY_UP)
			{
				if (key == KEY_DOWN)
				{
					if (current_column == 0)
					{
						current_row_interfaces
							= (current_row_interfaces + 1)
							  % static_cast<int>(interfaces.size());
					}
					else
					{
						if (count_networks == 0)
						{
							// you can't divide by 0, so count_networks = 1
							count_networks = 1;
						}
						current_row_networks
							= (current_row_networks + 1 + count_networks)
							  % count_networks;
					}
				}
				else if (key == KEY_UP)
				{
					if (current_column == 0)
					{
						current_row_interfaces
							= (current_row_interfaces - 1)
							  % static_cast<int>(interfaces.size());
					}
					else
					{

						if (count_networks == 0)
						{
							// you can't divide by 0, so count_networks = 1
							count_networks = 1;
						}
						current_row_networks
							= (current_row_networks - 1 + count_networks)
							  % count_networks;
					}
				}
			}
			// left/right
			else if (key == KEY_LEFT || key == KEY_RIGHT)
			{
				if (mode == true)
				{
					int size_modes = static_cast<int>(modes.size());
					if (key == KEY_RIGHT)
					{
						current_mode
							= (current_mode + 1 + size_modes) % size_modes;
					}
					else
						current_mode
							= (current_mode - 1 + size_modes) % size_modes;
				}
				else if (count_networks != 0)
				{
					const int count_windows = 2;
					if (key == KEY_RIGHT)
					{
						current_column = (current_column + 1 + count_windows)
										 % count_windows;
					}
					else
					{
						current_column = (current_column - 1 + count_windows)
										 % count_windows;
					}
				}
			}

			// press enter
			else if (key == 10 || key == 13)
			{ // Enter
				if (current_column == 0)
				{
					selected_interface = interfaces[current_row_interfaces];
					if (isMonitoring())
					{
						statemon = true;
					}
					else
					{
						statemon = false;
					}
				}
				else if (current_column == 1)
				{

					stop_capture();
					scan_network = true;
					start_capture(selected_interface, selectNetwork.channel);
				}
			}
		}
	}
};

int main(int argc, char * argv[])
{
	if (getuid() != 0)
	{
		std::cerr << "Run it as root\n";
		return getuid();
	}

	airodump_init();

	lopt.hopfreq = 250;
	lopt.channel[0] = 1;
	// Обязательно для корректной отрисовки границ ACS_VLINE и UTF-8 в ESSID
	setlocale(LC_ALL, "");

	// Инициализация ncurses
	WINDOW * main_win = initscr();
	if (main_win == nullptr)
	{
		fprintf(stderr, "Error initializing ncurses.\n");
		return 1;
	}

	// Базовые настройки терминала
	noecho(); // Не выводить нажатые клавиши
	cbreak(); // Читать клавиши сразу, без Enter
	keypad(main_win, TRUE); // Включить F1, F9, стрелки
	curs_set(0); // Скрыть курсор

	// Создаем объект и запускаем твой цикл
	AirTui app(main_win);

	// В будущем сюда можно добавить проверку root прав
	// и инициализацию структур lopt

	app.select_interface_loop();

	// Завершение работы ncurses
	endwin();

	return 0;
}