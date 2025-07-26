#include <iostream>
#include <regex>
#include <boost/asio.hpp>
#include <iomanip>
#include <fstream>
#include <string>
#include <filesystem>
#include <chrono>

// Validate IP address syntax using regex
bool ip_validation(std::string ip) {
	std::regex ip_pattern(R"(^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$)");

	return std::regex_match(ip, ip_pattern);
}

// Save content to a file
bool output_file(std::string filename, std::string content) {
	std::ofstream outfile(filename);
	if (!outfile) {
		std::cerr << "Failed to create or write to file: " << filename << '\n';
		return false;
	}
	outfile << content;
	outfile.close();
	return true;
}

// Validate output filename syntax
bool output_filename_validation(std::string output_filename) {
	std::regex filename_invalid_char(R"([\/:*?"<>|])");
	if (std::regex_search(output_filename, filename_invalid_char)) {
		return false;
	}
	std::filesystem::path path(output_filename);
	std::string extension = path.extension().string();
	if (extension.empty() || extension.length() < 2 || extension[0] != '.') {
		return false;
	}
	return true;
}

// Display help message for usage
std::string help_message() {
	return
		"Usage: scanner [OPTIONS]\n"
		"\n"
		"Options:\n"
		"+-- Target\n"
		"|   +-- -t, --target <IP>                   Target IP address [required]\n"
		"|\n"
		"+-- Ports\n"
		"|   +-- -p, --port <PORTS>                  Ports to scan (e.g., 80,443,1000-2000 or *)\n"
		"|   +-- -F, --fast                          Fast scan using top 110 common ports\n"
		"|   +-- (If neither -p nor -F is provided,  default ports will be scanned)\n"
		"|\n"
		"+-- Scan Delay\n"
		"|   +-- -D, --delay <ms>                    Delay (in milliseconds) between scans [max: 10000]\n"
		"\n"
		"+-- Output Files\n"
		"|   +-- -O,   --output <file.ext>           Save all scan results\n"
		"|   +-- -Oo,  --output_open <file.ext>      Save only open ports\n"
		"|   +-- -Oc,  --output_closed <file.ext>    Save only closed ports\n"
		"|   +-- -Ob,  --output_blocked <file.ext>   Save only filtered/blocked ports\n"
		"|\n"
		"+-- General\n"
		"    +-- -h, --help                          Show this help message and exit\n";
}

int main(int argc, char* argv[]) {

	// Flags for argument detectiond
	bool arg_t = false;
	bool arg_p = false;
	bool arg_F = false;
	bool arg_D = false;
	bool arg_v = false;
	bool arg_h = false;
	bool arg_o = false;
	bool arg_oc = false;
	bool arg_oo = false;
	bool arg_ob = false;
	bool tcp = true;

	// Input holders
	std::string ip;
	std::vector<int> port_list;
	int delay_ms = 1000;
	std::string output_name = "port_scanner.txt";
	std::string output_open_ports;
	std::string output_closed_ports;
	std::string output_blocked_ports;
	
	// Show help if no arguments
	if (argc == 1) {
		arg_h = true;
		std::cerr << help_message();
		return 0;
	}

	// Handle help early if passed with other args
	for (int i = 1; i < argc; i++) {
		std::string arg = argv[i];
		if (arg == "-h" && argc > 2 || arg == "--help" && argc > 2) {
			arg_h = true;
			std::cerr << help_message();
			return 0;
		}
	}

	// Process each CLI argument
	for (int i = 1; i < argc; i++) {
		std::string arg = argv[i];

		// Help
		if (arg == "-h" || arg == "--help") {
			arg_h = true;
			std::cout << help_message();
			return 0;
		}

		// Target IP
		else if (arg == "-t" || arg == "--target") {
			arg_t = true;
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				ip = argv[++i];
				if (!ip_validation(ip)) {
					std::cerr << "Invalid IP address format.\n";
					return 1;
				}
			}
			else {
				std::cerr << "-t/--target requires an IP address\n";
				return 1;
			}
		}

		// Port list
		else if (arg == "-p" || arg == "--port") {
			arg_p = true;
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				std::string port_input = argv[++i];
				if (port_input == "*") {
					port_input = "1-65535";
				}
				std::stringstream ss(port_input);
				std::string part;
				while (std::getline(ss, part, ',')) {
					size_t dash = part.find('-');
					if (dash != std::string::npos) {
						std::string start_str = part.substr(0, dash);
						std::string end_str = part.substr(dash + 1);
						if (!std::all_of(start_str.begin(), start_str.end(), ::isdigit) ||
							!std::all_of(end_str.begin(), end_str.end(), ::isdigit)) {
							std::cerr << "Port must be a number!\n";
							return 1;
						}
						int start = std::stoi(start_str);
						int end = std::stoi(end_str);
						if (start > end) {
							std::cerr << "Port range is not well defined\n";
							return 1;
						}
						if (start < 1 || end > 65535) {
							std::cerr << "Invalid port range.port numbers must be(1 - 65535)\n";
							return 1;
						}
						for (int p = start; p <= end; ++p) {
							port_list.push_back(p);
						}
					}
					else {
						if (!std::all_of(part.begin(), part.end(), ::isdigit)) {
							std::cerr << "port must be a number!\n";
							return 1;
						}
						int p = std::stoi(part);
						if (p < 1 || p > 65535) {
							std::cerr << "Invalid port number. port number must be (1-65535)" << '\n';
							return 1;
						}
						port_list.push_back(p);
					}
				}
			}
			else {
				std::cerr << "-p/--port requires a port or list of ports\n";
				return 1;
			}
		}

		// Fast scan
		else if (arg == "-F" || arg == "--fast") {
			arg_F = true;
			port_list = { 20, 21, 22, 23, 25, 53, 67, 68, 69, 80,
				110, 111, 119, 123, 135, 137, 138, 139, 143, 161,
				162, 179, 194, 443, 445, 465, 514, 515, 520, 587,
				631, 993, 995, 1080, 1194, 1352, 1433, 1434, 1521, 1701,
				1723, 1812, 1813, 1883, 2049, 2082, 2083, 2100, 2222, 2375,
				2376, 2483, 2484, 25565, 2600, 2947, 3000, 3001, 3128, 3260,
				3306, 3389, 3690, 4000, 4001, 4369, 4444, 4567, 5000, 5001,
				5060, 5061, 5432, 5631, 5666, 5800, 5900, 5984, 6000, 6379,
				6660, 6667, 6697, 7000, 7070, 7199, 7443, 7777, 8000, 8008,
				8080, 8081, 8086, 8222, 8333, 8443, 8888, 9000, 9090, 9200,
				9300, 9418, 9999, 10000, 11211, 27017, 28017, 50000, 49152, 32768 };
		}

		// Verbose
		else if (arg == "-v" || arg == "--verbose") {
			arg_v = true;
		}

		// Delay
		else if (arg == "-D" || arg == "--delay") {
			arg_D = true;
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				std::string delay_str = argv[++i];
				bool delay_ms_valid = true;
				for (char c : delay_str) {
					if (!isdigit(c)) {
						std::cerr << "Invalid delay value. Please provide a valid positive integer.\n";
						return 1;
					}
				}
				if (delay_ms_valid) {
					delay_ms = std::stoi(delay_str);
					if (delay_ms > 10000) {
						std::cerr << "Delay is too large. Maximum allowed delay is 10000 milliseconds.\n";
						return 1;
					}
				}
			}
			else {
				std::cerr << "-D/--delay requires a number\n";
				return 1;
			}
		}

		// Output-related flags (-O, -Oo, -Oc, -Ob)
		else if (arg == "-O" || arg == "--output") {
			arg_o = true;
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				if (!output_filename_validation(argv[i + 1])) {
					std::cerr << "Invalid filename.\n";
					return 1;
				}
				else {
					output_name = argv[++i];
					std::cout << output_name << '\n';
				}
			}
			else {
				std::cout << output_name << '\n';
			}
		}
		else if (arg == "-Oo" || arg == "--output_open") {
			arg_oo = true;
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				if (!output_filename_validation(argv[i + 1])) {
					std::cerr << "Invalid filename.\n";
					return 1;
				}
				else {
					output_name = argv[++i];
					std::cout << output_name << '\n';
				}
			}
			else {
				std::cout << output_name << '\n';
			}
		}
		else if (arg == "-Oc" || arg == "--output_closed") {
			arg_oc = true;
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				if (!output_filename_validation(argv[i + 1])) {
					std::cerr << "Invalid filename.\n";
					return 1;
				}
				else {
					output_name = argv[++i];
					std::cout << output_name << '\n';
				}
			}
			else {
				std::cout << output_name << '\n';
			}
		}
		else if (arg == "-Ob" || arg == "--output_blocked") {
			arg_ob = true;
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				if (!output_filename_validation(argv[i + 1])) {
					std::cerr << "Invalid filename.\n";
					return 1;
				}
				else {
					output_name = argv[++i];
					std::cout << output_name << '\n';
				}
			}
			else {
				std::cout << output_name << '\n';
			}
		}

		// unknown argument
		else {
			std::cerr << "Unknown argument: " << arg << '\n';
			return 1;
		}
	}

	// Validate required flags 
	if (!arg_t) {
		std::cerr << "-t/--target is required\n";
		return 1;
	}
	if(arg_p && arg_F) {
		std::cerr << "-p/--port and -F/--fast can not be used at the same time\n";
		return 1;
	}
	// no -p argument(default ports)
	if (arg_p == false && arg_F == false && arg_t == true) {
		port_list = { 21, 22, 23, 25, 53, 80, 110, 139, 143, 161, 389, 443, 445, 587, 993, 995, 3306, 3389, 5900, 8080 };
	}

	// Begin scan
	if (arg_t == true && ip_validation(ip) == true && arg_h == false) {
		std::cout << "=== Simple Port Scanner ===\n";
		std::cout << "Target IP: " << ip << '\n';
		std::cout << "Protocol : " << "TCP" << "\n\n";

		if (tcp) {
			auto start_time = std::chrono::high_resolution_clock::now();
			boost::asio::io_context io_context;
			if (!arg_v) {
				std::cout << std::left << std::setw(23) << "IP:PORT/PROTOCOL" << "STATUS" << "\n\n";
			}
			for (int port : port_list) {
				try {
					if (arg_v) {
						std::cout << "Attempting connection to " << ip << ":" << port << '\n';
					}
					if (arg_D) {
						std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
					}
					boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::make_address(ip), port);
					boost::asio::ip::tcp::socket socket(io_context);
					socket.open(boost::asio::ip::tcp::v4());
					socket.connect(endpoint);
					std::string open_ports = ip + ":" + std::to_string(port) + "/TCP";
					std::cout << std::left << std::setw(23) << open_ports << "OPEN" << '\n';
					output_open_ports += "- " + open_ports + '\n';
					socket.close();
				}
				catch (boost::system::system_error error) {
					if (error.code() == boost::asio::error::connection_refused) {
						std::string closed_ports = ip + ":" + std::to_string(port) + "/TCP";
						std::cout << std::left << std::setw(23) << closed_ports << "CLOSED" << '\n';
						output_closed_ports += "- " + closed_ports + '\n';
					}
					else {
						std::string blocked_ports = ip + ":" + std::to_string(port) + "/TCP";
						std::cout << std::left << std::setw(23) << blocked_ports << "BLOCKED" << '\n';
						output_blocked_ports += "- " + blocked_ports + '\n';
					}
				}
			}

			auto end_time = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

			if (arg_o && !arg_oo && !arg_oc && !arg_ob) {
				std::string content;
				content = "Scan Report\n===========\n\nTarget: " + ip + '\n' + "Scan Type: " + "TCP" + "\n\n" + "Open Ports:\n" + output_open_ports + "Closed Ports:\n" + output_closed_ports + "Blocked Ports:\n" + output_blocked_ports;
				output_file(output_name, content);
				if (!output_file(output_name, content)) {
					std::cerr << "Could not create a output file";
				}
			}
			if (!arg_o && arg_oo && !arg_oc && !arg_ob) {
				std::string content;
				content = "Scan Report\n===========\n\nTarget: " + ip + '\n' + "Scan Type: " + "TCP" + "\n\n" + "Open Ports:\n" + output_open_ports;
				output_file(output_name, content);
				if (!output_file(output_name, content)) {
					std::cerr << "Could not create a output file";
				}
			}
			if (!arg_o && !arg_oo && arg_oc && !arg_ob) {
				std::string content;
				content = "Scan Report\n===========\n\nTarget: " + ip + '\n' + "Scan Type: " + "TCP" + "\n\n" + "Closed Ports:\n" + output_closed_ports;
				output_file(output_name, content);
				if (!output_file(output_name, content)) {
					std::cerr << "Could not create a output file";
				}
			}
			if (!arg_o && !arg_oo && !arg_oc && arg_ob) {
				std::string content;
				content = "Scan Report\n===========\n\nTarget: " + ip + '\n' + "Scan Type: " + "TCP" + "\n\n" + "Blocked Ports:\n" + output_blocked_ports;
				output_file(output_name, content);
				if (!output_file(output_name, content)) {
					std::cerr << "Could not create a output file";
				}
			}

			std::cout << "\n[INFO] Scan completed in " << duration.count() << " ms.\n";
		}
	}
	return 0;
}