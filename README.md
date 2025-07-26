# 🔍 Simple Port Scanner (C++)

A lightweight command-line port scanner built in **C++** using **Boost.Asio**. This tool allows you to scan specific TCP ports on a target IP address to determine whether they are **open**, **closed**, or **filtered (blocked)**.

---

## 🚀 Features

- ✅ Validates IP addresses and port input
- 🚪 Scans single ports, port ranges, or all ports (`*`)
- ⚡ Supports fast scanning of top 110 commonly used ports
- ⏱️ Optional delay between scans (max 10 seconds)
- 📄 Export scan results to various output files
- 📢 Verbose mode for detailed scan logs
- 🛠️ Graceful error handling for invalid input

---

## 🧾 Usage

```bash
./scanner [OPTIONS]
