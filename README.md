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
./simple_port_scanner [OPTIONS]
```
---

## 🧾 Required

| Option   | Description                     |
|----------|---------------------------------|
| `-t <IP>`| Target IP address (required)    |

---

## 🔌 Ports

| Option   | Description                                                        |
|----------|--------------------------------------------------------------------|
| `-p <PORTS>` | Ports to scan. Ex: `80,443,1000-2000` or `*` for all ports     |
| `-F`     | Fast scan (top 110 common ports)                                   |

> ⚠️ Do **NOT** use `-p` and `-F` together.

---

## ⏱ Delay

| Option   | Description                                                      |
|----------|------------------------------------------------------------------|
| `-D <ms>`| Delay (in milliseconds) between scans. Max allowed: `10000 ms`   |

---

## 📄 Output

| Option     | Description                              |
|------------|------------------------------------------|
| `-O <file>`  | Save **all** scan results               |
| `-Oo <file>` | Save **only open** ports                |
| `-Oc <file>` | Save **only closed** ports              |
| `-Ob <file>` | Save **only blocked** ports             |

---

## ⚙️ General

| Option       | Description                     |
|--------------|---------------------------------|
| `-v`         | Verbose mode                    |
| `-h`, `--help` | Display help and usage guide   |

---

## 🔧 Examples

### Scan common ports on an IP:
```bash
./simple_port_scanner -t 192.168.1.1
