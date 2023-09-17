# Ping Tool by AK4CZ

## Overview

Ping Tool by AK4CZ is a versatile Python application designed for network administrators and IT professionals. This tool provides an intuitive graphical user interface (GUI) for conducting network diagnostics, primarily focusing on IP address ping tests. It combines ease of use with advanced functionality, making it a valuable addition to your network troubleshooting toolkit.

![Ping Tool Screenshot](https://imgur.com/a/s9Fekt8)

## Features

### 1. Ping Testing

- **Ping Multiple IP Addresses:** You can perform ping tests on one or more IP addresses simultaneously. Simply input the IP addresses and let the tool handle the rest.
- **Configurable Ping Count:** Specify the number of ping requests to send, allowing you to customize the duration of the test.
- **Real-Time Results:** Ping responses are displayed in real-time, allowing you to monitor network connectivity and latency.

### 2. Logging and Reporting

- **Comprehensive Logging:** All ping test results are automatically logged, including timestamps and response times.
- **Log Export:** You can export the log data to a file for later analysis or documentation.
- **FTP Integration:** Ping Tool supports FTP connectivity for seamless transfer of log files to a remote server.

### 3. Resource Monitoring (Optional)

- **System Resources:** Ping Tool can optionally monitor and display system resource utilization, including CPU, RAM, and GPU statistics. This feature helps you identify potential performance bottlenecks during network diagnostics.

## Getting Started

### Prerequisites

Before running Ping Tool, ensure you have the following Python libraries installed:

- `tkinter` - for the graphical user interface.
- `ftplib` - for FTP communication.
- `os` - for file system operations.
- `logging` - for logging.
- `socket` - for network operations.
- `datetime` - for date and time handling.
- `subprocess` - for running system commands.
- `threading` - for multi-threading.
- `ttk` - for creating a progress bar.
- `sys` - for system-related operations.
- `re` - for regular expressions.
- `cryptography.fernet` - for data encryption.
- `psutil` - for monitoring system resources (optional).
- `GPUtil` - for monitoring GPU resources (optional).

### Running the Application

1. Launch the application, and the login window will appear.
2. Enter the application password, which will be encrypted and securely stored.
3. Provide the FTP password, FTP username, and FTP host, which will also be encrypted for security.
4. The application will start, displaying the main window with the ping tool.
5. Input the IP address(es) you want to ping and the number of ping attempts, then click the "Test!" button.
6. Ping results will be displayed in the text field in real-time and saved in a log file.

## Author

Ping Tool by AK4CZ was developed by [Arkadiusz Adamowski], a network enthusiast, and IT professional, with a passion for simplifying network troubleshooting.

## License

This project is licensed under the [MIT License]. For detailed licensing information, please refer to the [LICENSE](https://www.mediafire.com/file/1237ejkpwz6ro53/LICENSE/file).

## Acknowledgments

We would like to express our gratitude to the open-source community and the developers of the libraries used in this project. Your contributions have made this tool possible.

