#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <csignal>
#include <sys/wait.h>  // For waitpid
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#include <string>
#include <vector>
#include <numeric>
#include <algorithm>
#include <cmath>

// Function to execute a command
void execute_command(const std::string& command) {
    int result = system(command.c_str());
    if (result != 0) {
        std::cerr << "Failed to execute command: " << command << std::endl;
    }
}

// Function to get the server IP address
std::string get_server_ip() {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char *addr;

    std::string ip_address;

    if (getifaddrs(&ifap) == -1) {
        std::cerr << "Error: getifaddrs() failed." << std::endl;
        return "";
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_INET) {
            sa = (struct sockaddr_in *)ifa->ifa_addr;
            addr = inet_ntoa(sa->sin_addr);

            if (std::string(ifa->ifa_name) == "enp58s0") {  // replace "enp58s0" with your network interface name
                ip_address = std::string(addr);
                break;
            }
        }
    }

    freeifaddrs(ifap);

    if (ip_address.empty()) {
        std::cerr << "Error: Could not find IP address for interface enp58s0." << std::endl;
    }

    std::cout<<ip_address<<std::endl;
    return ip_address;
}

std::string generate_dummy_file(int flow_size_kb, const std::string& file_name) {
    std::string web_root = "/var/www/html/";
    std::string destination = web_root + file_name;

    std::ofstream file(destination, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not create file at " << destination << std::endl;
        return "";
    }

    int flow_size_bytes = flow_size_kb * 1024;

    // Seek to the size minus one, and then write a single byte to set the file size
    file.seekp(flow_size_bytes*1024 - 1);
    file.write("", 1);
    file.close();
    return destination;  // Return the full path to the file
}

// Function to run BPF trace
pid_t run_bpftrace(const std::string& save_dir, int port) {
    pid_t pid = fork();

    if (pid == -1) {
        std::cerr << "Failed to fork process for bpftrace." << std::endl;
        return -1;
    }

    if (pid == 0) {
        std::string port_str = std::to_string(port);
        const char* command = "sudo";
        const char* script = "./run_bpftrace.sh";
        execlp(command, command, script, save_dir.c_str(), port_str.c_str(), nullptr);

        std::cerr << "Failed to execute bpftrace script." << std::endl;
        _exit(1);
    }

    return pid;
}

// Function to handle client requests
void handle_client(int client_socket, sockaddr_in client_addr, int port) {
    char buffer[4096];
    int data_len = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (data_len <= 0) {
        std::cerr << "Error receiving data from client." << std::endl;
        close(client_socket);
        return;
    }

    buffer[data_len] = '\0';
    std::string request(buffer);

    // Find the empty line between headers and the body
    std::size_t pos = request.find("\r\n\r\n");
    if (pos == std::string::npos) {
        std::cerr << "Invalid HTTP request: No header-body separation found." << std::endl;
        close(client_socket);
        return;
    }

    // Extract the body part after the headers
    std::string body = request.substr(pos + 4);

    // Now parse the body to extract the parameters
    std::size_t cc_pos = body.find("congestion_control=");
    std::size_t fs_pos = body.find("flow_size=");
    std::size_t rn_pos = body.find("repeat_number=");

    if (cc_pos == std::string::npos || fs_pos == std::string::npos || rn_pos == std::string::npos) {
        std::cerr << "Invalid POST data: Missing parameters." << std::endl;
        close(client_socket);
        return;
    }

    std::string congestion_control = body.substr(cc_pos + 18, body.find('&', cc_pos) - (cc_pos + 18));// Extract the flow_size and repeat_number strings first
    std::string flow_size_str = body.substr(fs_pos + 10, body.find('&', fs_pos) - (fs_pos + 10));
    std::string repeat_number_str = body.substr(rn_pos + 15, body.find('&', rn_pos) - (rn_pos + 15));

    // Convert the extracted strings to integers
    int flow_size = std::stoi(flow_size_str);
    int repeat_number = std::stoi(repeat_number_str);


    // Set congestion control algorithm
    if (congestion_control.find("bbr") != std::string::npos) {
        execute_command("sudo sysctl -w net.ipv4.tcp_congestion_control=bbr");
        std::cout << "TCP Congestion Control set to BBR" << std::endl;
    } else if (congestion_control.find("reno") != std::string::npos) {
        execute_command("sudo sysctl -w net.ipv4.tcp_congestion_control=reno");
        std::cout << "TCP Congestion Control set to Reno" << std::endl;
    } else if (congestion_control.find("cubic") != std::string::npos) {
        execute_command("sudo sysctl -w net.ipv4.tcp_congestion_control=cubic");
        std::cout << "TCP Congestion Control set to Cubic" << std::endl;
    } else if (congestion_control.find("ccp") != std::string::npos) {
        execute_command("sudo sysctl -w net.ipv4.tcp_congestion_control=ccp");
        std::cout << "TCP Congestion Control set to CCP (Copa)" << std::endl;
    } else {
        std::cerr << "Unknown congestion control algorithm: " << congestion_control << std::endl;
        close(client_socket);
        return;
    }

    std::cout << "Why" << std::endl;
    std::string file_name = "dummy_file_" + std::to_string(flow_size) + ".bin";

    // Generate the file directly in the web server's root directory
    std::string file_path = generate_dummy_file(flow_size, file_name);

    if (file_path.empty()) {
        std::cerr << "Failed to generate the dummy file" << std::endl;
        close(client_socket);
        return;
    }

    std::cout << "Why2" << std::endl;

    // No need to move the file since it's already created in the correct directory

    // Get the server's IP address
    std::string server_ip = get_server_ip();  // Replace with actual function to get server IP
    std::string download_url = "http://" + server_ip + "/" + file_name;


    std::cout << "Why2-2" << std::endl;

    // Start BPF trace
    std::string save_dir = "result/" + congestion_control + "_" + std::to_string(flow_size) + "_" + std::to_string(repeat_number) + "_" + std::to_string(time(nullptr));
    pid_t bpf_process = run_bpftrace(save_dir, port);

    std::cout << "Why3" << std::endl;
    // Send download URL to client
    send(client_socket, download_url.c_str(), download_url.size(), 0);


    std::cout << "Why4" << std::endl;

    // Wait for flow completion time from client
    data_len = recv(client_socket, buffer, sizeof(buffer), 0);
    if (data_len > 0) {
        buffer[data_len] = '\0';
        std::string flow_completion_data(buffer);

        // Parse the CSV data from the client
        std::vector<double> fct_values;
        std::istringstream ss(flow_completion_data);
        std::string line;
        while (std::getline(ss, line)) {
            std::istringstream line_stream(line);
            std::string index_str, fct_str;
            if (std::getline(line_stream, index_str, ',') && std::getline(line_stream, fct_str, ',')) {
                try {
                    double fct_value = std::stod(fct_str);
                    fct_values.push_back(fct_value);
                } catch (const std::invalid_argument&) {
                    std::cerr << "Invalid FCT value: " << fct_str << std::endl;
                }
            }
        }

        // Calculate mean and standard deviation
        double sum = std::accumulate(fct_values.begin(), fct_values.end(), 0.0);
        double mean = sum / fct_values.size();

        double sq_sum = std::inner_product(fct_values.begin(), fct_values.end(), fct_values.begin(), 0.0);
        double std_dev = std::sqrt(sq_sum / fct_values.size() - mean * mean);

        // Log flow completion times and statistics
        std::ofstream log_file(save_dir + "/flow_completion_time.log");
        log_file << "Index,FCT\n";
        for (size_t i = 0; i < fct_values.size(); ++i) {
            log_file << i << "," << fct_values[i] << "\n";
        }
        log_file << "\nMean FCT: " << mean << "\n";
        log_file << "Standard Deviation FCT: " << std_dev << "\n";
        log_file.close();

        // Print the mean and standard deviation
        std::cout << "Mean FCT: " << mean << " ms\n";
        std::cout << "Standard Deviation FCT: " << std_dev << " ms\n";
    }

    // Stop the BPF trace
    kill(bpf_process, SIGTERM);
    waitpid(bpf_process, nullptr, 0);

    close(client_socket);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        return 1;
    }

    int port = std::stoi(argv[1]);
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        std::cerr << "Error creating socket." << std::endl;
        return 1;
    }

    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Bind failed." << std::endl;
        close(server_socket);
        return 1;
    }

    listen(server_socket, 10);
    std::cout << "Server listening on port " << port << std::endl;

    while (true) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            std::cerr << "Error accepting connection." << std::endl;
            continue;
        }

        std::thread client_thread(handle_client, client_socket, client_addr, port);
        client_thread.detach();
    }

    close(server_socket);
    return 0;
}
