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

#include <ctime>      // For time-related functions
#include <iomanip>    // For std::put_time
#include <sstream>    // For std::ostringstream

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

    int flow_size_bytes = flow_size_kb*1024;

    // Seek to the size minus one, and then write a single byte to set the file size
    file.seekp(flow_size_bytes - 1);
    file.write("", 1);
    file.close();
    return destination;  // Return the full path to the file
}


// Updated function to run BPF trace
pid_t run_bpftrace(const std::string& save_dir, const std::string& client_ip) {
    pid_t pid = fork();

    if (pid == -1) {
        std::cerr << "Failed to fork process for bpftrace." << std::endl;
        return -1;
    }

    if (pid == 0) {
        const char* command = "sudo";
        const char* script = "./run_tracepoint.sh";
        execlp(command, command, script, save_dir.c_str(), client_ip.c_str(), nullptr);

        std::cerr << "Failed to execute bpftrace script." << std::endl;
        _exit(1);
    }

    return pid;
}


// Function to handle client requests
void handle_client(int client_socket, sockaddr_in client_addr, int port) {

    // Get client IP address
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    std::string client_ip_str(client_ip);

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

    // Extract values
    std::string congestion_control = body.substr(cc_pos + 19, body.find('&', cc_pos) - (cc_pos + 19));
    std::string flow_size_str = body.substr(fs_pos + 10, body.find('&', fs_pos) - (fs_pos + 10));

    if (rn_pos == std::string::npos) {
        std::cerr << "Invalid POST data: Missing repeat_number parameter." << std::endl;
        close(client_socket);
        return;
    }

    // Extract repeat_number value
    std::string repeat_number_str = body.substr(rn_pos + 14); // +14 to skip "repeat_number="

    std::cout << "Body: " << body << std::endl;
    std::cout << "Parsed values: " << congestion_control << " " << flow_size_str << " " << repeat_number_str << std::endl;

    int flow_size = std::stoi(flow_size_str);
    int repeat_number = std::stoi(repeat_number_str);

    std::cout << "Converted values: Flow Size = " << flow_size << ", Repeat Number = " << repeat_number << std::endl;


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

    std::string file_name = "dummy_file_" + std::to_string(flow_size) + ".bin";

    // Generate the file directly in the web server's root directory
    std::string file_path = generate_dummy_file(flow_size, file_name);

    if (file_path.empty()) {
        std::cerr << "Failed to generate the dummy file" << std::endl;
        close(client_socket);
        return;
    }

    // No need to move the file since it's already created in the correct directory

    // Get the server's IP address
    std::string server_ip = get_server_ip();  // Replace with actual function to get server IP
    std::string download_url = "http://" + server_ip + "/" + file_name;

    // Get the current time
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);

    // Create a string stream to format the time
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d-%H-%M-%S");
    std::string time_str = oss.str();

    // Build the save_dir string with the formatted time
    std::string save_dir = congestion_control + "_" + std::to_string(flow_size) + "_" + std::to_string(repeat_number) + "_" + time_str;
    pid_t bpf_process = run_bpftrace(save_dir, client_ip_str);

    // Send download URL to client
    // In the handle_client function, replace the direct send with:
    std::string response = "HTTP/1.1 200 OK\r\n";
    response += "Content-Type: text/plain\r\n";
    response += "Content-Length: " + std::to_string(download_url.size()) + "\r\n";
    response += "\r\n";
    response += download_url;

    send(client_socket, response.c_str(), response.size(), 0);

    std::string received_data;
    buffer[4096];
    int total_bytes = 0;
    int bytes_received;
    while ((bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        total_bytes += bytes_received;
        buffer[bytes_received] = '\0';
        received_data += buffer;
        
        // Check if we've received the entire message
        if (received_data.find("\r\n\r\n") != std::string::npos) {
            break;
        }
    }

    if (total_bytes <= 0) {
        std::cerr << "Error receiving data from client." << std::endl;
        close(client_socket);
        return;
    }

    // Separate headers from body
    std::size_t header_end = received_data.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        std::cerr << "Invalid HTTP request: No header-body separation found." << std::endl;
        close(client_socket);
        return;
    }

    std::string headers = received_data.substr(0, header_end);
    body = received_data.substr(header_end + 4);  // +4 to skip "\r\n\r\n"

    // Trim any leading or trailing whitespace from the body
    body.erase(0, body.find_first_not_of(" \n\r\t"));
    body.erase(body.find_last_not_of(" \n\r\t") + 1);

    std::cout << "Received headers:\n" << headers << std::endl;
    std::cout << "Received body: " << body << std::endl;

    // Parse the CSV data from the body
    std::vector<double> fct_values;
    std::istringstream ss(body);
    std::string fct_str;

    while (std::getline(ss, fct_str, ',')) {
        try {
            // Trim leading and trailing whitespace
            fct_str.erase(0, fct_str.find_first_not_of(" \n\r\t"));
            fct_str.erase(fct_str.find_last_not_of(" \n\r\t") + 1);

            if (!fct_str.empty()) {
                double fct_value = std::stod(fct_str);
                fct_values.push_back(fct_value);
                //std::cout << "Parsed FCT: " << fct_value << std::endl;
            }
        } catch (const std::invalid_argument&) {
            std::cerr << "Invalid FCT value: \"" << fct_str << "\"" << std::endl;
        }
    }

    // Calculate and log statistics
    if (!fct_values.empty()) {
        double sum = std::accumulate(fct_values.begin(), fct_values.end(), 0.0);
        double mean = sum / fct_values.size();

        double variance = 0.0;
        for (double fct : fct_values) {
            variance += (fct - mean) * (fct - mean);
        }
        variance /= fct_values.size();

        double std_dev = std::sqrt(variance);

        // Log flow completion times and statistics
        std::ofstream log_file("result/" + save_dir + "/flow_completion_time.log");
        log_file << "Index,FCT\n";
        for (size_t i = 0; i < fct_values.size(); ++i) {
            log_file << i << "," << fct_values[i] << "\n";
        }
        log_file << "\nMean FCT: " << mean << "\n";
        log_file << "Standard Deviation FCT: " << std_dev << "\n";
        log_file.close();

        std::cout << "Mean FCT: " << mean << " ms, Standard Deviation FCT: " << std_dev << " ms" << std::endl;// Send success response to client
        std::string success_response = "HTTP/1.1 200 OK\r\n"
                                       "Content-Type: text/plain\r\n"
                                       "Content-Length: 7\r\n"
                                       "\r\n"
                                       "SUCCESS";
        send(client_socket, success_response.c_str(), success_response.size(), 0);
    } else {
        std::cerr << "No valid FCT values received." << std::endl;
        // Send error response to client
        std::string error_response = "HTTP/1.1 400 Bad Request\r\n"
                                     "Content-Type: text/plain\r\n"
                                     "Content-Length: 21\r\n"
                                     "\r\n"
                                     "No valid FCT received";
        send(client_socket, error_response.c_str(), error_response.size(), 0);
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
