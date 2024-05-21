#include <iostream>
#include <cstring>
#include <cassert>
#include <fstream>
#include <vector>
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <net/if.h>
#include "BPF.h"

using namespace std;

// Constants
const char interface[] = "ens33"; // Constant for network interface
string prefix_path = "./decision_tree/Trained_model_1"; // Constant for ML prefix path

// Function to read binary files into a vector
std::vector<int64_t> read_file(string filename) {
    std::streampos fileSize;
    std::ifstream file(filename, std::ios::binary);
    file.seekg(0, std::ios::end);
    fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<int64_t> fileData(fileSize / sizeof(int64_t));
    file.read((char*)&fileData[0], fileSize);
    return fileData;
}

int main(int argc, char *argv[]) {
    // Load decision tree and other data
    vector<int64_t> children_left = read_file(prefix_path + "/childrenLeft");
    vector<int64_t> children_right = read_file(prefix_path + "/childrenRight");
    vector<int64_t> value = read_file(prefix_path + "/value");
    vector<int64_t> feature = read_file(prefix_path + "/feature");
    vector<int64_t> threshold = read_file(prefix_path + "/threshold");

    // Create BPF map and program definitions
    string maps_string = string("#include \"openstate.h\"\n") +
        "BPF_TABLE(\"lru_hash\", struct XFSMTableKey, struct XFSMTableLeaf, xfsm_table, 10000);" +
        "BPF_ARRAY(num_processed, u64, 1);" +
        "BPF_ARRAY(all_features, s64, 12);" +
        "BPF_ARRAY(children_left, s64, " + to_string(children_left.size()) + ");" +
        "BPF_ARRAY(children_right, s64, " + to_string(children_right.size()) + ");" +
        "BPF_ARRAY(value, s64, " + to_string(value.size()) + ");" +
        "BPF_ARRAY(feature, s64, " + to_string(feature.size()) + ");" +
        "BPF_ARRAY(threshold, s64, " + to_string(threshold.size()) + ");\n";

    // Load eBPF program source code
    std::ifstream source_stream("ebpf.c");
    std::string ebpf_program((std::istreambuf_iterator<char>(source_stream)),
        std::istreambuf_iterator<char>());

    // Prepend map definitions to the eBPF program
    ebpf_program = maps_string + ebpf_program;

    // Initialize eBPF program
    ebpf::BPF bpf;
    auto res = bpf.init(ebpf_program);
    if (res.code() != 0) {
        std::cerr << res.msg() << std::endl;
        return 1;
    }

    // Load decision tree data into BPF arrays
    ebpf::BPFArrayTable<int64_t> children_left_table = bpf.get_array_table<int64_t>("children_left");
    for (size_t i = 0; i < children_left.size(); i++) {
        res = children_left_table.update_value(i, children_left[i]);
        assert(res.code() == 0);
    }
    ebpf::BPFArrayTable<int64_t> children_right_table = bpf.get_array_table<int64_t>("children_right");
    for (size_t i = 0; i < children_right.size(); i++) {
        res = children_right_table.update_value(i, children_right[i]);
        assert(res.code() == 0);
    }
    ebpf::BPFArrayTable<int64_t> value_table = bpf.get_array_table<int64_t>("value");
    for (size_t i = 0; i < value.size(); i++) {
        res = value_table.update_value(i, value[i]);
        assert(res.code() == 0);
    }
    ebpf::BPFArrayTable<int64_t> threshold_table = bpf.get_array_table<int64_t>("threshold");
    for (size_t i = 0; i < threshold.size(); i++) {
        res = threshold_table.update_value(i, threshold[i]);
        assert(res.code() == 0);
    }
    ebpf::BPFArrayTable<int64_t> feature_table = bpf.get_array_table<int64_t>("feature");
    for (size_t i = 0; i < feature.size(); i++) {
        res = feature_table.update_value(i, feature[i]);
        assert(res.code() == 0);
    }

    // Load the BPF program into the kernel
    int fd;
    res = bpf.load_func("filter", BPF_PROG_TYPE_SOCKET_FILTER, fd);
    assert(res.code() == 0);

    // Attach the BPF program to a raw socket
    int sd = bpf_open_raw_sock("ens33");
    int ret = setsockopt(sd, SOL_SOCKET, SO_ATTACH_BPF, &fd, sizeof(fd));
    assert(ret >= 0);
    std::cout << "Finished loading eBPF kernel program." << std::endl;

    // Start a TCP server to handle the IDS packets
    int server_fd, client_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    int port = 9000;

    // Creating socket file descriptor
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        return 1;
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        return 1;
    }

    std::cout << "Waiting for incoming connections on port " << port << std::endl;

    client_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
    if (client_socket < 0) {
        perror("accept failed");
        return 1;
    }

    // Loop to handle incoming data
    while (true) {
        char buffer[1024] = { 0 };
        int valread = read(client_socket, buffer, 1024);
        if (valread < 0) {
            perror("read error");
            break;
        } else if (valread == 0) {
            std::cout << "Connection closed by client" << std::endl;
            break;
        }
        // Log received data
        // std::cout << "Packet received: " << buffer << std::endl;
        // Process the received data
    }

    // Clean up and close sockets
    close(client_socket);
    close(server_fd);
    std::cout << "Finished processing." << std::endl;

    return 0;
}

