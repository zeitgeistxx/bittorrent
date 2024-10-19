#ifndef UTILS
#define UTILS

#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>

ssize_t receive_all(int &sockfd, char *buffer, size_t length)
{
    ssize_t total_received = 0;

    while (total_received < length)
    {
        auto bytes_received = recv(sockfd, buffer + total_received, length - total_received, 0);

        if (bytes_received < 0)
        {
            perror("recv");
            std::cerr << "Failed after receiving " << total_received << " bytes." << std::endl;
            return 0;
        }
        else if (bytes_received == 0)
        {
            std::cerr << "Received " << total_received << " bytes." << std::endl;
            break;
        }
        total_received += bytes_received;
    }
    return total_received;
}

// receive peer message and extract message id and payload length
bool receive_peer_message(int &client_socket, int &message_id, size_t &payload_length)
{
    char header[5] = {0}; // 4B (message_length) + 1B (message_id)

    auto bytes_received = receive_all(client_socket, header, sizeof(header));
    if (bytes_received != sizeof(header))
    {
        std::cerr << "Failed to receive peer message header." << std::endl;
        return false;
    }

    uint32_t length = ntohl(*(uint32_t *)header);       // Convert network byte order to host byte order
    message_id = static_cast<unsigned char>(header[4]); // 5th byte is the message ID

    if (length > 1)
    {
        payload_length = length - 1;
    }
    return true;
}

void split_ip_port(const std::string &peer, std::string &ip, int &port)
{
    size_t colon_pos = peer.find(':');
    if (colon_pos == std::string::npos)
    {
        std::cerr << "Invalid peer information format." << std::endl;
    }

    ip = peer.substr(0, colon_pos);
    port = std::stoi(peer.substr(colon_pos + 1));
}

std::string hex_to_string(const std::string &in)
{
    std::string output;
    if ((in.length() % 2) != 0)
    {
        throw std::runtime_error("String is not valid length ...");
    }
    size_t cnt = in.length() / 2;
    for (size_t i = 0; cnt > i; ++i)
    {
        uint32_t s = 0;
        std::stringstream ss;
        ss << std::hex << in.substr(i * 2, 2);
        ss >> s;
        output.push_back(static_cast<unsigned char>(s));
    }
    return output;
}

std::string calculate_hash(const std::string input)
{
    SHA1 sha1;
    sha1.update(input);
    return sha1.final();
}

std::string calculate_info_hash(const json &info_dict)
{
    auto bencoded_info = bencode_torrent(info_dict);

    return calculate_hash(bencoded_info);
}

std::string calculate_piece_hash(const std::string &info_piece)
{
    std::stringstream ss;
    for (unsigned char byte : info_piece)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

bool check_piece_integrity(const std::string data, const std::string piece_hash)
{
    auto computed_hash = calculate_hash(data);
    if (computed_hash != piece_hash)
    {
        std::cerr << "Hash mismatched. Expected: " << piece_hash << ", Computed: " << computed_hash << std::endl;
        return false;
    }
    return true;
}

std::string read_file(const std::string &filename)
{
    std::ifstream file(filename, std::ios::binary);

    if (!file.is_open())
    {
        throw std::runtime_error("Unable to find file: " + filename);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    return buffer.str();
}

bool create_directory_if_not_exists(const std::string &dir)
{
    struct stat info;
    if (stat(dir.c_str(), &info) != 0) // if diretory not exists
    {
        if (mkdir(dir.c_str(), 0777) != 0) // crate directory
        {
            std::cerr << "Failed to create directory: " << dir << std::endl;
            return false;
        }
    }
    else if (!(info.st_mode & S_IFDIR))
    {
        std::cerr << dir << " is not a directory." << std::endl;
        return false;
    }
    return true;
}

bool write_to_file(const std::string filename, const char *buffer, int length)
{
    std::string dir = filename.substr(0, filename.find_last_of('/'));

    if (!create_directory_if_not_exists(dir))
    {
        return false;
    }

    std::ofstream output_file(filename, std::ios::binary);
    if (!output_file)
    {
        std::cerr << "Failed to open output file." << std::endl;
        return false;
    }

    output_file.write(buffer, length);
    if (!output_file)
    {
        std::cerr << "Failed to write to output file." << std::endl;
        return false;
    }

    return true;
}

#endif