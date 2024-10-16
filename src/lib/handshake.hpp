#ifndef PEER_HANDSHAKE
#define PEER_HANDSHAKE

#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>

std::string hex_str(const std::string &piece)
{
    std::ostringstream ret;
    for (std::string::size_type i = 0; i < piece.length(); ++i)
    {
        ret << std::hex << std::setfill('0') << std::setw(2) << std::nouppercase << (int)(unsigned char)piece[i];
    }
    return ret.str();
}

void sendHandShake(const std::string &peer_ip, int peer_port, const std::string &info_hash, const std::string &peer_id)
{
    int client_fd, valread, status;
    struct sockaddr_in server_addr;
    char buffer[1024] = {0};

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket creation failed");
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(peer_port);

    if (inet_pton(AF_INET, peer_ip.c_str(), &server_addr.sin_addr) <= 0)
    {
        perror("Invalid address/ Address not supported");
        close(client_fd);
        return;
    }

    if ((status = connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr))) < 0)
    {
        perror("Connection failed");
        close(client_fd);
        return;
    }

    std::string message;
    char c = (char)19;
    message.push_back(c);
    message.append("BitTorrent protocol", 19);
    uint8_t arr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    message.append((char *)arr, 8);
    message.append(info_hash);
    message.append(peer_id);

    send(client_fd, message.c_str(), message.length(), 0);
    valread = read(client_fd, buffer, 70);

    std::string response;
    response.append(buffer, valread);

    close(client_fd);

    std::cout << "Peer ID: ";
    std::cout << hex_str(response.substr(48, 20)) << std::endl;
}

#endif