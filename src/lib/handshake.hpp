#ifndef PEER_HANDSHAKE
#define PEER_HANDSHAKE

#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>

void sendHandShake(const std::string &peer_ip, int peer_port, const std::string &info_hash, const std::string &peer_id)
{
    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Socket creation failed");
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(peer_port);

    if (inet_pton(AF_INET, peer_ip.c_str(), &server_addr.sin_addr) <= 0)
    {
        perror("Invalid address/ Address not supported");
        close(sockfd);
        return;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Connection failed");
        close(sockfd);
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

    send(sockfd, message.c_str(), message.length(), 0);

    unsigned char response[68];
    recv(sockfd, response, sizeof(response), 0);

    close(sockfd);

    std::cout << "Peer ID: ";
    for (size_t i = 48; i < 68; ++i)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(response[i]);
        if (i < 67)
            std::cout << "";
    }

    std::cout << std::dec << std::endl;
}

#endif