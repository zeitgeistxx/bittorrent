#ifndef PEER_HANDSHAKE
#define PEER_HANDSHAKE

#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <cstring>

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

    memset(&server_addr, 0, sizeof(server_addr));
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

    unsigned char handshake[68] = {0};
    handshake[0] = 19;
    memcpy(handshake + 1, "BitTorrent protocol", 19);
    memset(handshake + 20, 0, 8);

    memcpy(handshake + 28, info_hash.data(), 20);
    memcpy(handshake + 48, peer_id.data(), 20);

    std::cout << "Handshake in Hexadecimal: ";
    for (int i = 0; i < 68; ++i)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(handshake[i]) << " ";
    }
    std::cout << std::dec << std::endl;

    send(sockfd, handshake, sizeof(handshake), 0);

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