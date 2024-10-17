#ifndef DOWNLOAD_PIECE
#define DOWNLOAD_PIECE

#include <cstring>
#include <cstdio>
#include <netinet/in.h>
#include <sys/socket.h>

// peer message
// prefix (4 bytes)
// message id (1 byte)
// payload (variable size)

void sendInterested(int &sockfd)
{
    unsigned char message[5] = {0};
    message[0] = 0;
    message[1] = 2;

    int message_len = htonl(1); // Length of payload (1 byte for interested)

    memcpy(message + 0, &message_len, sizeof(message_len));

    send(sockfd, message, sizeof(message), 0);
}

void waitForUnchoke(int &sockfd)
{
    unsigned char buffer[5];
    recv(sockfd, buffer, sizeof(buffer), 0);

    if (buffer[1] == 1)
    {
        std::cout << "Received unchoke message." << std::endl;
    }
}

void requestPiece(int &sockfd, int piece_index, size_t piece_length)
{
    unsigned char request[17];
    request[0] = 0;
    request[1] = 6;

    int index_network_order = htonl(piece_index);
    memcpy(request + 2, &index_network_order, sizeof(index_network_order));

    int begin_network_order = htonl(0);
    memcpy(request + 6, &begin_network_order, sizeof(begin_network_order));

    int length_network_order = htonl(16384); // 16 kiB (16 * 1024 bytes)
    memcpy(request + 10, &length_network_order, sizeof(length_network_order));

    send(sockfd, request, sizeof(request), 0);
}

void receivePiece(int &sockfd, const std::string &output_file, int piece_index, size_t piece_length)
{
    unsigned char buffer[16384 + 9];

    FILE *file = fopen(output_file.c_str(), "wb");

    while (true)
    {
        int bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);

        if (bytes_received <= 0)
            break;

        if (buffer[1] == 7)
        {
            fwrite(buffer + 9, sizeof(unsigned char), bytes_received - 9, file);
            break;
        }
    }

    fclose(file);
}

#endif