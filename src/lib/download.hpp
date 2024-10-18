#ifndef DOWNLOAD_PIECE
#define DOWNLOAD_PIECE

#include <cstring>
#include <cstdio>
#include <netinet/in.h>
#include <sys/socket.h>

// htonl() function stands for "host to network long", used in network programming to convert a 32-bit integer from host byte order to network byte order. Network byte order is big-endian, which means the most significant byte is stored at the lowest memory address.

// 0 - choke
// 1 - unchoke
// 2 - interested
// 3 - not interested
// 4 - have
// 5 - bitfield
// 6 - request
// 7 - piece
// 8 - cancel

// peer message
// prefix (4 bytes)
// message id (1 byte)
// payload (variable size)

bool waitForBitField(int &sockfd)
{
    int message_id;
    size_t payload_length;

    if (!receive_peer_message(sockfd, message_id, payload_length))
    {
        return false;
    }

    if (message_id == 5) // skip the payload
    {
        char *payload_buffer = new char[payload_length];
        ssize_t bytes_skipped = recv_all(sockfd, payload_buffer, payload_length);
        delete[] payload_buffer;

        if (bytes_skipped != payload_length)
        {
            std::cerr << "Error skipping bitfield payload." << std::endl;
            return false;
        }
    }
    else
    {
        std::cerr << "Expected bitfield message, but received another message with ID: " << message_id << std::endl;
        return false;
    }
    return true;
}

bool sendInterested(int &sockfd)
{
    unsigned char message[5] = {0};

    uint32_t message_len = htonl(1); // Length of payload (1 byte for message_id)

    memcpy(message, &message_len, sizeof(message_len));
    message[4] = 2;

    auto bytes_sent = send(sockfd, message, sizeof(message), 0);
    if (bytes_sent != sizeof(message))
    {
        std::cerr << "Error sending interested message." << std::endl;
        return false;
    }
    return true;
}

bool waitForUnchoke(int &sockfd)
{
    int message_id;
    size_t payload_length;

    // continuously wait for messages until an unchoke message is received
    while (true)
    {
        if (!receive_peer_message(sockfd, message_id, payload_length))
        {
            return false;
        }

        if (message_id == 1)
        {
            return true;
        }
        else
        {
            if (payload_length > 0)
            {
                char *payload_buffer = new char[payload_length];
                ssize_t bytes_skipped = recv_all(sockfd, payload_buffer, payload_length);
                delete[] payload_buffer;

                if (bytes_skipped != payload_length)
                {
                    std::cerr << "Error skipping message payload." << std::endl;
                    return false;
                }
            }
        }
    }
}

bool requestPiece(int &sockfd, int piece_index, int block_offset, size_t block_length)
{
    char request[17]; // 4 bytes prefix, (1 byte for message_id and 12 bytes for the payload)

    uint32_t request_len = htonl(13); // paylaod + message_id

    memcpy(request, &request_len, sizeof(request_len));
    request[4] = 6;

    // payload
    uint32_t piece_index_network = htonl(piece_index);
    uint32_t block_offset_network = htonl(block_offset);
    uint32_t block_length_network = htonl(block_length);

    memcpy(request + 5, &piece_index_network, sizeof(piece_index_network));
    memcpy(request + 9, &block_offset_network, sizeof(block_offset_network));
    memcpy(request + 13, &block_length_network, sizeof(block_length_network));

    auto bytes_sent = send(sockfd, request, sizeof(request), 0);
    if (bytes_sent != sizeof(request))
    {
        std::cerr << "Error sending request message." << std::endl;
        return false;
    }
    return true;
}

bool receivePiece(int &sockfd, char *piece_buffer, int piece_index, int block_offset, size_t block_length)
{
    // Message header is 9 bytes: 4 bytes for piece index, 4 bytes for block offset, 1 byte for ID
    char message_header[13];

    auto bytes_received = recv_all(sockfd, message_header, sizeof(message_header));

    if (bytes_received < 0)
    {
        std::cerr << "Error receiving piece header: " << strerror(errno) << std::endl;
        return false;
    }
    else if (bytes_received = 0)
    {
        std::cerr << "Connection closed by the peer while receiving piece header." << std::endl;
        return false;
    }

    auto message_len = ntohl(*reinterpret_cast<uint32_t *>(message_header));

    auto message_id = static_cast<uint8_t>(message_header[4]);
    if (message_id != 7)
    {
        std::cerr << "Unexpected message ID: " << static_cast<int>(message_id) << std::endl;
        return false;
    }

    uint32_t received_piece_index = ntohl(*reinterpret_cast<uint32_t *>(message_header + 5));
    uint32_t received_block_offset = ntohl(*reinterpret_cast<uint32_t *>(message_header + 9));

    if (received_piece_index != piece_index || received_block_offset != block_offset)
    {
        std::cerr << "Piece or block offset mismatch. Expected piece index: " << piece_index
                  << ", received: " << received_piece_index
                  << ", Expected block offset: " << block_offset
                  << ", received: " << received_block_offset << std::endl;
        return false;
    }

    ssize_t block_bytes_received = recv_all(sockfd, piece_buffer + block_offset, block_length);
    if (block_bytes_received < 0)
    {
        std::cerr << "Error receiving piece block data: " << strerror(errno) << std::endl;
        return false;
    }
    else if (block_bytes_received == 0)
    {
        std::cerr << "Connection closed before receiving full block data." << std::endl;
        return false;
    }
    if (block_bytes_received != block_length)
    {
        std::cerr << "Expected " << block_length << " bytes, but received " << block_bytes_received << " bytes." << std::endl;
        return false;
    }
    return true;
}

bool download_piece(int &client_socket, int piece_index, int piece_length, const std::string &output_filename)
{
    if (!waitForBitField(client_socket))
    {
        return false;
    }
    std::cout << "Waited for bitfield" << std::endl;

    if (!sendInterested(client_socket))
    {
        return false;
    }
    std::cout << "send interested message" << std::endl;

    if (!waitForUnchoke(client_socket))
    {
        return false;
    }
    std::cout << "Waited for unchoke" << std::endl;

    const int BLOCK_SIZE = 16 * 1024; // break piece into blocks of 16 KiB
    char *piece_buffer = new char[piece_length];
    size_t total_received = 0;

    for (int block_offset = 0; block_offset < piece_length; block_offset += BLOCK_SIZE)
    {
        int block_length = std::min(BLOCK_SIZE, piece_length - block_offset);

        if (!requestPiece(client_socket, piece_index, block_offset, block_length))
        {
            delete[] piece_buffer;
            return false;
        }

        if (!receivePiece(client_socket, piece_buffer, piece_index, block_offset, block_length))
        {
            delete[] piece_buffer;
            return false;
        }

        if (block_length == 0)
        {
            break;
        }

        total_received += block_length;

        if (total_received >= piece_length)
        {
            break; // all blocks for this piece have been received
        }
    }

    if (!write_to_file(output_filename, piece_buffer, piece_length))
    {
        delete[] piece_buffer;
        return false;
    }

    delete[] piece_buffer;
    return true;
}

#endif