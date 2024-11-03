#ifndef DOWNLOAD_PIECE
#define DOWNLOAD_PIECE

#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <optional>
#include <sys/socket.h>
#include <unordered_map>

#include "work_queue.hpp"
#include "utils.hpp"

// htonl() function stands for "host to network long", used in network
// programming to convert a 32-bit integer from host byte order to network byte
// order. Network byte order is big-endian, which means the most significant
// byte is stored at the lowest memory address.

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
        auto bytes_skipped = receive_all(sockfd, payload_buffer, payload_length);
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

    uint32_t message_len = htonl(1); // Length of payload (1B for message_id)

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
                auto bytes_skipped = receive_all(sockfd, payload_buffer, payload_length);
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
    char request[17]; // 4B (message_length) + 1B (message_id) + 12B (payload_length = piece_index + piece_offset + piece_length)

    auto request_len = htonl(13); // paylaod + message_id

    memcpy(request, &request_len, sizeof(request_len));
    request[4] = 6;

    // payload
    auto piece_index_network = htonl(piece_index);
    auto block_offset_network = htonl(block_offset);
    auto block_length_network = htonl(block_length);

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

bool receivePiece(int &sockfd, std::vector<uint8_t> &piece_buffer, int piece_index, int block_offset, size_t block_length)
{
    char message_header[13]; // 4B (message_length) + 1B (message_id) + 4B (piece_index) + 4B (block_offset)

    auto bytes_received = receive_all(sockfd, message_header, sizeof(message_header));

    if (bytes_received < 0)
    {
        std::cerr << "Error receiving piece header: " << strerror(errno) << std::endl;
        return false;
    }
    else if (bytes_received == 0)
    {
        std::cerr << "Connection closed by the peer while receiving piece header." << std::endl;
        return false;
    }

    // extract message length (first 4 bytes)
    auto message_len = ntohl(*reinterpret_cast<uint32_t *>(message_header));

    // extract next 1 byte for message_id
    auto message_id = static_cast<uint8_t>(message_header[4]);
    if (message_id != 7)
    {
        std::cerr << "Unexpected message ID: " << static_cast<int>(message_id) << std::endl;
        return false;
    }

    // extract the piece index and block offset
    auto received_piece_index = ntohl(*reinterpret_cast<uint32_t *>(message_header + 5));
    auto received_block_offset = ntohl(*reinterpret_cast<uint32_t *>(message_header + 9));

    if (received_piece_index != piece_index || received_block_offset != block_offset)
    {
        std::cerr << "Piece or block offset mismatch. Expected piece index: " << piece_index << ", received: " << received_piece_index << ", Expected block offset: " << block_offset << ", received: " << received_block_offset << std::endl;
        return false;
    }

    ssize_t block_bytes_received = receive_all(sockfd, reinterpret_cast<char*>(piece_buffer.data()) + block_offset, block_length);
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

std::optional<std::vector<uint8_t>> download_piece(int &client_socket, const int &file_length, const int &piece_index, const int &piece_length, const std::string &pieces, bool skip_initial_handshake)
{
    if (!skip_initial_handshake)
    {
        if (!waitForBitField(client_socket))
        {
            return std::nullopt;
        }

        if (!sendInterested(client_socket))
        {
            return std::nullopt;
        }
    }

    if (!waitForUnchoke(client_socket))
    {
        return std::nullopt;
    }

    const int BLOCK_SIZE = 16 * 1024; // break piece into blocks of 16 KiB
    size_t total_received = 0;

    const auto downloaded = piece_index * piece_length;
    if (downloaded >= file_length)
    {
        return std::nullopt;
    }

    const auto actual_piece_length = std::min(piece_length, file_length - downloaded);

    std::vector<uint8_t> piece_buffer(actual_piece_length);

    for (int block_offset = 0; block_offset < actual_piece_length; block_offset += BLOCK_SIZE)
    {
        auto left_to_download = file_length - downloaded - block_offset;
        auto block_length = std::min(BLOCK_SIZE, left_to_download);

        if (block_length == 0)
        {
            break;
        }

        if (!requestPiece(client_socket, piece_index, block_offset, block_length))
        {
            return std::nullopt;
        }

        if (!receivePiece(client_socket, piece_buffer, piece_index, block_offset, block_length))
        {
            return std::nullopt;
        }

        total_received += block_length;

        if (total_received >= actual_piece_length)
        {
            break; // all blocks for this piece have been downloaded
        }
    }

    const auto piece_hash = calculate_piece_hash(pieces.substr(piece_index * 20, 20));
    if (!check_piece_integrity(piece_buffer, piece_hash))
    {
        return std::nullopt;
    }

    return piece_buffer;
}

bool process_torrent_download(const std::string &info_hash, const std::vector<std::string> &peers, const int &file_length, const int &piece_length, const std::string &pieces, const std::string &output_filename)
{
    const auto piece_count = (int)(ceil(static_cast<double>(file_length) / static_cast<double>(piece_length)));
    std::cout << "pieces -> " << piece_count << std::endl;

    ThreadSafeWorkQueue<int> work_queue;
    std::unordered_map<int, int> retry_count;

    for (int piece_index = 0; piece_index < piece_count; ++piece_index)
    {
        work_queue.push(piece_index);
        retry_count[piece_index] = 0;
    }

    std::mutex conn_mtx;
    std::mutex write_mtx;
    std::vector<std::optional<std::vector<uint8_t>>> downloaded_pieces(piece_count);
    std::unordered_map<std::string, int> active_connections;
    std::unordered_map<std::string, bool> initial_handshake_done;
    std::atomic<bool> download_failed(false);

    auto worker = [&](const std::string &peer_info)
    {
        int client_socket;
        {
            std::lock_guard<std::mutex> lock(conn_mtx);
            client_socket = connect_to_peer(peer_info, info_hash);
            if (client_socket < 0)
            {
                std::cerr << "Failed to connect to peer: " << peer_info << std::endl;
                download_failed = true;
                return;
            }
            active_connections[peer_info]++;
            initial_handshake_done[peer_info] = false;
        }

        while (!work_queue.is_done() && !download_failed)
        {
            int piece_index;
            if (work_queue.try_pop(piece_index))
            {
                std::cout << "processing piece-" << piece_index << std::endl;
                bool skip_handshake = initial_handshake_done[peer_info];
                auto piece_data = download_piece(client_socket, file_length, piece_index, piece_length, pieces, skip_handshake);
                if (piece_data.has_value())
                {
                    initial_handshake_done[peer_info] = true;
                    std::lock_guard<std::mutex> lock(write_mtx);
                    downloaded_pieces[piece_index] = piece_data.value();
                }
                else
                {
                    if (retry_count[piece_index] < 3)
                    {
                        retry_count[piece_index]++;
                        work_queue.push(piece_index);
                    }
                    else
                    {
                        std::cerr << "Max retries reached for piece " << piece_index << std::endl;
                        download_failed = true;
                    }
                }
            }
        }

        {
            std::lock_guard<std::mutex> lock(conn_mtx);
            active_connections[peer_info]--;
            if (active_connections[peer_info] == 0)
            {
                close(client_socket);
                active_connections.erase(peer_info);
            }
        }
    };

    std::vector<std::thread> workers;
    for (const auto &peer : peers)
    {
        workers.emplace_back(worker, peer);
    }
    work_queue.set_done();

    for (auto &worker_thread : workers)
    {
        if (worker_thread.joinable())
        {
            worker_thread.join();
        }
    }

    if (download_failed)
    {
        downloaded_pieces.clear();
        std::cerr << "File download failed due to repeated piece download failures." << std::endl;
        return false;
    }

    for (const auto &piece_data : downloaded_pieces)
    {
        if (piece_data.has_value())
        {
            write_piece_to_file(output_filename, piece_data.value());
        }
        else
        {
            std::cerr << "Missing or corrupted piece" << std::endl;
            return false;
        }
    }
    return true;
}

#endif
