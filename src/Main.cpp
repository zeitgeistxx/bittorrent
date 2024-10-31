#include <iostream>
#include <cctype>
#include <cstdlib>
#include <string>

#include "lib/download.hpp"
#include "lib/handshake.hpp"
#include "lib/tracker.hpp"
#include "lib/utils.hpp"

void parse_torrent(const std::string filename)
{
    json info;
    std::string tracker_url, pieces;
    size_t length, piece_length;

    torrent_file_info(filename, tracker_url, info, length, piece_length, pieces);

    std::cout << "Tracker URL: " << tracker_url << std::endl;
    std::cout << "Length: " << length << std::endl;

    std::cout << "Info Hash: " << calculate_info_hash(info) << std::endl;

    std::cout << "Piece Length: " << piece_length << std::endl;

    std::cout << "Piece Hashes: " << std::endl;
    for (size_t i = 0; i < pieces.length(); i += 20)
    {
        auto piece = pieces.substr(i, 20);
        std::cout << calculate_piece_hash(piece) << std::endl;
    }
}

std::vector<std::string> discover_peers(const std::string filename)
{
    json info;
    std::string tracker_url, pieces;
    size_t length, piece_length;

    torrent_file_info(filename, tracker_url, info, length, piece_length, pieces);

    auto info_hash = calculate_info_hash(info);

    const auto peer_id = generatePeerID();
    int port = 6881;
    int uploaded = 0;
    int downloaded = 0;
    int left = length;

    return request_tracker(tracker_url, info_hash, peer_id, port, uploaded, downloaded, left);
}

void peer_handshake(const std::string filename, const std::string &peer)
{
    json info;
    std::string tracker_url, pieces;
    size_t length, piece_length;

    torrent_file_info(filename, tracker_url, info, length, piece_length, pieces);

    std::string peer_ip;
    int peer_port;
    split_ip_port(peer, peer_ip, peer_port);

    const auto peer_id = generatePeerID();
    const auto hash = calculate_info_hash(info);
    const auto info_hash = hex_to_string(hash);

    int sockfd;
    std::cout << "Peer ID: " << sendHandShake(peer_ip, peer_port, info_hash, peer_id, sockfd) << std::endl;
    close(sockfd);
}

void piece_download(const std::string output_file, const std::string torrent_file, const int &piece_index)
{
    json info;
    std::string tracker_url, pieces;
    size_t file_length, piece_length;

    torrent_file_info(torrent_file, tracker_url, info, file_length, piece_length, pieces);

    const auto hash = calculate_info_hash(info);
    const auto info_hash = hex_to_string(hash);

    auto peers = discover_peers(torrent_file);
    auto client_socket = connect_to_peer(peers[0], info_hash);

    auto result = download_piece(client_socket, file_length, piece_index, piece_length, pieces, false);
    if (result.has_value())
    {
        if (!write_piece_to_file(output_file, result.value()))
        {
            std::cout << "write to file failed" << std::endl;
        }
        std::cout << "piece-" << piece_index << " downloaded successfully." << std::endl;
    }
    else
    {
        std::cout << "piece-" << piece_index << " download failed." << std::endl;
    }
    close(client_socket);
}

void file_download(const std::string output_file, const std::string torrent_file)
{
    json info;
    std::string tracker_url, pieces;
    size_t file_length, piece_length;

    torrent_file_info(torrent_file, tracker_url, info, file_length, piece_length, pieces);

    const auto hash = calculate_info_hash(info);
    const auto info_hash = hex_to_string(hash);

    auto peers = discover_peers(torrent_file);

    if (!process_torrent_download(info_hash, peers, file_length, piece_length, pieces, output_file))
    {
        std::cout << "File download failed." << std::endl;
    }
    else
    {
        std::cout << "File downloaded successfully." << std::endl;
    }
}

int main(int argc, char *argv[])
{
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "decode")
    {
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }
        std::string encoded_value = argv[2];
        auto decoded_value = decode_bencoded_value(encoded_value);
        std::cout << decoded_value.dump() << std::endl;
    }
    else if (command == "info")
    {
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " info <torrent_file>" << std::endl;
            return 1;
        }
        std::string filename = argv[2];
        parse_torrent(filename);
    }
    else if (command == "peers")
    {
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " peers <torrent_file>" << std::endl;
            return 1;
        }
        std::string filename = argv[2];
        auto peers = discover_peers(filename);
        for (const auto &peer : peers)
        {
            std::cout << "Peer: " << peer << std::endl;
        }
    }
    else if (command == "handshake")
    {
        if (argc < 4)
        {
            std::cerr << "Usage: " << argv[0] << " handshake <torrent_file> <peer_ip>:<peer_port>" << std::endl;
            return 1;
        }
        std::string filename = argv[2];
        std::string peer_info = argv[3];
        peer_handshake(filename, peer_info);
    }
    else if (command == "download_piece")
    {
        if (argc < 6)
        {
            std::cerr << "Usage: " << argv[0] << " download_piece -o /tmp/<filename> <torrent_file> 0" << std::endl;
            return 1;
        }
        std::string output_file = argv[3];
        std::string filename = argv[4];
        const auto piece_index = std::atoi(argv[5]);
        piece_download(output_file, filename, piece_index);
    }
    else if (command == "download")
    {
        if (argc < 5)
        {
            std::cerr << "Usage: " << argv[0] << " download_piece -o /tmp/<filename> <torrent_file>" << std::endl;
            return 1;
        }
        std::string output_file = argv[3];
        std::string filename = argv[4];
        file_download(output_file, filename);
    }
    else
    {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
