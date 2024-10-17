#include <iostream>
#include <iomanip>
#include <string>
#include <cctype>
#include <cstdlib>
#include <sstream>

#include "lib/decoder.hpp"
#include "lib/encoder.hpp"
#include "lib/sha.hpp"
#include "lib/tracker.hpp"
#include "lib/handshake.hpp"
#include "lib/utils.hpp"
#include "lib/download.hpp"

std::string piece_hashes(const std::string &info_piece)
{
    std::stringstream ss;
    for (unsigned char byte : info_piece)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

void parse_torrent(const std::string &filename)
{
    auto content = read_file(filename);
    auto decoded_data = decode_bencoded_value(content);

    std::string tracker_url;
    decoded_data["announce"].get_to(tracker_url);
    std::cout << "Tracker URL: " << tracker_url << std::endl;
    std::cout << "Length: " << decoded_data["info"]["length"] << std::endl;

    std::cout << "Info Hash: " << calculate_info_hash(decoded_data["info"]) << std::endl;

    std::cout << "Piece Length: " << decoded_data["info"]["piece length"] << std::endl;

    std::cout << "Piece Hashes: " << std::endl;
    for (size_t i = 0; i < decoded_data["info"]["pieces"].get<std::string>().length(); i += 20)
    {
        std::string piece = decoded_data["info"]["pieces"].get<std::string>().substr(i, 20);
        std::cout << piece_hashes(piece) << std::endl;
    }
}

std::vector<std::string> discover_peers(const std::string &filename)
{
    auto content = read_file(filename);
    auto decoded_data = decode_bencoded_value(content);

    auto tracker_url = decoded_data["announce"].get<std::string>();

    auto info_hash = calculate_info_hash(decoded_data["info"]);

    const auto peer_id = generatePeerID();
    int port = 6881;
    int uploaded = 0;
    int downloaded = 0;
    int left = decoded_data["info"]["length"];

    return request_tracker(tracker_url, info_hash, peer_id, port, uploaded, downloaded, left);
}

std::string peer_handshake(const std::string &filename, const std::string &peer, int &sockfd, const std::string peer_id)
{
    auto content = read_file(filename);
    auto decoded_data = decode_bencoded_value(content);

    std::string peer_ip;
    int peer_port;
    split_ip_port(peer, peer_ip, peer_port);

    // const auto peer_id = generatePeerID();
    const auto hash = calculate_info_hash(decoded_data["info"]);
    const auto info_hash = hex_to_string(hash);

    return sendHandShake(peer_ip, peer_port, info_hash, peer_id, sockfd);
}

void piece_download(const std::string output_file, const std::string &filename, int piece_index)
{
    auto content = read_file(filename);
    auto decoded_data = decode_bencoded_value(content);
    size_t piece_length = decoded_data["info"]["piece length"];

    auto peers = discover_peers(filename);
    const auto peer_id = generatePeerID();
    for (const auto peer : peers)
    {
        int sockfd;
        peer_handshake(filename, peer, sockfd, peer_id);

        if (!download_piece(sockfd, piece_index, piece_length, filename))
        {
            close(sockfd);
            return;
        }
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
        int sockfd;
        auto peerID = peer_handshake(filename, peer_info, sockfd);
        close(sockfd);
        std::cout << "Peer ID: " << peerID << std::endl;
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
        int piece_index = std::atoi(argv[5]);
        piece_download(output_file, filename, piece_index);
    }
    else
    {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
