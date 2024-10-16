#include <iostream>
#include <iomanip>
#include <string>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>

#include "lib/decoder.hpp"
#include "lib/encoder.hpp"
#include "lib/sha.hpp"
#include "lib/tracker.hpp"
#include "lib/handshake.hpp"

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

std::string read_file(const std::string &filename)
{
    std::ifstream file(filename, std::ios::binary);

    if (!file.is_open())
    {
        throw std::runtime_error("Unable to find file: " + filename);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    return buffer.str();
}

std::string calculate_info_hash(const json &info_dict)
{
    auto bencoded_info = bencode_torrent(info_dict);

    SHA1 sha1;
    sha1.update(bencoded_info);
    return sha1.final();
}

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

void discover_peers(const std::string &filename)
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

    request_tracker(tracker_url, info_hash, peer_id, port, uploaded, downloaded, left);
}

void peer_handshake(const std::string &filename, const std::string &peer_info)
{
    auto content = read_file(filename);
    auto decoded_data = decode_bencoded_value(content);

    size_t colon_pos = peer_info.find(':');
    if (colon_pos == std::string::npos)
    {
        std::cerr << "Invalid peer information format." << std::endl;
        return;
    }

    std::string peer_ip = peer_info.substr(0, colon_pos);
    int peer_port = std::stoi(peer_info.substr(colon_pos + 1));

    const auto peer_id = generatePeerID();
    auto info_hash = calculate_info_hash(decoded_data["info"]);
    auto hex_info_hash = hex_to_string(info_hash);

    sendHandShake(peer_ip, peer_port, info_hash, peer_id);
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
        discover_peers(filename);
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
    else
    {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
