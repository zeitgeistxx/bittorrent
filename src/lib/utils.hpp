#ifndef UTILS
#define UTILS

#include <fstream>

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

std::string calculate_info_hash(const json &info_dict)
{
    auto bencoded_info = bencode_torrent(info_dict);

    SHA1 sha1;
    sha1.update(bencoded_info);
    return sha1.final();
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

#endif