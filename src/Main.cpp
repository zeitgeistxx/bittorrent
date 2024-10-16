#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>

#include "lib/nlohmann/json.hpp"
#include "lib/sha.hpp"

using json = nlohmann::json;

// Function prototypes
json decode_bencoded_value(const std::string &encoded_value, size_t &position);

json decode_bencoded_string(const std::string &encoded_string, size_t &position)
{
    size_t colon_index = encoded_string.find(':', position);
    if (colon_index != std::string::npos)
    {
        int string_length = std::stoi(encoded_string.substr(position, colon_index - position));
        position = colon_index + 1;
        std::string str = encoded_string.substr(position, string_length);
        position += string_length;

        return json(str);
    }
    else
    {
        throw std::runtime_error("Invalid encoded string: " + encoded_string);
    }
}

json decode_bencoded_integer(const std::string &encoded_number, size_t &position)
{
    position++;
    size_t end = encoded_number.find('e', position);
    if (end == std::string::npos)
    {
        throw std::invalid_argument("Invalid bencoded integer");
    }
    std::string integer_str = encoded_number.substr(position, end - position);
    position = end + 1;
    return std::stoll(integer_str);
}

json decode_bencoded_list(const std::string &encoded_list, size_t &position)
{
    json list = json::array();
    position++;

    while (position < encoded_list.length())
    {
        if (encoded_list[position] == 'e')
        {
            position++;
            return list;
        }

        list.push_back(decode_bencoded_value(encoded_list, position));
    }

    throw std::runtime_error("Invalid list encoding");
}

json decode_bencoded_dictionary(const std::string &encoded_dictionary, size_t &position)
{
    position++;
    json dict = json::object();

    while (position < encoded_dictionary.length())
    {
        if (encoded_dictionary[position] == 'e')
        {
            position++;
            return dict;
        }

        json key = decode_bencoded_string(encoded_dictionary, position);
        dict[key] = decode_bencoded_value(encoded_dictionary, position);
    }
    throw std::runtime_error("Invalid dictionary encoding");
}

json decode_bencoded_value(const std::string &encoded_value, size_t &position)
{
    char type = encoded_value[position];
    switch (type)
    {
    case 'i':
        return decode_bencoded_integer(encoded_value, position);
    case 'l':
        return decode_bencoded_list(encoded_value, position);
    case 'd':
        return decode_bencoded_dictionary(encoded_value, position);
    default:
        if (std::isdigit(type))
        {
            return decode_bencoded_string(encoded_value, position);
        }
        else
        {
            throw std::runtime_error("Invalid encoded value.");
        }
    }
}

json decode_bencoded_value(const std::string &encoded_value)
{
    size_t position = 0;
    return decode_bencoded_value(encoded_value, position);
}

std::string bencode_info_dict(const json &info_dict)
{
    std::ostringstream os;
    if (info_dict.is_object())
    {
        os << 'd';
        for (auto &el : info_dict.items())
        {
            os << el.key().size() << ':' << el.key() << bencode_info_dict(el.value());
        }
        os << 'e';
    }
    else if (info_dict.is_array())
    {
        os << 'l';
        for (const json &item : info_dict)
        {
            os << bencode_info_dict(item);
        }
        os << 'e';
    }
    else if (info_dict.is_number_integer())
    {
        os << 'i' << info_dict.get<int>() << 'e';
    }
    else if (info_dict.is_string())
    {
        const std::string &value = info_dict.get<std::string>();
        os << value.size() << ':' << value;
    }
    return os.str();
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

void parse_torrent(const std::string &filename)
{
    std::string content = read_file(filename);
    auto decoded_data = decode_bencoded_value(content);
    auto bencoded_info = bencode_info_dict(decoded_data["info"]);

    std::string tracker_url;
    decoded_data["announce"].get_to(tracker_url);
    std::cout << "Tracker URL: " << tracker_url << std::endl;
    std::cout << "Length: " << decoded_data["info"]["length"] << std::endl;

    SHA1 sha1;
    sha1.update(bencoded_info);
    auto info_hash = sha1.final();
    std::cout << "Info Hash: " << info_hash << std::endl;

    std::cout << "Piece Length: " << decoded_data["info"]["piece length"] << std::endl;

    std::cout << "Piece Hashes: " << std::endl;
    for (size_t i = 0; i < decoded_data["info"]["pieces"].get<std::string>().length(); i += 20)
    {
        std::string piece = decoded_data["info"]["pieces"].get<std::string>().substr(i, 20);
        std::stringstream ss;
        for (unsigned char byte : piece)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::cout << ss.str() << std::endl;
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
        json decoded_value = decode_bencoded_value(encoded_value);
        std::cout << decoded_value.dump() << std::endl;
    }
    else if (command == "info")
    {
        if (argc < 3)
        {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }
        std::string filename = argv[2];
        parse_torrent(filename);
    }
    else
    {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
