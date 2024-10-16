#ifndef TORRENT_DECODER
#define TORRENT_DECODER

#include "nlohmann/json.hpp"

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

#endif