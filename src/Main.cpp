#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;

json decode_bencoded_string(const std::string &encoded_string, size_t &position)
{
    size_t colon_index = encoded_string.find(':', position);
    if (colon_index != std::string::npos)
    {
        std::string string_size_str = encoded_string.substr(position, colon_index - position);
        int64_t string_size_int = std::atoll(string_size_str.c_str());
        position = colon_index + 1 + string_size_int;
        std::string str = encoded_string.substr(colon_index + 1, string_size_int);
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
        if (encoded_list[position] == 'l')
        {
            list.push_back(decode_bencoded_list(encoded_list, position));
        }
        else if (std::isdigit(encoded_list[position]))
        {
            list.push_back(decode_bencoded_string(encoded_list, position));
        }
        else if (encoded_list[position] == 'i')
        {
            list.push_back(decode_bencoded_integer(encoded_list, position));
        }
        else if (encoded_list[position] == 'e')
        {
            position++;
            return list;
        }
    }
    return list;
}

json decode_bencoded_dictionary(const std::string &encoded_dictionary, size_t &position)
{
    json dict = json::object();
    position++;

    while (position < encoded_dictionary.length())
    {
        if (encoded_dictionary[position] == 'e')
        {
            position++;
            return dict;
        }

        json key = decode_bencoded_string(encoded_dictionary, position);
        if (std::isdigit(encoded_dictionary[position]))
        {
            dict[key] = decode_bencoded_string(encoded_dictionary, position);
        }
        else if (encoded_dictionary[position] == 'i')
        {
            dict[key] = decode_bencoded_integer(encoded_dictionary, position);
        }
        else if (encoded_dictionary[position] == 'l')
        {
            dict[key] = decode_bencoded_list(encoded_dictionary, position);
        }
        else if (encoded_dictionary[position] == 'd')
        {
            dict[key] = decode_bencoded_dictionary(encoded_dictionary, position);
        }
    }

    throw std::runtime_error("Invalid dictionary encoding");
}

json decode_bencoded_value(const std::string &encoded_value, size_t &position)
{
    if (std::isdigit(encoded_value[position]))
    {
        return decode_bencoded_string(encoded_value, position);
    }
    else if (encoded_value[position] == 'i')
    {
        return decode_bencoded_integer(encoded_value, position);
    }
    else if (encoded_value[position] == 'l')
    {
        return decode_bencoded_list(encoded_value, position);
    }
    else if (encoded_value[position] == 'd')
    {
        return decode_bencoded_dictionary(encoded_value, position);
    }
    else
    {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}

json decode_bencoded_value(const std::string &encoded_value)
{
    size_t position = 0;
    return decode_bencoded_value(encoded_value, position);
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
    else
    {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
