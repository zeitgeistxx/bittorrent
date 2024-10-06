#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;

json decode_bencoded_value(const std::string &encoded_value)
{
    if (std::isdigit(encoded_value[0]))
    {
        // Example: "5:hello" -> "hello"
        size_t colon_index = encoded_value.find(':');
        if (colon_index != std::string::npos)
        {
            std::string number_string = encoded_value.substr(0, colon_index);
            int64_t number = std::atoll(number_string.c_str());
            std::string str = encoded_value.substr(colon_index + 1, number);
            return json(str);
        }
        else
        {
            throw std::runtime_error("Invalid encoded value: " + encoded_value);
        }
    }
    else if (encoded_value[0] == 'i' && encoded_value[encoded_value.length() - 1] == 'e')
    {
        // Example: "i52e" -> 52
        std::string x = encoded_value.substr(1, encoded_value.length() - 2);
        return json(std::atoll(x.c_str()));
    }
    else if (encoded_value[0] == 'l' && encoded_value[encoded_value.length() - 1] == 'e')
    {
        // Example: "l5:helloi52ee" -> ["hello", 52]
        json list = json::array();

        std::string str = encoded_value.substr(1, encoded_value.length() - 2);
        if (std::isdigit(str[0]))
        {
            size_t colon_index = str.find(':');
            std::string number_string = str.substr(0, colon_index);
            int64_t number = std::atoll(number_string.c_str());
            std::string temp_str = str.substr(colon_index + 1, number);
            list.push_back(temp_str);

            str = str.substr(colon_index + number + 1, str.length() - 1);
            if (str[0] == 'i' && str[str.length() - 1] == 'e')
            {
                std::string temp_number = str.substr(1, str.length() - 2);
                list.push_back(std::atoll(temp_number.c_str()));
            }
            return list;
        }
        else
        {
            throw std::runtime_error("Invalid encoded value: " + encoded_value);
        }
    }
    else
    {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
}

int main(int argc, char *argv[])
{
    // Flush after every std::cout / std::cerr
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
