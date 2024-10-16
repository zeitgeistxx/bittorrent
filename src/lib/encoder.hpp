#ifndef TORRENT_ENCODER
#define TORRENT_ENCODER

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

#endif