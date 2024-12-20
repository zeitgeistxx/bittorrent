#ifndef TRACKERS
#define TRACKERS

#include <curl/curl.h>
#include <vector>

std::string url_encode(const std::string &hex_string)
{
    std::string encoded;
    encoded.reserve(hex_string.length() + hex_string.length() / 2);
    std::array<bool, 256> unreserved{};
    for (size_t i = '0'; i <= '9'; ++i)
        unreserved[i] = true;
    for (size_t i = 'A'; i <= 'Z'; ++i)
        unreserved[i] = true;
    for (size_t i = 'a'; i <= 'z'; ++i)
        unreserved[i] = true;
    unreserved['-'] = true;
    unreserved['_'] = true;
    unreserved['.'] = true;
    unreserved['~'] = true;
    for (size_t i = 0; i < hex_string.length(); i += 2)
    {
        std::string byte_str = hex_string.substr(i, 2);
        int byte_val = std::stoul(byte_str, nullptr, 16);
        if (unreserved[byte_val])
        {
            encoded += static_cast<char>(byte_val);
        }
        else
        {
            encoded += "%" + byte_str;
        }
    }
    return encoded;
}

size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    auto *readBuffer = static_cast<std::vector<char> *>(userp);
    size_t totalSize = size * nmemb;
    readBuffer->insert(readBuffer->end(), (char *)contents, (char *)contents + totalSize);
    return totalSize;
}

std::vector<std::string> request_tracker(const std::string &tracker_url, const std::string &info_hash, const std::string &peer_id, int port, int uploaded, int downloaded, int left)
{
    CURL *curl;
    CURLcode res;
    std::vector<char> readBuffer;

    // query parameters
    std::ostringstream oss;
    oss << tracker_url << "?info_hash=" << url_encode(info_hash)
        << "&peer_id=" << peer_id
        << "&port=" << port
        << "&uploaded=" << uploaded
        << "&downloaded=" << downloaded
        << "&left=" << left
        << "&compact=1";

    curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, oss.str().c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        else
        {
            std::string response_str(readBuffer.begin(), readBuffer.end());
            auto decoded_response = decode_bencoded_value(response_str);
            if (decoded_response.contains("peers"))
            {
                const auto &peers = decoded_response["peers"].get<std::string>();

                std::vector<std::string> peers_array;
                for (size_t i = 0; i < peers.length(); i += 6)
                {
                    std::string ip = peers.substr(i, 4);                                                            // First 4 bytes are IP
                    uint16_t port = (static_cast<uint8_t>(peers[i + 4]) << 8) | static_cast<uint8_t>(peers[i + 5]); // Last 2 bytes are port

                    std::ostringstream ip_stream;
                    ip_stream << static_cast<int>(static_cast<unsigned char>(ip[0])) << "."
                              << static_cast<int>(static_cast<unsigned char>(ip[1])) << "."
                              << static_cast<int>(static_cast<unsigned char>(ip[2])) << "."
                              << static_cast<int>(static_cast<unsigned char>(ip[3]));

                    std::ostringstream ip_port;
                    ip_port << ip_stream.str() << ":" << port;
                    peers_array.push_back(ip_port.str());
                }
                return peers_array;
            }
        }
        curl_easy_cleanup(curl);
    }
    return {};
}

#endif