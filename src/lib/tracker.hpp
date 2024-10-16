#ifndef TRACKERS
#define TRACKERS

#include <curl/curl.h>

std::string url_encode(const std::string &value)
{
    char buffer[4];
    std::string encoded;
    for (unsigned char c : value)
    {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
        {
            encoded += c;
        }
        else
        {
            snprintf(buffer, sizeof(buffer), "%%%02X", c);
            encoded += buffer;
        }
    }
    return encoded;
}

size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

void request_tracker(const std::string &tracker_url, const std::string &info_hash, const std::string &peer_id, int port, int uploaded, int downloaded, int left)
{
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    // Construct query parameters
    std::ostringstream oss;
    oss << tracker_url << "?info_hash=" << url_encode(info_hash)
        << "&peer_id=" << url_encode(peer_id)
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
            auto decoded_response = decode_bencoded_value(readBuffer);
            if (decoded_response.contains("peers"))
            {
                const auto &peers = decoded_response["peers"].get<std::string>();
                for (size_t i = 0; i < peers.length(); i += 6)
                {
                    std::string ip = peers.substr(i, 4);                                                            // First 4 bytes are IP
                    uint16_t port = (static_cast<uint8_t>(peers[i + 4]) << 8) | static_cast<uint8_t>(peers[i + 5]); // Last 2 bytes are port

                    std::ostringstream ip_stream;
                    ip_stream << static_cast<int>(static_cast<unsigned char>(ip[0])) << "."
                              << static_cast<int>(static_cast<unsigned char>(ip[1])) << "."
                              << static_cast<int>(static_cast<unsigned char>(ip[2])) << "."
                              << static_cast<int>(static_cast<unsigned char>(ip[3]));

                    std::cout << "Peer: " << ip_stream.str() << ":" << port << std::endl;
                }
            }
        }
        curl_easy_cleanup(curl);
    }
}

#endif