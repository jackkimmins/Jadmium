// HttpUtils.hpp
#ifndef HTTPUTILS_HPP
#define HTTPUTILS_HPP

#include <string>
#include <unordered_map>
#include <map>
#include <sstream>
#include <iostream>

enum class HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    UNKNOWN
};

const std::unordered_map<int, std::string> HTTP_STATUS = {
    { 100, "Continue" },
    { 101, "Switching Protocols" },
    { 200, "OK" },
    { 201, "Created" },
    { 202, "Accepted" },
    { 203, "Non-Authoritative Information" },
    { 204, "No Content" },
    { 205, "Reset Content" },
    { 206, "Partial Content" },
    { 300, "Multiple Choices" },
    { 301, "Moved Permanently" },
    { 302, "Found" },
    { 303, "See Other" },
    { 304, "Not Modified" },
    { 305, "Use Proxy" },
    { 307, "Temporary Redirect" },
    { 400, "Bad Request" },
    { 401, "Unauthorized" },
    { 402, "Payment Required" },
    { 403, "Forbidden" },
    { 404, "Not Found" },
    { 405, "Method Not Allowed" },
    { 406, "Not Acceptable" },
    { 407, "Proxy Authentication Required" },
    { 408, "Request Time-out" },
    { 409, "Conflict" },
    { 410, "Gone" },
    { 411, "Length Required" },
    { 412, "Precondition Failed" },
    { 413, "Request Entity Too Large" },
    { 414, "Request-URI Too Large" },
    { 415, "Unsupported Media Type" },
    { 416, "Requested Range Not Satisfiable" },
    { 417, "Expectation Failed" },
    { 500, "Internal Server Error" },
    { 501, "Not Implemented" },
    { 502, "Bad Gateway" },
    { 503, "Service Unavailable" },
    { 504, "Gateway Time-out" },
    { 505, "HTTP Version Not Supported" },
    { 510, "Not Extended" }
};

class HttpRequest {
public:
    HttpMethod method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
};

class HttpResponse {
private:
    int statusCode;
    std::string body;
    std::map<std::string, std::string> headers;

public:
    void SetStatusCode(int code) { statusCode = code; }
    void SetBody(const std::string& b) { body = b; }
    void SetHeader(const std::string& key, const std::string& value) {
        headers[key] = value;
    }

    std::string ToString() const {
        std::ostringstream response;
        response << "HTTP/1.1 " << statusCode << " " << GetStatusMessage(statusCode) << "\r\n";
        for (const auto& header : headers) response << header.first << ": " << header.second << "\r\n";
        response << "Content-Length: " << body.size() << "\r\n";
        response << "\r\n";
        response << body;
        return response.str();
    }

private:
    std::string GetStatusMessage(int code) const {
        auto it = HTTP_STATUS.find(code);
        if (it != HTTP_STATUS.end()) {
            return it->second;
        } else {
            return "Unknown";
        }
    }
};

#endif // HTTPUTILS_HPP