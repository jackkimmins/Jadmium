#pragma once
#ifndef WEBSERVER_HPP
#define WEBSERVER_HPP

#include <string>
#include <functional>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>
#include <map>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <errno.h>

#include <openssl/ssl.h>

#include "HttpUtils.hpp"
#include "Logger.hpp"
#include "SSLManager.hpp"

class WebServer {
public:
    WebServer(const std::string& host, int port, int threadCount);
    ~WebServer();
    void AddRoute(HttpMethod method, const std::string& path, std::function<void(HttpRequest&, HttpResponse&)> handler);
    void Run();

private:
    std::string host_;
    int port_;
    int threadCount_;
    std::unordered_map<std::string, std::function<void(HttpRequest&, HttpResponse&)>> routes_;
    SSLManager ssl_manager_;

    int server_fd_;
    std::vector<std::thread> worker_threads_;
    std::queue<int> client_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    bool is_running_;

    void WorkerThread();
    void EnqueueClient(int client_socket);
    void HandleClient(int client_socket);
    HttpRequest ParseRequest(const std::string& requestStr);
    std::string GetMethodString(HttpMethod method);
    void SetupSocket();
};

WebServer::WebServer(const std::string& host, int port, int threadCount) : host_(host), port_(port), threadCount_(threadCount), is_running_(false) {}

WebServer::~WebServer() {
    is_running_ = false;
    queue_cv_.notify_all();
    for (auto& thread : worker_threads_) if (thread.joinable()) thread.join();
    if (server_fd_ >= 0) close(server_fd_);
}

void WebServer::AddRoute(HttpMethod method, const std::string& path, std::function<void(HttpRequest&, HttpResponse&)> handler) {
    std::string key = GetMethodString(method) + ":" + path;
    routes_[key] = handler;
}

std::string WebServer::GetMethodString(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET:     return "GET";
        case HttpMethod::POST:    return "POST";
        case HttpMethod::PUT:     return "PUT";
        case HttpMethod::DELETE:  return "DELETE";
        default:                  return "UNKNOWN";
    }
}

void WebServer::SetupSocket() {
    int opt = 1;
    struct sockaddr_in address;

    if ((server_fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == 0) {
        Logger::log("Socket creation failed: " + std::string(strerror(errno)), Logger::Level::ERROR);
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        Logger::log("setsockopt failed: " + std::string(strerror(errno)), Logger::Level::ERROR);
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_port = htons(port_);

    if (host_ == "*" || host_.empty()) {
        address.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, host_.c_str(), &address.sin_addr) <= 0) {
            Logger::log("Invalid address: " + host_, Logger::Level::ERROR);
            exit(EXIT_FAILURE);
        }
    }

    if (bind(server_fd_, (struct sockaddr*)&address, sizeof(address)) < 0) {
        Logger::log("Bind failed: " + std::string(strerror(errno)), Logger::Level::ERROR);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd_, SOMAXCONN) < 0) {
        Logger::log("Listen failed: " + std::string(strerror(errno)), Logger::Level::ERROR);
        exit(EXIT_FAILURE);
    }
}

void WebServer::Run() {
    SetupSocket();

    std::string display_host = (host_ == "*" || host_.empty()) ? "0.0.0.0" : host_;
    Logger::log("Server is listening at https://" + display_host + ":" + std::to_string(port_), Logger::Level::INFO);

    is_running_ = true;

    // Start workers
    for (int i = 0; i < threadCount_; ++i) worker_threads_.emplace_back(&WebServer::WorkerThread, this);

    while (is_running_) {
        int client_socket;
        struct sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);

        client_socket = accept(server_fd_, (struct sockaddr*)&client_address, &client_len);
        if (client_socket < 0) {
            Logger::log("Accept failed: " + std::string(strerror(errno)), Logger::Level::ERROR);
            continue;
        }

        EnqueueClient(client_socket);
    }

    close(server_fd_);
    for (auto& thread : worker_threads_) thread.join();
}

void WebServer::EnqueueClient(int client_socket) {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    client_queue_.push(client_socket);
    queue_cv_.notify_one();
}

void WebServer::WorkerThread() {
    while (is_running_) {
        int client_socket;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this]() { return !client_queue_.empty() || !is_running_; });
            if (!is_running_) break;
            client_socket = client_queue_.front();
            client_queue_.pop();
        }

        HandleClient(client_socket);
    }
}

void WebServer::HandleClient(int client_socket) {
    const int buffer_size = 8192;
    char buffer[buffer_size];
    int bytes_read;

    // Peek at the first byte to determine if it's an SSL/TLS handshake
    unsigned char first_byte;
    int peek_result = recv(client_socket, &first_byte, 1, MSG_PEEK);
    if (peek_result <= 0) {
        close(client_socket);
        return;
    }

    bool use_ssl = (first_byte == 0x16); // 0x16 indicates TLS handshake

    std::string requestStr;
    if (use_ssl) {
        SSL* ssl = SSL_new(ssl_manager_.GetContext());
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            unsigned long err_code = ERR_get_error();
            int reason = ERR_GET_REASON(err_code);

            // Suppress cert errors
            if (reason != SSL_R_TLSV1_ALERT_UNKNOWN_CA &&
                reason != SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN &&
                reason != SSL_R_SSLV3_ALERT_NO_CERTIFICATE) {
                char buf[256];
                ERR_error_string_n(err_code, buf, sizeof(buf));
                Logger::log("SSL accept failed: " + std::string(buf), Logger::Level::SSL);
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_socket);
            return;
        }

        bytes_read = SSL_read(ssl, buffer, buffer_size);
        if (bytes_read <= 0) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_socket);
            return;
        }

        requestStr = std::string(buffer, bytes_read);

        HttpRequest request = ParseRequest(requestStr);

        // Log the request
        Logger::log("[REQ]: " + GetMethodString(request.method) + " " + request.path, Logger::Level::INFO);

        HttpResponse response;

        std::string routeKey = GetMethodString(request.method) + ":" + request.path;
        if (routes_.find(routeKey) != routes_.end()) {
            routes_[routeKey](request, response);
        } else {
            response.SetStatusCode(404);
            response.SetBody("Not Found");
        }

        // Set Server header
        response.SetHeader("Server", "Jadmium");

        std::string responseStr = response.ToString();
        SSL_write(ssl, responseStr.c_str(), responseStr.length());

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_socket);

    } else {
        bytes_read = recv(client_socket, buffer, buffer_size, 0);
        if (bytes_read <= 0) {
            close(client_socket);
            return;
        }

        requestStr = std::string(buffer, bytes_read);
        HttpRequest request = ParseRequest(requestStr);

        // Log the request
        Logger::log("[REQ]: " + GetMethodString(request.method) + " " + request.path, Logger::Level::INFO);

        // Get the Host header
        std::string host = request.headers["Host"];
        if (host.empty()) host = "localhost";

        // Construct the redirect URL using the Host header and request path
        std::string redirectUrl = "https://" + host + request.path;

        // Send HTTP redirect response to HTTPS
        HttpResponse response;
        response.SetStatusCode(301);
        response.SetHeader("Location", redirectUrl);
        // Set Server header
        response.SetHeader("Server", "Jadmium");
        response.SetBody(""); // Empty body
        std::string responseStr = response.ToString();

        send(client_socket, responseStr.c_str(), responseStr.length(), 0);
        close(client_socket);
    }
}

HttpRequest WebServer::ParseRequest(const std::string& requestStr) {
    HttpRequest request;
    std::istringstream stream(requestStr);
    std::string line;

    // Get the request line
    if (std::getline(stream, line)) {
        std::istringstream requestLine(line);
        std::string methodStr, path, version;

        requestLine >> methodStr >> path >> version;

        // Convert method string to HttpMethod
        if (methodStr == "GET") request.method = HttpMethod::GET;
        else if (methodStr == "POST") request.method = HttpMethod::POST;
        else if (methodStr == "PUT") request.method = HttpMethod::PUT;
        else if (methodStr == "DELETE") request.method = HttpMethod::DELETE;
        else request.method = HttpMethod::UNKNOWN;

        request.path = path;
    }

    // Get headers
    while (std::getline(stream, line) && line != "\r") {
        if (line.back() == '\r') line.pop_back();
        auto colonPos = line.find(":");
        if (colonPos != std::string::npos) {
            std::string headerName = line.substr(0, colonPos);
            std::string headerValue = line.substr(colonPos + 1);
            if (!headerValue.empty() && headerValue[0] == ' ') headerValue.erase(0, 1);
            request.headers[headerName] = headerValue;
        }
    }

    // Get body
    if (request.headers.find("Content-Length") != request.headers.end()) {
        int contentLength = std::stoi(request.headers["Content-Length"]);
        std::string body(contentLength, '\0');
        stream.read(&body[0], contentLength);
        request.body = body;
    }

    return request;
}

#endif // WEBSERVER_HPP