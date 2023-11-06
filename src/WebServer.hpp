#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <thread>
#include <functional>
#include <unordered_map>
#include <vector>
#include <netdb.h>
#include <arpa/inet.h>
#include <utility>
#include <zlib.h>

#include "ThreadPool.hpp"
#include "Logger.hpp"
#include "HTTPStatus.hpp"

class WebServer {
public:
    struct Response {
    private:
        std::string status_line;
        std::unordered_map<std::string, std::string> headers;
        std::string body;

        // Set the status line based on the status code
        void SetStatusLine(int code) {
            auto it = HTTP_STATUS.find(code);
            if (it == HTTP_STATUS.end()) code = 510;

            status_line = "HTTP/1.1 " + std::to_string(code) + " " + HTTP_STATUS.at(code);
        }

    public:
        Response() {
            SetStatusCode(200);
            AddHeader("Content-Type", "text/html");
            AddHeader("Server", "Jadmium");
        }

        // Set the status code of the response
        void SetStatusCode(int code) {
            SetStatusLine(code);
        }

        // Redirect to another URL
        void Redirect(const std::string& url, bool permanent = false) {
            SetStatusCode(permanent ? 301 : 302);
            AddHeader("Location", url);
        }

        // Set a HTTP Response header
        void AddHeader(const std::string& key, const std::string& value) {
            headers[key] = value;
        }

        // Set the body of the response
        void SetBody(const std::string& bodyContent) {
            body = bodyContent;
        }

        // Get the response as a string
        std::string ToString() const {
            std::string response = status_line + "\r\n";
            for (const auto& [key, value] : headers) {
                response += key + ": " + value + "\r\n";
            }

            if (headers.find("Content-Length") == headers.end() && !body.empty()) {
                response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
            }

            response += "\r\n" + body;
            return response;
        }
    };

    // Takes a request and response object
    using RouteHandler = std::function<void(const std::string&, Response&)>;
    using RouteKey = std::pair<std::string, HttpMethod>;

    WebServer(int port, size_t threads) : server_fd(-1), port(port), thread_pool(threads) {
        Setup();
    }

    ~WebServer() {
        if (server_fd != -1) close(server_fd);
    }

    // Add a route to the server
    void AddRoute(HttpMethod method, const std::string& path, const RouteHandler& handler) {
        routes[{path, method}] = handler;
    }

    std::string GetHostIPAddress() {
        char hostbuffer[256];
        char *IPbuffer;
        struct hostent *host_entry;
        int hostname;

        // To retrieve hostname
        hostname = gethostname(hostbuffer, sizeof(hostbuffer));
        if (hostname == -1) {
            perror("gethostname");
            exit(EXIT_FAILURE);
        }

        // To retrieve host information
        host_entry = gethostbyname(hostbuffer);
        if (host_entry == NULL) {
            perror("gethostbyname");
            exit(EXIT_FAILURE);
        }

        // To convert an Internet network address into ASCII string
        IPbuffer = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
        return IPbuffer;
    }

    // Start the server
    void Run() {
        std::string ip = GetHostIPAddress();
        Logger::log("Jadmium Server is running at http://" + ip + ":" + std::to_string(port), Logger::Level::INFO);

        while (true) {
            int new_socket;
            struct sockaddr_in address;
            int addrlen = sizeof(address);
            if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
                perror("accept");
                exit(EXIT_FAILURE);
            }

            thread_pool.enqueue(&WebServer::HandleConnection, this, new_socket);
        }
    }

private:
    struct pair_hash {
        template <class T1, class T2>
        std::size_t operator () (const std::pair<T1, T2>& pair) const {
            auto hash1 = std::hash<T1>{}(pair.first);
            auto hash2 = std::hash<T2>{}(pair.second);
            return hash1 ^ hash2;
        }
    };

    int server_fd;
    int port;
    bool debugMode = false;
    ThreadPool thread_pool;
    std::unordered_map<RouteKey, RouteHandler, pair_hash> routes;

    void Setup() {
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            perror("socket failed");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            perror("bind failed");
            exit(EXIT_FAILURE);
        }
        if (listen(server_fd, 10) < 0) {
            perror("listen");
            exit(EXIT_FAILURE);
        }
    }

    bool BufferContainsIncompleteHeader(const std::vector<char>& buffer) {
        const std::string end_of_header = "\r\n\r\n";
        auto it = std::search(buffer.begin(), buffer.end(), end_of_header.begin(), end_of_header.end());
        return it == buffer.end();
    }

    static std::string GetHeaderValue(const std::string& request, const std::string& header_name) {
        size_t start = request.find(header_name + ":");
        if (start == std::string::npos) return "";

        start += header_name.size() + 1;
        size_t end = request.find("\r\n", start);
        if (end == std::string::npos) return "";

        return request.substr(start, end - start);
    }

    void HandleConnection(int socket) {
        bool keep_alive;
        Response response;

        do {
            std::vector<char> buffer;
            const size_t buffer_size = 1024;
            size_t total_bytes_read = 0;
            ssize_t bytes_read;

            // Read from the socket until the header is fully received
            do {
                buffer.resize(total_bytes_read + buffer_size);
                bytes_read = read(socket, buffer.data() + total_bytes_read, buffer_size);
                if (bytes_read > 0) total_bytes_read += bytes_read;
            } while (bytes_read > 0 && BufferContainsIncompleteHeader(buffer));

            // If there's an error reading from the socket, exit the function
            if (bytes_read < 0) {
                perror("read");
                close(socket);
                return;
            }

            // Convert the buffer to a string for easier processing
            std::string request(buffer.begin(), buffer.begin() + total_bytes_read);
            if (debugMode) std::cout << request << std::endl;

            // Extract the request method and path from the request line
            size_t method_end = request.find(' ');
            std::string method_str = request.substr(0, method_end);
            HttpMethod method;
            if (method_str == "GET") method = HttpMethod::GET;
            else if (method_str == "POST") method = HttpMethod::POST;
            else if (method_str == "PUT") method = HttpMethod::PUT;
            else if (method_str == "DELETE") method = HttpMethod::DELETE;
            else {
                // Handle unknown methods
                close(socket);
                return;
            }

            size_t path_start = request.find(' ', method_end) + 1;
            size_t path_end = request.find(' ', path_start);
            std::string path = request.substr(path_start, path_end - path_start);

            // Find the handler for the route based on method and path
            RouteKey route_key = {path, method};
            auto route_it = routes.find(route_key);
            if (route_it != routes.end()) {
                // Call the associated handler, which now expects a Response reference
                route_it->second(request, response);
                
                // Send the response back to the client
                std::string response_str = response.ToString();
                if (debugMode) std::cout << response_str << std::endl;
                send(socket, response_str.c_str(), response_str.size(), 0);
            } else {
                // Handle unknown routes or methods
            }

            // Check if the client has requested to keep the connection alive
            keep_alive = GetHeaderValue(request, "Connection") == "keep-alive";
            if (keep_alive) response.AddHeader("Connection", "keep-alive");

            // Send the response back to the client
            std::string response_str = response.ToString();
            if (debugMode) std::cout << response_str << std::endl;
            send(socket, response_str.c_str(), response_str.size(), 0);
        } while (keep_alive);

        // Close the socket after handling the connection
        close(socket);
    }
};