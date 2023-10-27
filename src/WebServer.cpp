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

#include "ThreadPool.hpp"
#include "Logger.hpp"

class WebServer {
public:
    struct Response {
        std::string status_line;
        std::unordered_map<std::string, std::string> headers;
        std::string body;

        std::string ToString() const {
            std::string response = status_line + "\r\n";
            bool has_content_length = false;

            for (const auto& [key, value] : headers) {
                response += key + ": " + value + "\r\n";
                if (key == "Content-Length" || key == "content-length") {
                    has_content_length = true;
                }
            }

            if (!has_content_length && !body.empty()) {
                response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
            }

            response += "\r\n" + body;
            return response;
        }
    };

    using Route = std::function<Response(const std::string&)>;

    WebServer(int port, size_t threads) : server_fd(-1), port(port), thread_pool(threads) {
        Setup();
    }

    ~WebServer() {
        if (server_fd != -1) close(server_fd);
    }

    void AddRoute(const std::string& path, const Route& route) {
        routes[path] = route;
    }

    std::string getHostIPAddress() {
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

        // To convert an Internet network
        // address into ASCII string
        IPbuffer = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));

        return IPbuffer;
    }

    void Run() {
        std::string ip = getHostIPAddress();
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
    int server_fd;
    int port;
    bool debugMode = false;
    ThreadPool thread_pool;
    std::unordered_map<std::string, Route> routes;

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

    static std::string GetHeaderValue(const std::string& request, const std::string& header_name)
    {
        size_t start = request.find(header_name + ":");
        if (start == std::string::npos) return "";

        start += header_name.size() + 1;
        size_t end = request.find("\r\n", start);
        if (end == std::string::npos) return "";

        return request.substr(start, end - start);
    }

    void HandleConnection(int socket)
    {
        bool keep_alive;
        do {
            std::vector<char> buffer;
            const size_t buffer_size = 1024;
            size_t total_bytes_read = 0;
            ssize_t bytes_read;

            do {
                buffer.resize(total_bytes_read + buffer_size);
                bytes_read = read(socket, buffer.data() + total_bytes_read, buffer_size);
                if (bytes_read > 0) total_bytes_read += bytes_read;
            } while (bytes_read > 0 && BufferContainsIncompleteHeader(buffer));

            if (bytes_read < 0) {
                perror("read");
                close(socket);
                return;
            }

            std::string request(buffer.begin(), buffer.begin() + total_bytes_read);
            if (debugMode) std::cout << request << std::endl; 

        // Simple parsing to extract the path
        size_t start = request.find("GET /") + 4;
        size_t end = request.find(" ", start);
        std::string path = request.substr(start, end - start);

        // Find the route
        auto it = routes.find(path);
        Response response;
            if (it != routes.end()) {
                response = it->second(request);
            } else {
                response.status_line = "HTTP/1.1 404 Not Found";
                response.headers["Content-Type"] = "text/html";
                response.headers["Content-Length"] = "9";
                response.body = "Not Found";
            }

            keep_alive = GetHeaderValue(request, "Connection") == "keep-alive";
            if (keep_alive) response.headers["Connection"] = "keep-alive";

            std::string response_str = response.ToString();
            send(socket, response_str.c_str(), response_str.size(), 0);
        } while (keep_alive);

        close(socket);
    }
};

int main() {
    WebServer server(8080, 4);
    
    // Add a route for the index page
    server.AddRoute("/", [](const std::string& request) -> WebServer::Response {
        WebServer::Response response;
        response.status_line = "HTTP/1.1 200 OK";
        response.headers["Content-Type"] = "text/html";
        response.body = "Hello, world!";
        return response;
    });
    
    server.Run();
    return 0;
}
