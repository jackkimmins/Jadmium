#include <iostream>
#include "WebServer.hpp"
#include "HttpUtils.hpp"

int main() {
    // Example usage
    WebServer server("10.0.10.15", 5000, 4);

    // Add a route for the index page
    server.AddRoute(HttpMethod::GET, "/", [](auto& req, auto& res) {
        res.SetStatusCode(200);
        res.SetBody("Hello, world!");
    });

    server.Run();
    return 0;
}