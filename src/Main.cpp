#include <iostream>
#include "WebServer.hpp"

int main() {
    WebServer server(3000, 4);
    
    // Add a route for the index page
    server.AddRoute(HttpMethod::GET, "/", [](auto& req, auto& res) {
        res.SetStatusCode(200);
        res.SetBody("Hello, world!");
    });
    
    server.Run();
    return 0;
}