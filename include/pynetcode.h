#pragma once
#include <cstddef>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>
#include <string_view>
#include <tuple>
#include <vector>
#include "netcode.h"
#include <functional>

class Client {
private:
netcode_client_t *client;
public:
Client(const std::string_view&, const double);
~Client();
void connect(const std::array<std::uint8_t, NETCODE_CONNECT_TOKEN_BYTES>&);
void update(const double);
std::uint64_t next_packet_sequence() const;
void send_packet(const pybind11::buffer&);
std::tuple<pybind11::bytes, int, std::uint64_t> receive_packet() const;
void disconnect();
int state() const;
int index() const;
int max_clients() const;
void connect_loopback(const int, const int);
void disconnect_loopback() const;
std::uint16_t get_port() const;
std::string server_address() const;
};

class Server {
private:
netcode_server_t *server;
public:
std::function<void(int, bool)> py_connect_disconnect_cb;
Server(const std::string_view&, const double, const std::uint64_t, const pybind11::buffer&, const std::function<void(int, bool)>&);
~Server();
void start(const int);
void stop();
int running() const;
int max_clients() const;
void update(const double);
int client_connected(const int) const;
std::uint64_t client_id(const int) const;
std::string client_address(const int) const;
void disconnect_client(const int);
void disconnect_all_clients();
std::uint64_t next_packet_sequence(const int) const;
void send_packet(const int, const pybind11::buffer&);
std::tuple<pybind11::bytes, int, std::uint64_t> receive_packet(const int) const;
int num_connected_clients() const;
void connect_loopback_client(const int, const std::uint64_t);
void disconnect_loopback_client(const int);
std::uint16_t get_port() const;
};

void connect_disconnect_cb(void *, int, int);
