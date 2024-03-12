#include "pynetcode.h"
#include <algorithm>
#include <stdexcept>
#include <format>
#include <cstdarg>
#include <cstdio>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

namespace py = pybind11;

Client::Client(const std::string_view& address, const double time) {
netcode_address_t addr;
if (netcode_parse_address(address.data(), &addr) != NETCODE_OK) {
throw std::runtime_error("Invalid IP address specification");
}
netcode_client_config_t config;
netcode_default_client_config(&config);
this->client = netcode_client_create(address.data(), &config, time);
if (!this->client) {
throw std::runtime_error("Client creation failed!");
}
}

Client::~Client() {
if (this->client) {
netcode_client_destroy(this->client);
}
}

void Client::connect(const std::array<std::uint8_t, NETCODE_CONNECT_TOKEN_BYTES>& token) {
if (this->client) {
return netcode_client_connect(this->client, const_cast<std::uint8_t*>(token.data()));
}
throw std::runtime_error("Managed to call this function without a valid client pointer! This is a bug!");
}

void Client::update(const double time) {
if (this->client) {
return netcode_client_update(this->client, time);
}
throw std::runtime_error("Managed to call this function without a valid client pointer! This is a bug!");
}

std::uint64_t Client::next_packet_sequence() const {
if (this->client) {
return netcode_client_next_packet_sequence(this->client);
}
throw std::runtime_error("Managed to call this function without a valid client pointer! This is a bug!");
}

void Client::send_packet(const py::buffer& buf) {
if (this->client) {
if (buf) {
if (buf.is_none()) {
return; // Do nothing
}
const auto info = buf.request();
return netcode_client_send_packet(this->client, static_cast<const std::uint8_t*>(info.ptr), info.size);
}
} else {
throw std::runtime_error("Managed to call this function without a valid client pointer! This is a bug!");
}
}

std::tuple<py::bytes, int, std::uint64_t> Client::receive_packet() const {
if (this->client) {
int bytes;
std::uint64_t seq;
const auto* data = netcode_client_receive_packet(client, &bytes, &seq);
std::string py_data;
py_data.reserve(bytes);
std::copy(data, data + bytes, std::back_inserter(py_data));
netcode_client_free_packet(this->client, static_cast<void*>(const_cast<std::uint8_t*>(data)));
return std::make_tuple(py_data, bytes, seq);
} else {
throw std::runtime_error("Managed to call this function without a valid client pointer! This is a bug!");
}
}

void Client::disconnect() {
if (this->client) {
return netcode_client_disconnect(this->client);
}
throw std::runtime_error("Managed to call this function without a valid client pointer! This is a bug!");
}

int Client::state() const {
if (this->client) {
return netcode_client_state(this->client);
} else {
throw std::runtime_error("Managed to call this function without a valid client pointer! This is a bug!");
}
}

int Client::index() const {
if (this->client) {
return netcode_client_index(this->client);
}
throw std::runtime_error("Managed to call this function without a valid client pointer! This is a bug!");
}

int Client::max_clients() const {
if (this->client) {
return netcode_client_max_clients(this->client);
}
throw std::runtime_error("Managed to call this function without a valid client pointer! This is a bug!");
}

void Client::connect_loopback(const int client_index, const int max_clients) {
if (this->client) {
return netcode_client_connect_loopback(this->client, client_index, max_clients);
}
throw std::runtime_error("Managed to call this function without a valid client pointer! This is a bug!");
}

void Client::disconnect_loopback() const {
if (this->client) {
return netcode_client_disconnect_loopback(this->client);
}
throw std::runtime_error("Managed to call this function without a valid client pointer! This is a bug!");
}

std::uint16_t Client::get_port() const {
if (this->client) {
return netcode_client_get_port(this->client);
}
throw std::runtime_error("Managed to call this function without a valid client pointer! This is a bug!");
}

std::string Client::server_address() const {
if (this->client) {
auto* address = netcode_client_server_address(this->client);
char buffer[256];
netcode_address_to_string(address, buffer);
return std::string(buffer);
}
throw std::runtime_error("Managed to call this function without a valid client pointer! This is a bug!");
}

Server::Server(const std::string_view& address, const double time) {
netcode_address_t addr;
if (netcode_parse_address(address.data(), &addr) != NETCODE_OK) {
throw std::runtime_error("Invalid IP address specification");
}
netcode_server_config_t config;
netcode_default_server_config(&config);
this->server = netcode_server_create(address.data(), &config, time);
if (!this->server) {
throw std::runtime_error("Server creation failed!");
}
}

Server::~Server() {
if (this->server) {
netcode_server_destroy(this->server);
}
}

void Server::start(const int max_clients) {
if (this->server) {
return netcode_server_start(this->server, max_clients);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

void Server::stop() {
if (this->server) {
return netcode_server_stop(this->server);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

int Server::running() const {
if (this->server) {
return netcode_server_running(this->server);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

int Server::max_clients() const {
if (this->server) {
return netcode_server_max_clients(this->server);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

void Server::update(const double time) {
if (this->server) {
return netcode_server_update(this->server, time);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

int Server::client_connected(const int id) const {
if (this->server) {
return netcode_server_client_connected(this->server, id);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

std::uint64_t Server::client_id(const int index) const {
if (this->server) {
return netcode_server_client_id(this->server, index);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

std::string Server::client_address(const int index) const {
if (this->server) {
auto* address = netcode_server_client_address(this->server, index);
char buffer[256];
netcode_address_to_string(address, buffer);
return std::string(buffer);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

void Server::disconnect_client(const int index) {
if (this->server) {
return netcode_server_disconnect_client(this->server, index);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

void Server::disconnect_all_clients() {
if (this->server) {
return netcode_server_disconnect_all_clients(this->server);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

std::uint64_t Server::next_packet_sequence(const int index) const {
if (this->server) {
return netcode_server_next_packet_sequence(this->server, index);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

void Server::send_packet(const int index, const py::buffer& buf) {
if (this->server) {
if (buf) {
if (buf.is_none()) {
return; // Do nothing
}
const auto info = buf.request();
return netcode_server_send_packet(this->server, index, static_cast<std::uint8_t*>(info.ptr), info.size);
}
} else {
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}
}

std::tuple<py::bytes, int, std::uint64_t> Server::receive_packet(const int index) const {
if (this->server) {
int bytes;
std::uint64_t seq;
const auto* data = netcode_server_receive_packet(this->server, index, &bytes, &seq);
std::string py_data;
py_data.reserve(bytes);
std::copy(data, data + bytes, std::back_inserter(py_data));
netcode_server_free_packet(this->server, static_cast<void*>(const_cast<std::uint8_t*>(data)));
return std::make_tuple(py_data, bytes, seq);
} else {
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}
}

int Server::num_connected_clients() const {
if (this->server) {
return netcode_server_num_connected_clients(this->server);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

void Server::connect_loopback_client(const int index, const std::uint64_t id) {
if (this->server) {
return netcode_server_connect_loopback_client(this->server, index, id, nullptr);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

void Server::disconnect_loopback_client(const int index) {
if (this->server) {
return netcode_server_disconnect_loopback_client(this->server, index);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

std::uint16_t Server::get_port() const {
if (this->server) {
return netcode_server_get_port(this->server);
}
throw std::runtime_error("Managed to call this function without a valid server pointer! This is a bug!");
}

void assert_func(const char* condition, const char* function, const char* file, const int line) {
throw std::runtime_error(std::format("Internal assertion failure: {}, in {}, at {}:{}", condition, function, file, line));
}

int errprintf(const char* format...) {
std::va_list arglist;
std::string msg;
msg.resize(16384);
va_start( arglist, format );
std::vsnprintf(msg.data(), 16384, format, arglist);
va_end(arglist);
throw std::runtime_error(msg);
return msg.size();
}

PYBIND11_MODULE(netcode, m) {
m.def("init", []() {
netcode_set_assert_function(&assert_func);
netcode_log_level(NETCODE_LOG_LEVEL_ERROR);
netcode_set_printf_function(&errprintf);
if (netcode_init() != NETCODE_OK) {
throw std::runtime_error("Unable to initialize netcode library");
}
});
m.def("term", &netcode_term);
m.def("sleep", &netcode_sleep);
m.def("time", &netcode_time);

py::class_<Client>(m, "Client")
.def(py::init<const std::string_view&, const double>())
.def("connect", &Client::connect)
.def("update", &Client::update)
.def("next_packet_sequence", &Client::next_packet_sequence)
.def("send_packet", &Client::send_packet)
.def("receive_packet", &Client::receive_packet)
.def("disconnect", &Client::disconnect)
.def("state", &Client::state)
.def("index", &Client::index)
.def("max_clients", &Client::max_clients)
.def("connect_loopback", &Client::connect_loopback)
.def("disconnect_loopback", &Client::disconnect_loopback)
.def("get_port", &Client::get_port)
.def("server_address", &Client::server_address);

py::class_<Server>(m, "Server")
.def(py::init<const std::string_view&, const double>())
.def("start", &Server::start)
.def("stop", &Server::stop)
.def("running", &Server::running)
.def("max_clients", &Server::max_clients)
.def("update", &Server::update)
.def("client_connected", &Server::client_connected)
.def("client_id", &Server::client_id)
.def("client_address", &Server::client_address)
.def("disconnect_client", &Server::disconnect_client)
.def("disconnect_all_clients", &Server::disconnect_all_clients)
.def("next_packet_sequence", &Server::next_packet_sequence)
.def("send_packet", &Server::send_packet)
.def("receive_packet", &Server::receive_packet)
.def("num_connected_clients", &Server::num_connected_clients)
.def("connect_loopback_client", &Server::connect_loopback_client)
.def("disconnect_loopback_client", &Server::disconnect_loopback_client)
.def("get_port", &Server::get_port);
}
