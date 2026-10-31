/**
 * @file tests/unit/test_nvhttp_https.cpp
 * @brief Verify HTTPS callbacks retain the guard protecting server lifetime.
 */

// test includes
#include "../certificate_test_utils.h"
#include "../tests_common.h"

// standard includes
#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

// lib includes
#include <boost/asio/read_until.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/write.hpp>

// local includes
#include <src/config.h>
#include <src/crypto.h>
#include <src/nvhttp.h>
#include <src/platform/common.h>
#include <src/utility.h>

namespace {
  using namespace std::chrono_literals;
  using boost::asio::ip::tcp;

  /**
   * @brief Run real HTTPS callbacks against an isolated loopback listener.
   */
  struct HttpsHandlerLifetimeTest: BaseTest {
    /**
     * @brief Create credentials and start the production HTTPS accept handler.
     */
    void SetUp() override {
      BaseTest::SetUp();
      const auto credentials = crypto::gen_creds("Sunshine HTTPS lifetime test", 2048);
      certificate_file = std::filesystem::path {SUNSHINE_TEST_BIN_DIR} / "https_lifetime_cert.pem";
      private_key_file = std::filesystem::path {SUNSHINE_TEST_BIN_DIR} / "https_lifetime_key.pem";
      std::ofstream {certificate_file} << credentials.x509;
      std::ofstream {private_key_file} << credentials.pkey;

      server = nvhttp::test_support::make_https_server(certificate_file.string(), private_key_file.string(), handler_scope);
      server->io_service = std::make_shared<boost::asio::io_context>();
      server->config.address = "127.0.0.1";
      server->config.port = 0;
      server->start([this](unsigned short assigned_port) {
        port = assigned_port;
      });
      server->io_service->poll();
      ASSERT_NE(port, 0);
    }

    /**
     * @brief Drain canceled callbacks and remove the generated credentials.
     */
    void TearDown() override {
      if (server) {
        server->stop();
        server->io_service->restart();
        server->io_service->poll();
        server.reset();
      }
      if (stop_thread.joinable()) {
        stop_thread.join();
      }
      std::error_code cleanup_error;
      std::filesystem::remove(certificate_file, cleanup_error);
      std::filesystem::remove(private_key_file, cleanup_error);
      BaseTest::TearDown();
    }

    /**
     * @brief Check that stopping the scope runner waits until the error callback exits.
     *
     * @param callback_error Error delivered by the real accept or TLS handshake operation.
     */
    void check_handler_guard(const boost::system::error_code &callback_error) {
      EXPECT_TRUE(callback_error);
      ++error_callbacks;
      std::promise<void> stopping;
      auto stopping_future = stopping.get_future();
      std::promise<void> stopped;
      stopped_future = stopped.get_future();
      stop_thread = std::jthread([this, stopping = std::move(stopping), stopped = std::move(stopped)]() mutable {
        stopping.set_value();
        handler_scope->stop();
        stopped.set_value();
      });
      stopping_future.wait();
      EXPECT_EQ(stopped_future.wait_for(50ms), std::future_status::timeout);
    }

    std::unique_ptr<SimpleWeb::ServerBase<nvhttp::SunshineHTTPS>> server;  ///< Server running production accept and handshake callbacks.
    std::shared_ptr<SimpleWeb::ScopeRunner> handler_scope;  ///< Guard used by the server destructor.
    std::jthread stop_thread;  ///< Concurrent attempt to stop the handler scope.
    std::future<void> stopped_future;  ///< Signals that all callback guards have been released.
    unsigned short port = 0;  ///< Assigned loopback port.
    int error_callbacks = 0;  ///< Number of errors delivered while testing a handler.
    std::filesystem::path certificate_file;  ///< Generated server certificate.
    std::filesystem::path private_key_file;  ///< Generated server private key.
  };

  /**
   * @brief Canceling a pending accept holds the server guard through its error callback.
   */
  TEST_F(HttpsHandlerLifetimeTest, AcceptErrorRetainsGuardUntilCallbackReturns) {
    server->on_error = [this](auto, const auto &callback_error) {
      check_handler_guard(callback_error);
    };
    server->stop();
    server->io_service->run_for(2s);
    ASSERT_EQ(error_callbacks, 1);
    ASSERT_TRUE(stopped_future.valid());
    EXPECT_EQ(stopped_future.wait_for(2s), std::future_status::ready);
  }

  /**
   * @brief A failed TLS handshake holds the server guard through its error callback.
   */
  TEST_F(HttpsHandlerLifetimeTest, HandshakeErrorRetainsGuardUntilCallbackReturns) {
    server->on_error = [this](auto, const auto &callback_error) {
      check_handler_guard(callback_error);
    };
    boost::asio::io_context client_io;
    tcp::socket client {client_io};
    client.connect({boost::asio::ip::address_v4::loopback(), port});
    client.close();
    server->io_service->run_for(2s);
    ASSERT_EQ(error_callbacks, 1);
    ASSERT_TRUE(stopped_future.valid());
    EXPECT_EQ(stopped_future.wait_for(2s), std::future_status::ready);
  }

  /**
   * @brief A stopped server scope prevents a canceled accept from dispatching an error.
   */
  TEST_F(HttpsHandlerLifetimeTest, StoppedScopeSkipsAcceptCallback) {
    server->on_error = [this](auto, const auto &) {
      ++error_callbacks;
    };
    handler_scope->stop();
    server->stop();
    server->io_service->run_for(2s);
    EXPECT_EQ(error_callbacks, 0);
  }

  /**
   * @brief A stopped server scope prevents an outstanding handshake from dispatching an error.
   */
  TEST_F(HttpsHandlerLifetimeTest, StoppedScopeSkipsHandshakeCallback) {
    server->on_error = [this](auto, const auto &) {
      ++error_callbacks;
    };
    boost::asio::io_context client_io;
    tcp::socket client {client_io};
    client.connect({boost::asio::ip::address_v4::loopback(), port});
    server->io_service->poll();
    handler_scope->stop();
    client.close();
    server->io_service->run_for(2s);
    EXPECT_EQ(error_callbacks, 0);
  }

  /**
   * @brief Exercise the production TLS verifier and per-connection Request identity context.
   */
  struct HttpsClientIdentityTest: BaseTest {
    using tls_stream_t = boost::asio::ssl::stream<tcp::socket>;

    /**
     * @brief Own a TLS context for the lifetime of its client stream.
     */
    struct client_connection_t {
      client_connection_t(const std::filesystem::path &certificate_file, const std::filesystem::path &key_file):
          context(boost::asio::ssl::context::tls_client) {
        context.set_verify_mode(boost::asio::ssl::verify_none);
        if (!certificate_file.empty()) {
          context.use_certificate_file(certificate_file.string(), boost::asio::ssl::context::pem);
          context.use_private_key_file(key_file.string(), boost::asio::ssl::context::pem);
        }
        stream = std::make_unique<tls_stream_t>(io, context);
      }

      boost::asio::io_context io;  ///< Isolated execution context for this client connection.
      boost::asio::ssl::context context;  ///< TLS context referenced by the stream.
      std::unique_ptr<tls_stream_t> stream;  ///< Connected HTTPS stream.
    };

    /**
     * @brief Create paired client credentials and start the verified loopback HTTPS server.
     */
    void SetUp() override {
      BaseTest::SetUp();
      original_state_file = config::nvhttp.file_state;
      original_fresh_state = config::sunshine.flags[config::flag::FRESH_STATE];
      state_file = std::filesystem::path {SUNSHINE_TEST_BIN_DIR} / "https_identity_state.json";
      config::nvhttp.file_state = state_file.string();
      config::sunshine.flags[config::flag::FRESH_STATE] = false;
      nvhttp::test_support::reset_client_state();
      std::error_code cleanup_error;
      std::filesystem::remove(state_file, cleanup_error);

      server_credentials = crypto::gen_creds("Sunshine HTTPS identity server", 2048);
      first_credentials = test_utils::certificates::generate_ca_credentials("Sunshine HTTPS identity first");
      second_credentials = test_utils::certificates::generate_ca_credentials("Sunshine HTTPS identity second");
      unknown_credentials = test_utils::certificates::generate_ca_credentials("Sunshine HTTPS identity unknown");
      disabled_credentials = test_utils::certificates::generate_ca_credentials("Sunshine HTTPS identity disabled");
      duplicate_credentials = test_utils::certificates::generate_ca_credentials("Sunshine HTTPS identity duplicate");
      const auto directory = std::filesystem::path {SUNSHINE_TEST_BIN_DIR};
      server_certificate_file = directory / "https_identity_server_cert.pem";
      server_key_file = directory / "https_identity_server_key.pem";
      first_certificate_file = directory / "https_identity_first_cert.pem";
      first_key_file = directory / "https_identity_first_key.pem";
      second_certificate_file = directory / "https_identity_second_cert.pem";
      second_key_file = directory / "https_identity_second_key.pem";
      unknown_certificate_file = directory / "https_identity_unknown_cert.pem";
      unknown_key_file = directory / "https_identity_unknown_key.pem";
      disabled_certificate_file = directory / "https_identity_disabled_cert.pem";
      disabled_key_file = directory / "https_identity_disabled_key.pem";
      duplicate_certificate_file = directory / "https_identity_duplicate_cert.pem";
      duplicate_key_file = directory / "https_identity_duplicate_key.pem";
      write_credentials(server_credentials, server_certificate_file, server_key_file);
      write_credentials(first_credentials, first_certificate_file, first_key_file);
      write_credentials(second_credentials, second_certificate_file, second_key_file);
      write_credentials(unknown_credentials, unknown_certificate_file, unknown_key_file);
      write_credentials(disabled_credentials, disabled_certificate_file, disabled_key_file);
      write_credentials(duplicate_credentials, duplicate_certificate_file, duplicate_key_file);

      ASSERT_FALSE(nvhttp::test_support::add_client("first client", first_credentials.x509, true).empty());
      ASSERT_FALSE(nvhttp::test_support::add_client("second client", second_credentials.x509, true).empty());
      server = nvhttp::test_support::make_verified_https_server(server_certificate_file.string(), server_key_file.string(), handler_scope);
      server->io_service = std::make_shared<boost::asio::io_context>();
      server->config.address = "127.0.0.1";
      server->config.port = 0;
      nvhttp::test_support::install_client_diagnostics_endpoint(*server);
      server->resource["^/identity$"]["GET"] = [this](auto response, auto request) {
        ++handler_calls;
        const auto context = request->application_context();
        const auto identity = std::static_pointer_cast<const nvhttp::client_identity_t>(context);
        response->write(identity ? identity->name : "missing identity");
      };
      server->start([this](unsigned short assigned_port) {
        port = assigned_port;
      });
      server->io_service->poll();
      server->io_service->restart();
      ASSERT_NE(port, 0);
      server_thread = std::jthread([this] {
        try {
          server->io_service->run();
        } catch (const std::exception &error) {
          server_error = error.what();
        }
      });
    }

    /**
     * @brief Stop the server, clear paired state, and remove test credentials.
     */
    void TearDown() override {
      if (server) {
        server->stop();
        server->io_service->stop();
        server.reset();
      }
      if (server_thread.joinable()) {
        server_thread.join();
      }
      nvhttp::test_support::reset_client_state();
      config::nvhttp.file_state = original_state_file;
      config::sunshine.flags[config::flag::FRESH_STATE] = original_fresh_state;
      std::error_code cleanup_error;
      for (const auto &path : {state_file, server_certificate_file, server_key_file, first_certificate_file, first_key_file, second_certificate_file, second_key_file, unknown_certificate_file, unknown_key_file, disabled_certificate_file, disabled_key_file, duplicate_certificate_file, duplicate_key_file}) {
        std::filesystem::remove(path, cleanup_error);
      }
      BaseTest::TearDown();
    }

    /**
     * @brief Write a certificate and its private key to files required by the HTTPS backend.
     *
     * @param credentials PEM certificate and private key.
     * @param certificate_file Destination certificate path.
     * @param key_file Destination private key path.
     */
    static void write_credentials(const crypto::creds_t &credentials, const std::filesystem::path &certificate_file, const std::filesystem::path &key_file) {
      std::ofstream {certificate_file} << credentials.x509;
      std::ofstream {key_file} << credentials.pkey;
    }

    /**
     * @brief Connect using the given client certificate and return an established TLS stream.
     *
     * @param certificate_file Client certificate path, or an empty path for an absent identity.
     * @param key_file Matching client key path.
     * @return Connected TLS stream with the client handshake completed.
     */
    std::unique_ptr<client_connection_t> connect(const std::filesystem::path &certificate_file, const std::filesystem::path &key_file) {
      auto connection = std::make_unique<client_connection_t>(certificate_file, key_file);
      connection->stream->lowest_layer().connect({boost::asio::ip::address_v4::loopback(), port});
      connection->stream->handshake(boost::asio::ssl::stream_base::client);
      return connection;
    }

    /**
     * @brief Send one HTTP request and return its status and body.
     *
     * @param stream Established client TLS stream.
     * @param buffer Reusable input buffer for response bytes.
     * @return Pair containing HTTP status and response body.
     */
    static std::pair<int, std::string> request(tls_stream_t &stream, boost::asio::streambuf &buffer) {
      constexpr std::string_view request_text = "GET /identity HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
      boost::asio::write(stream, boost::asio::buffer(request_text));
      boost::asio::read_until(stream, buffer, "\r\n\r\n");
      std::istream input {&buffer};
      std::string line;
      std::getline(input, line);
      const int status = std::stoi(line.substr(line.find(' ') + 1, 3));
      std::size_t content_length = 0;
      while (std::getline(input, line) && line != "\r") {
        if (line.starts_with("Content-Length:")) {
          content_length = static_cast<std::size_t>(std::stoul(line.substr(15)));
        }
      }
      std::string body(content_length, '\0');
      const auto buffered = std::min(content_length, buffer.size());
      if (buffered) {
        input.read(body.data(), static_cast<std::streamsize>(buffered));
      }
      if (buffered < content_length) {
        boost::asio::read(stream, boost::asio::buffer(body.data() + buffered, content_length - buffered));
      }
      return {status, body};
    }

    static std::pair<int, std::string> post_diagnostics(tls_stream_t &stream, const std::string &body) {
      const std::string request_text = "POST /client-diagnostics HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
      boost::asio::write(stream, boost::asio::buffer(request_text));
      boost::asio::streambuf buffer;
      boost::asio::read_until(stream, buffer, "\r\n\r\n");
      std::istream input {&buffer};
      std::string line;
      std::getline(input, line);
      const int status = std::stoi(line.substr(line.find(' ') + 1, 3));
      std::size_t content_length = 0;
      while (std::getline(input, line) && line != "\r") {
        if (line.starts_with("Content-Length:")) {
          content_length = static_cast<std::size_t>(std::stoul(line.substr(15)));
        }
      }
      std::string response(content_length, '\0');
      const auto buffered = std::min(content_length, buffer.size());
      if (buffered) {
        input.read(response.data(), static_cast<std::streamsize>(buffered));
      }
      if (buffered < content_length) {
        boost::asio::read(stream, boost::asio::buffer(response.data() + buffered, content_length - buffered));
      }
      return {status, response};
    }

    std::pair<int, std::string> reject_oversized_diagnostics() {
      auto connection = connect(first_certificate_file, first_key_file);
      const std::string headers = "POST /client-diagnostics HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 262145\r\nConnection: close\r\n\r\n";
      boost::asio::write(*connection->stream, boost::asio::buffer(headers));
      boost::asio::streambuf buffer;
      try {
        boost::asio::read_until(*connection->stream, buffer, "\r\n\r\n");
      } catch (const boost::system::system_error &error) {
        if (error.code() == boost::asio::error::eof) {
          return {0, {}};
        }
        throw;
      }
      std::istream input {&buffer};
      std::string line;
      std::getline(input, line);
      return {std::stoi(line.substr(line.find(' ') + 1, 3)), {}};
    }

    static std::string diagnostic_body(const std::string &upload_id, const std::string &scope = "host", const std::string &session_id = "00000000000000000000000000000002", const std::string &parent_id = "", const std::string &content = "safe diagnostic line\n") {
      nlohmann::json body = {
        {"version", 1},
        {"scope", scope},
        {"upload_id", upload_id},
        {"session_id", session_id},
        {"parent_id", parent_id},
        {"begin", "100"},
        {"end", "200"},
        {"build", "3.6.0-gui16"},
        {"outcome", "user_left_host"},
        {"truncated", false},
        {"content", content}
      };
      return body.dump();
    }

    std::shared_ptr<SimpleWeb::ScopeRunner> handler_scope;  ///< Production HTTPS handler lifetime guard.
    std::unique_ptr<SimpleWeb::ServerBase<nvhttp::SunshineHTTPS>> server;  ///< Loopback HTTPS server using production verification.
    std::jthread server_thread;  ///< Runs the server's asynchronous I/O context.
    std::string server_error;  ///< Exception reported by the server I/O thread.
    std::atomic_int handler_calls {0};  ///< Counts requests that passed connection verification.
    unsigned short port = 0;  ///< Ephemeral loopback port.
    std::string original_state_file;  ///< State path restored after the fixture.
    bool original_fresh_state = false;  ///< Fresh-state flag restored after the fixture.
    std::filesystem::path state_file;  ///< Isolated persistent state path.
    std::filesystem::path server_certificate_file;  ///< Server certificate path.
    std::filesystem::path server_key_file;  ///< Server private key path.
    std::filesystem::path first_certificate_file;  ///< First paired client certificate path.
    std::filesystem::path first_key_file;  ///< First paired client private key path.
    std::filesystem::path second_certificate_file;  ///< Second paired client certificate path.
    std::filesystem::path second_key_file;  ///< Second paired client private key path.
    std::filesystem::path unknown_certificate_file;  ///< Unpaired client certificate path.
    std::filesystem::path unknown_key_file;  ///< Unpaired client private key path.
    std::filesystem::path disabled_certificate_file;  ///< Disabled client certificate path.
    std::filesystem::path disabled_key_file;  ///< Disabled client private key path.
    std::filesystem::path duplicate_certificate_file;  ///< Ambiguous client certificate path.
    std::filesystem::path duplicate_key_file;  ///< Ambiguous client private key path.
    crypto::creds_t server_credentials;  ///< Server certificate and key.
    crypto::creds_t first_credentials;  ///< First paired client certificate and key.
    crypto::creds_t second_credentials;  ///< Second paired client certificate and key.
    crypto::creds_t unknown_credentials;  ///< Unpaired client certificate and key.
    crypto::creds_t disabled_credentials;  ///< Disabled client certificate and key.
    crypto::creds_t duplicate_credentials;  ///< Ambiguous client certificate and key.
  };

  /**
   * @brief Distinct identities remain bound to their independent TLS connections under concurrency.
   */
  TEST_F(HttpsClientIdentityTest, ConcurrentConnectionsKeepDistinctRequestIdentities) {
    std::promise<std::pair<int, std::string>> first_result;
    std::promise<std::pair<int, std::string>> second_result;
    std::jthread first_thread([this, &first_result] {
      try {
        auto stream = connect(first_certificate_file, first_key_file);
        boost::asio::streambuf buffer;
        first_result.set_value(request(*stream->stream, buffer));
      } catch (const std::exception &error) {
        first_result.set_value({-1, error.what()});
      }
    });
    std::jthread second_thread([this, &second_result] {
      try {
        auto stream = connect(second_certificate_file, second_key_file);
        boost::asio::streambuf buffer;
        second_result.set_value(request(*stream->stream, buffer));
      } catch (const std::exception &error) {
        second_result.set_value({-1, error.what()});
      }
    });
    const auto first = first_result.get_future().get();
    const auto second = second_result.get_future().get();
    first_thread.join();
    second_thread.join();
    EXPECT_EQ(first, (std::pair {200, "first client"}));
    EXPECT_EQ(second, (std::pair {200, "second client"}));
    EXPECT_EQ(handler_calls, 2);
    EXPECT_TRUE(server_error.empty()) << server_error;
  }

  /**
   * @brief Sequential requests on one keep-alive TLS connection retain their connection identity.
   */
  TEST_F(HttpsClientIdentityTest, KeepAliveRequestsReuseTheConnectionIdentity) {
    auto stream = connect(first_certificate_file, first_key_file);
    boost::asio::streambuf buffer;
    EXPECT_EQ(request(*stream->stream, buffer), (std::pair {200, "first client"}));
    EXPECT_EQ(request(*stream->stream, buffer), (std::pair {200, "first client"}));
    EXPECT_EQ(handler_calls, 2);
  }

  /**
   * @brief Missing, unknown, disabled, and duplicate certificate identities never reach the route handler.
   */
  TEST_F(HttpsClientIdentityTest, RejectsMissingUnknownDisabledAndAmbiguousIdentitiesBeforeHandler) {
    const auto disabled_uuid = nvhttp::test_support::add_client("disabled client", disabled_credentials.x509, false);
    ASSERT_FALSE(disabled_uuid.empty());
    const auto duplicate_uuid = nvhttp::test_support::add_client("duplicate client", duplicate_credentials.x509, true);
    ASSERT_FALSE(duplicate_uuid.empty());
    ASSERT_TRUE(nvhttp::test_support::duplicate_client(duplicate_uuid));
    const auto before = handler_calls.load();

    EXPECT_THROW({
      auto stream = connect({}, {});
      boost::asio::streambuf buffer;
      static_cast<void>(request(*stream->stream, buffer)); }, boost::system::system_error);
    for (const auto &[certificate, key] : {std::pair {unknown_certificate_file, unknown_key_file}, std::pair {disabled_certificate_file, disabled_key_file}, std::pair {duplicate_certificate_file, duplicate_key_file}}) {
      auto stream = connect(certificate, key);
      boost::asio::streambuf buffer;
      EXPECT_EQ(request(*stream->stream, buffer).first, 401);
    }
    EXPECT_EQ(handler_calls, before);
  }

  /**
   * @brief Diagnostic uploads use the verified request identity, reject unsafe metadata and retain only twenty files.
   */
  TEST_F(HttpsClientIdentityTest, ClientDiagnosticsArePairedBoundedIdempotentAndRetainedPerIdentity) {
    auto first_id = util::hex_vec(crypto::hash(first_credentials.x509));
    auto second_id = util::hex_vec(crypto::hash(second_credentials.x509));
    auto lowercase = [](unsigned char c) {
      return c >= 'A' && c <= 'F' ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c);
    };
    std::transform(first_id.begin(), first_id.end(), first_id.begin(), lowercase);
    std::transform(second_id.begin(), second_id.end(), second_id.begin(), lowercase);
    const auto root = platf::appdata() / "moonlight-client-logs";
    const auto first_directory = root / first_id;
    const auto second_directory = root / second_id;
    std::filesystem::remove_all(first_directory);
    std::filesystem::remove_all(second_directory);

    auto post_as = [&](const std::filesystem::path &certificate, const std::filesystem::path &key, const std::string &payload) {
      auto connection = connect(certificate, key);
      return post_diagnostics(*connection->stream, payload);
    };
    const std::string valid_id = "00000000000000000000000000000001";
    const auto body = diagnostic_body(valid_id);
    const auto first_response = post_as(first_certificate_file, first_key_file, body);
    EXPECT_EQ(first_response.first, 200) << first_response.second;
    const auto saved = first_directory / ("100-host-00000000000000000000000000000002-" + valid_id + ".json");
    ASSERT_TRUE(std::filesystem::exists(saved));
    std::ifstream saved_input(saved, std::ios::binary);
    const std::string saved_content((std::istreambuf_iterator<char>(saved_input)), {});
    saved_input.close();
    EXPECT_EQ(saved_content, body);
    EXPECT_EQ(post_as(first_certificate_file, first_key_file, body).first, 200);
    EXPECT_EQ(std::distance(std::filesystem::directory_iterator(first_directory), std::filesystem::directory_iterator {}), 1);

    EXPECT_EQ(post_as(first_certificate_file, first_key_file, "{\"version\":1}").first, 400);
    const auto traversal = diagnostic_body("../" + std::string(29, 'a'));
    EXPECT_EQ(post_as(first_certificate_file, first_key_file, traversal).first, 400);
    EXPECT_EQ(post_as(first_certificate_file, first_key_file, diagnostic_body("00000000000000000000000000000003", "bad")).first, 400);
    auto invalid_time = nlohmann::json::parse(diagnostic_body("00000000000000000000000000000004"));
    invalid_time["begin"] = "not-an-epoch";
    EXPECT_EQ(post_as(first_certificate_file, first_key_file, invalid_time.dump()).first, 400);
    auto invalid_outcome = nlohmann::json::parse(diagnostic_body("00000000000000000000000000000005"));
    invalid_outcome["outcome"] = "arbitrary value";
    EXPECT_EQ(post_as(first_certificate_file, first_key_file, invalid_outcome.dump()).first, 400);
    EXPECT_EQ(std::distance(std::filesystem::directory_iterator(first_directory), std::filesystem::directory_iterator {}), 1);

    const auto oversized_result = reject_oversized_diagnostics();
    EXPECT_TRUE(oversized_result.first == 413 || oversized_result.first == 0);
    EXPECT_EQ(std::distance(std::filesystem::directory_iterator(first_directory), std::filesystem::directory_iterator {}), 1);

    for (unsigned int i = 4; i < 26; ++i) {
      std::ostringstream id;
      id << std::string(28, '0') << std::hex << std::setw(4) << std::setfill('0') << i;
      EXPECT_EQ(post_as(first_certificate_file, first_key_file, diagnostic_body(id.str())).first, 200);
    }
    EXPECT_EQ(std::distance(std::filesystem::directory_iterator(first_directory), std::filesystem::directory_iterator {}), 20);
    for (const auto &entry : std::filesystem::directory_iterator(first_directory)) {
      EXPECT_NE(entry.path().extension(), ".tmp");
    }

    EXPECT_EQ(post_as(first_certificate_file, first_key_file, diagnostic_body("0000000000000000000000000000001a", "stream", "00000000000000000000000000000002", "00000000000000000000000000000003")).first, 200);

    EXPECT_EQ(post_as(second_certificate_file, second_key_file, diagnostic_body(valid_id)).first, 200);
    EXPECT_TRUE(std::filesystem::exists(second_directory / ("100-host-00000000000000000000000000000002-" + valid_id + ".json")));

    EXPECT_EQ(post_as(unknown_certificate_file, unknown_key_file, diagnostic_body(valid_id)).first, 401);
    std::filesystem::remove_all(first_directory);
    std::filesystem::remove_all(second_directory);
  }
}  // namespace
