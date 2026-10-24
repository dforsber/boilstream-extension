#pragma once
#include "boilstream_local_secret_host.h"
#include "duckdb/common/exception.hpp"
#include "duckdb/main/client_context.hpp"
#include <chrono>

namespace duckdb {
// A retained host capability, never constructed from SQL/IDs or transport keys.
class BoilstreamLocalSecretProvider {
public:
    struct Response {
        uint32_t status;
        string body;
        string TakeBody() {
            if (status < 200 || status >= 300)
                throw IOException("Local credential request rejected (status %u)", status);
            return std::move(body);
        }
    };
    explicit BoilstreamLocalSecretProvider(const BoilstreamLocalSecretHostV2 &host) : host(host) {
        if (host.version != 2 || host.size != sizeof(host) || !host.owner || !host.retain || !host.release ||
            !host.request || !host.release_reply || Expired() ||
            host.expires_at_us > std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::system_clock::time_point::max().time_since_epoch()).count())
            throw InvalidInputException("Invalid local credential host");
        host.retain(host.owner);
    }
    ~BoilstreamLocalSecretProvider() { host.release(host.owner); }
    BoilstreamLocalSecretProvider(const BoilstreamLocalSecretProvider &) = delete;
    BoilstreamLocalSecretProvider &operator=(const BoilstreamLocalSecretProvider &) = delete;
    uint32_t TenantId() const { return host.tenant_id; }
    uint32_t UserId() const { return host.internal_user_id; }
    std::chrono::system_clock::time_point ExpiresAt() const {
        return std::chrono::system_clock::time_point(std::chrono::duration_cast<std::chrono::system_clock::duration>(
            std::chrono::microseconds(host.expires_at_us)));
    }
    bool Expired() const {
        return host.expires_at_us <= std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    Response RequestResponse(ClientContext &context, const string &request) const {
        if (context.IsInterrupted()) throw InterruptException();
        if (Expired()) throw IOException("Local credential authority expired");
        static constexpr size_t LIMIT = 10 * 1024 * 1024;
        if (request.size() > LIMIT) throw InvalidInputException("Oversized local credential request");
        BoilstreamLocalSecretReplyV1 reply {};
        struct Release {
            const BoilstreamLocalSecretHostV2 &host;
            BoilstreamLocalSecretReplyV1 &reply;
            ~Release() { if (reply.owner) host.release_reply(reply.owner); }
        } release {host, reply};
        if (host.request(host.owner, &context, reinterpret_cast<const uint8_t *>(request.data()), request.size(), &reply) != 1)
            throw IOException("Local credential callback failed");
        if (context.IsInterrupted() || reply.status == 408) throw InterruptException();
        if (Expired()) throw IOException("Local credential authority expired");
        if (reply.length > LIMIT || (reply.length && (!reply.data || !reply.owner)))
            throw IOException("Invalid local credential response");
        return {reply.status, reply.length ? string(reinterpret_cast<const char *>(reply.data), reply.length) : string()};
    }
    string Request(ClientContext &context, const string &request) const {
        return RequestResponse(context, request).TakeBody();
    }
    void Validate(ClientContext &context) const { Request(context, "{\"operation\":\"validate\"}"); }
private:
    const BoilstreamLocalSecretHostV2 host;
};
} // namespace duckdb
