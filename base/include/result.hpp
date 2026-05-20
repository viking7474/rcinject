#pragma once
#include <cerrno>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <variant>
#include <vector>

constexpr const auto UNKNOWN_ERROR = 0;
constexpr const auto ERRNO_ERROR = 1;

struct Void {};

struct Error {
    int32_t code;
    int32_t sub_code;
    std::vector<std::string> msgs;

    [[nodiscard]] inline std::string display() const {
        std::string m = "Error code=";
        m += std::to_string(code);
        m += " sub=";
        m += std::to_string(sub_code);
        m += '\n';
        for (auto i = 0; i < msgs.size(); i++) {
            m += std::to_string(i);
            m += ": ";
            m += msgs[i];
            m += '\n';
        }
        return m;
    }
};

template <typename T>
class Result {
    std::variant<T, Error> v{};

public:
    // NOLINTNEXTLINE
    inline Result() {}
    inline Result(T d) : v(d) {}

    // NOLINTNEXTLINE
    inline Result(Error e) : v(e) {}

    inline bool is_err() { return v.index() == 1; }

    inline bool is_ok() { return v.index() == 0; }

    inline T get_value() { return std::get<0>(v); }

    inline Error get_error() { return std::get<1>(v); }

    inline Result<T> &context(const std::string &msg) {
        if (is_err()) {
            Error &e = std::get<1>(v);
            e.msgs.push_back(msg);
        }
        return *this;
    }

    inline Result<T> &with_context(const std::function<std::string()> &fn) {
        if (is_err()) {
            Error &e = std::get<1>(v);
            e.msgs.push_back(fn());
        }
        return *this;
    }
};

inline Result<Void> Ok() { return Result<Void>(Void{}); }

inline Error Err(std::string msg) { return Error{UNKNOWN_ERROR, 0, {std::move(msg)}}; }

inline Error Err(int32_t code) { return Error{code, 0, {""}}; }

inline Error Err(int32_t code, std::string msg) { return Error{code, 0, {std::move(msg)}}; }

inline Error Err(int32_t code, int32_t sub_code, std::string msg) {
    return Error{code, sub_code, {std::move(msg)}};
}

inline Error Errno(const std::string &msg) {
    return Error{ERRNO_ERROR, errno, {msg + " failed with " + std::to_string(errno)}};
}

#define TRY(expr)                                                                                  \
    ({                                                                                             \
        auto __result = (expr);                                                                    \
        if (__result.is_err()) return __result.get_error();                                        \
        __result.get_value();                                                                      \
    })
#define WITH_CONTEXT(v) with_context([&]() -> auto { return (v); })
