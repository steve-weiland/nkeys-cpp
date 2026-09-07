#pragma once

#include <stdexcept>

namespace nkeys {

    /// Polymorphic tag base for every exception this library throws.
    /// `catch (const nkeys::Error&)` distinguishes nkeys failures from the
    /// standard library's own exceptions and still carries the message via
    /// what(). Each concrete error ALSO derives from the std exception it
    /// historically was (std::invalid_argument, std::runtime_error,
    /// std::logic_error), so pre-taxonomy catch sites keep working.
    class Error {
    public:
        virtual ~Error() = default;
        [[nodiscard]] virtual const char* what() const noexcept = 0;

    protected:
        Error() = default;
        Error(const Error&) = default;
        Error& operator=(const Error&) = default;
    };

    namespace detail {
        /// Grafts the Error interface onto a std exception base, forwarding
        /// what(). Base is std::invalid_argument / runtime_error / logic_error.
        template <typename Base>
        class ErrorImpl : public Base, public Error {
        public:
            using Base::Base;
            [[nodiscard]] const char* what() const noexcept override { return Base::what(); }
        };
    } // namespace detail

    /// A key, seed, or encoded string is malformed or of the wrong type:
    /// bad Base32/CRC/length/prefix, a seed where a public key belongs (or
    /// vice versa), a curve key given to a signing entry point (or vice
    /// versa), an invalid seal/open recipient or sender.
    class InvalidKeyError : public detail::ErrorImpl<std::invalid_argument> {
        using ErrorImpl::ErrorImpl;
    };

    /// A sealed payload could not be opened: wrong wire format or version,
    /// or Poly1305 authentication failure (tampering, or the wrong key pair).
    class DecryptionError : public detail::ErrorImpl<std::runtime_error> {
        using ErrorImpl::ErrorImpl;
    };

    /// A decorated credentials (.creds) block didn't contain what was asked
    /// for — no nkey seed found, or not a seed of the required type.
    class CredsError : public detail::ErrorImpl<std::invalid_argument> {
        using ErrorImpl::ErrorImpl;
    };

    /// The platform's secure random source is unavailable or failed.
    class RandomnessError : public detail::ErrorImpl<std::runtime_error> {
        using ErrorImpl::ErrorImpl;
    };

    /// A key pair was used after wipe() ended its lifetime.
    class WipedKeyError : public detail::ErrorImpl<std::logic_error> {
        using ErrorImpl::ErrorImpl;
    };

} // namespace nkeys
