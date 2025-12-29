#pragma once
#include <algorithm>
#include <map>
#include <string>
#include <utility>
#include <vector>
#include <optional>

// trim whitespace (both ends)
inline std::string trim(std::string s) {
    auto isspace = [](unsigned char c){ return std::isspace(c); };
    auto b = std::find_if_not(s.begin(), s.end(), isspace);
    auto e = std::find_if_not(s.rbegin(), s.rend(), isspace).base();
    if (b >= e) return {};
    return {b, e};
}

struct cmd_args {
    std::map<std::string, std::string> options;
    std::vector<std::string> positional;
    static cmd_args parse(int argc, char* argv[]) {
        cmd_args result;

        auto put = [&](std::string k, std::string v) {
            result.options[trim(std::move(k))] = trim(std::move(v));
        };

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];

            // ----- LONG OPTIONS -----
            if (arg.rfind("--", 0) == 0) {
                std::string rest = arg.substr(2);
                // handle --key[=value] and --key = value
                auto eq = rest.find('=');
                if (eq != std::string::npos) {
                    std::string key = trim(rest.substr(0, eq));
                    std::string val = trim(rest.substr(eq + 1));
                    // Consistent behavior with short options: --key= becomes "true"
                    put(key, val.empty() ? "true" : val);
                } else {
                    std::string key = trim(rest);
                    // support: --key value  OR  --key = value
                    if (i + 2 < argc && std::string(argv[i + 1]) == "=") {
                        put(key, argv[i + 2]);
                        i += 2;
                    } else if (i + 1 < argc && std::string(argv[i + 1]).rfind('-', 0) != 0
                               && std::string(argv[i + 1]) != "=") {
                        put(key, argv[++i]);
                    } else {
                        put(key, "true");
                    }
                }
                continue;
            }

            // ----- SHORT OPTIONS (including grouped) -----
            if (arg.size() >= 2 && arg[0] == '-' && arg[1] != '-') {
                std::string s = arg.substr(1);

                // -x=value  (explicit value for short)
                auto eq = s.find('=');
                if (eq != std::string::npos && eq >= 1) {
                    std::string key(1, s[0]);
                    std::string val = s.substr(eq + 1);
                    put(key, val.empty() ? "true" : val);
                    continue;
                }

                if (s.size() > 1) {
                    // Treat as grouped flags: -abc => a=true,b=true,c=true
                    for (char ch : s) put(std::string(1, ch), "true");
                } else {
                    // single short: -o  [value]  or  -o = value
                    // std::string key = s;
                    if (i + 2 < argc && std::string(argv[i + 1]) == "=") {
                        put(s, argv[i + 2]);
                        i += 2;
                    } else if (i + 1 < argc && std::string(argv[i + 1]).rfind('-', 0) != 0
                               && std::string(argv[i + 1]) != "=") {
                        put(s, argv[++i]);
                    } else {
                        put(s, "true");
                    }
                }
                continue;
            }
            result.positional.push_back(trim(arg));
        }

        return result;
    }

    [[nodiscard]] std::optional<std::string> get(std::string_view key) const {
        if (const auto it = options.find(std::string(key)); it != options.end()) return it->second;
        return std::nullopt;
    }
};
