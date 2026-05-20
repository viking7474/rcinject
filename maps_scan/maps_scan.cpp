#include "maps_scan.hpp"

#include <sys/mman.h>
#include <sys/sysmacros.h>

#include <cinttypes>
#include <list>
#include <map>
#include <vector>

namespace maps_scan {

    void MapInfo::ForEach(const Callback &callback, std::string_view pid) {
        constexpr static auto kPermLength = 5;
        constexpr static auto kMapEntry = 7;
        auto path = "/proc/" + std::string{pid} + "/maps";
        auto maps = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "r"), &fclose};
        if (maps) {
            char *line = nullptr;
            size_t len = 0;
            ssize_t read;
            while ((read = getline(&line, &len, maps.get())) > 0) {
                line[read - 1] = '\0';
                uintptr_t start = 0;
                uintptr_t end = 0;
                uintptr_t off = 0;
                ino_t inode = 0;
                unsigned int dev_major = 0;
                unsigned int dev_minor = 0;
                std::array<char, kPermLength> perm{'\0'};
                int path_off;
                if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n%*s", &start,
                           &end, perm.data(), &off, &dev_major, &dev_minor, &inode,
                           &path_off) != kMapEntry) {
                    continue;
                }
                while (path_off < read && isspace(line[path_off])) path_off++;
                uint8_t perms = 0;
                if (perm[0] == 'r') perms |= PROT_READ;
                if (perm[1] == 'w') perms |= PROT_WRITE;
                if (perm[2] == 'x') perms |= PROT_EXEC;
                MapInfo mi{start, end, perms, perm[3] == 'p', off,
                           static_cast<dev_t>(makedev(dev_major, dev_minor)),
                           inode, line + path_off};

                if (!callback(mi)) break;
            }
            free(line);
        }
    }

    std::vector<MapInfo> MapInfo::Scan(std::string_view pid, std::optional<const Filter> filter) {
        std::vector<MapInfo> info;

        ForEach([&](const auto &map) -> auto {
            if (!filter.has_value() || filter->operator()(map))
                info.emplace_back(map);
            return true;
        }, pid);

        return info;
    }

    void SMapInfo::ForEach(const maps_scan::SCallback &callback, std::string_view pid) {
        constexpr static auto kPermLength = 5;
        constexpr static auto kMapEntry = 7;
        auto path = "/proc/" + std::string{pid} + "/smaps";
        auto maps = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "r"), &fclose};
        if (maps) {
            char *line = nullptr;
            size_t len = 0;
            ssize_t read;
            std::unique_ptr<SMapInfo> info;
            while ((read = getline(&line, &len, maps.get())) > 0) {
                line[read - 1] = '\0';
                uintptr_t start = 0;
                uintptr_t end = 0;
                uintptr_t off = 0;
                ino_t inode = 0;
                unsigned int dev_major = 0;
                unsigned int dev_minor = 0;
                std::array<char, kPermLength> perm{'\0'};
                int path_off;
                if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n%*s", &start,
                           &end, perm.data(), &off, &dev_major, &dev_minor, &inode,
                           &path_off) == kMapEntry) {
                    if (info) {
                        if (!callback(*info)) {
                            info.reset();
                            break;
                        }
                    }
                    while (path_off < read && isspace(line[path_off])) path_off++;
                    uint8_t perms = 0;
                    if (perm[0] == 'r') perms |= PROT_READ;
                    if (perm[1] == 'w') perms |= PROT_WRITE;
                    if (perm[2] == 'x') perms |= PROT_EXEC;
                    info = std::make_unique<SMapInfo>(start, end, perms, perm[3] == 'p', off,
                               static_cast<dev_t>(makedev(dev_major, dev_minor)),
                               inode, line + path_off);
                } else if (info) {
                    std::string_view line_view{line};
                    if (auto sep = line_view.find(':'); sep != std::string_view::npos) {
                        auto k = line_view.substr(0, sep);
                        auto v = line_view.substr(line_view.find_first_not_of(' ', sep + 1));
                        info->fields.emplace_back(std::string{k}, std::string{v});
                    }
                }
            }
            if (info) {
                callback(*info);
            }
            free(line);
        }
    }

    std::vector<SMapInfo> SMapInfo::Scan(std::string_view pid, std::optional<const SFilter> filter) {
        std::vector<SMapInfo> info;

        ForEach([&](const auto &map) -> auto {
            if (!filter.has_value() || filter->operator()(map))
                info.emplace_back(map);
            return true;
        }, pid);

        return info;
    }

    std::string MapInfo::display() const {
        char buf[sizeof(long) * 2 + 1];
        std::string result;
        snprintf(buf, sizeof(buf), "%" PRIxPTR, start);
        result += buf;
        result += "-";
        snprintf(buf, sizeof(buf), "%" PRIxPTR, end);
        result += buf;
        result += ' ';
        result += (perms & PROT_READ) ? 'r' : '-';
        result += (perms & PROT_WRITE) ? 'w' : '-';
        result += (perms & PROT_EXEC) ? 'x' : '-';
        result += is_private ? 'p' : 's';
        result += ' ';
        snprintf(buf, sizeof(buf), "%08" PRIxPTR, offset);
        result += buf;
        result += ' ';
        snprintf(buf, sizeof(buf), "%02" PRIxPTR, major(dev));
        result += buf;
        result += ':';
        snprintf(buf, sizeof(buf), "%02" PRIxPTR, minor(dev));
        result += buf;
        result += ' ';
        snprintf(buf, sizeof(buf), "%lu", inode);
        result += buf;
        result += ' ';
        result += path;
        return result;
    }

    std::string SMapInfo::display() const {
        char buf[sizeof(long) * 2 + 1];
        std::string result;
        snprintf(buf, sizeof(buf), "%" PRIxPTR, start);
        result += buf;
        result += "-";
        snprintf(buf, sizeof(buf), "%" PRIxPTR, end);
        result += buf;
        result += ' ';
        result += (perms & PROT_READ) ? 'r' : '-';
        result += (perms & PROT_WRITE) ? 'w' : '-';
        result += (perms & PROT_EXEC) ? 'x' : '-';
        result += is_private ? 'p' : 's';
        result += ' ';
        snprintf(buf, sizeof(buf), "%08" PRIxPTR, offset);
        result += buf;
        result += ' ';
        snprintf(buf, sizeof(buf), "%02" PRIxPTR, major(dev));
        result += buf;
        result += ':';
        snprintf(buf, sizeof(buf), "%02" PRIxPTR, minor(dev));
        result += buf;
        result += ' ';
        snprintf(buf, sizeof(buf), "%lu", inode);
        result += buf;
        result += ' ';
        result += path;
        // TODO: smaps
        /*
        char buf[sizeof(long) * 2 + 1];
        result += '\n';
        result += "SZ:";
        snprintf(buf, sizeof(buf), "%zu", size);
        result += buf;
        result += " RSS:";
        snprintf(buf, sizeof(buf), "%zu", rss);
        result += buf;
        result += " PSS:";
        snprintf(buf, sizeof(buf), "%zu", pss);
        result += buf;
        result += " SC:";
        snprintf(buf, sizeof(buf), "%zu", shared_clean);
        result += buf;
        result += " SD:";
        snprintf(buf, sizeof(buf), "%zu", shared_dirty);
        result += buf;
        result += " PC:";
        snprintf(buf, sizeof(buf), "%zu", private_clean);
        result += buf;
        result += " PD:";
        snprintf(buf, sizeof(buf), "%zu", private_dirty);
        result += buf;
        result += " REF:";
        snprintf(buf, sizeof(buf), "%zu", referenced);
        result += buf;
        result += " ANON:";
        snprintf(buf, sizeof(buf), "%zu", anonymous);
        result += buf;*/
        return result;
    }
}
