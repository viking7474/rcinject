#include "logging.hpp"

#include "elf_parser.hpp"
#include "maps_scan.hpp"
#include "misc.hpp"

#include <map>
#include <string>
#include <memory>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

/*
static const char kInjectedRc[] = ""
"on property:sys.aaa=*\n"
"    setprop sys.bbb 11111\n"
"\n"
;*/

static const char kCreateParser[] = "_ZN7android4init12CreateParserERNS0_13ActionManagerERNS0_11ServiceListE";
static const char kParseConfig[] = "_ZN7android4init6Parser11ParseConfigERKNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE";
static const char kActionManagerGetInstance[] = "_ZN7android4init13ActionManager11GetInstanceEv";
static const char kServiceListGetInstance[] = "_ZN7android4init11ServiceList11GetInstanceEv";

struct ServiceList {
    inline static ServiceList& (*GetInstance_fn)() = nullptr;
};

struct ActionManager {
    inline static ActionManager& (*GetInstance_fn)() = nullptr;
};

class SectionParser {
  public:
    virtual ~SectionParser() {}
    virtual void ParseSection(std::vector<std::string>&& args, const std::string& filename,
                                      int line) = 0;
    virtual void ParseLineSection(std::vector<std::string>&&, int) { return; };
    virtual void EndSection() { return; };
    virtual void EndFile(){};
};
class Line;

class Parser {
    using LineCallback = std::function<void(std::vector<std::string>&&)>;
private:
    std::map<std::string, std::unique_ptr<SectionParser>> section_parsers_;
    std::vector<std::pair<std::string, LineCallback>> line_callbacks_;
    size_t parse_error_count_ = 0;

public:
    inline static Parser (*CreateParser_fn)(ActionManager&, ServiceList&) = nullptr;
    inline static void (*ParseConfig_fn)(Parser*, const std::string& filename) = nullptr;
};

static bool write_fully(int fd, const char *buf, size_t len) {
    const char *p = buf;
    size_t l = len;
    for (;;) {
        auto r = TEMP_FAILURE_RETRY(write(fd, p, l));
        if (r < 0) {
            PLOGE("write");
            return false;
        }
        if (r == 0) break;
        l -= r;
        p += r;
    }
    if (l != 0) {
        LOGE("not fully write: remain {}", l);
    }
    return l == 0;
}

extern "C"
[[gnu::used, gnu::visibility("default")]]
int Entry() {
    LOGI("loaded");

    std::string path;
    uintptr_t base = 0;

    maps_scan::MapInfo::ForEach([&](const maps_scan::MapInfo &info) -> bool {
        if (info.offset == 0 && info.path.ends_with("/init")) {
            path = info.path;
            base = info.start;
        }
        return true;
    });

    if (!base) {
        LOGE("no init found");
        return 1;
    }

    {
        elf_parser::Elf elf{};
        if (!elf.InitFromFile(path, base, true)) {
            LOGE("parse init");
            return 1;
        }

        #define FIND_SYM(VAR, NAME) \
        VAR = (decltype(VAR)) elf.getSymbAddress(NAME); \
        if (!VAR) { \
            LOGE("failed to find " #VAR); \
            return 1; \
        }

        FIND_SYM(Parser::CreateParser_fn, kCreateParser)
        FIND_SYM(Parser::ParseConfig_fn, kParseConfig)
        FIND_SYM(ServiceList::GetInstance_fn, kServiceListGetInstance)
        FIND_SYM(ActionManager::GetInstance_fn, kActionManagerGetInstance)
    }

    UniqueFd fd = syscall(__NR_memfd_create, "config", MFD_CLOEXEC);
    if (fchmod(fd, 0600) < 0) {
        PLOGE("chmod memfd");
    }
    if (!fd.valid()) {
        PLOGE("create config fd");
        return 2;
    }

    /*
    if (!write_fully(fd, kInjectedRc, sizeof(kInjectedRc) - 1)) {
        LOGE("not fully written");
        return 3;
    }*/

    auto config_path = Format("/proc/self/fd/{}", fd.as_fd());
    LOGD("open {}", config_path);

    auto parser = Parser::CreateParser_fn(ActionManager::GetInstance_fn(), ServiceList::GetInstance_fn());
    LOGD("injecting rc {}", config_path);
    Parser::ParseConfig_fn(&parser, config_path);
    LOGD("inject done!");
    return 0;
}
