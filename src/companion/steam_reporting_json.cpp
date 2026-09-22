#include "companion/steam_reporting_json.h"

#include <cstring>

namespace rs2fix::reporting {
namespace {
enum class Role : unsigned char { Generic, Root, Properties, Property };
enum class State : unsigned char { FirstKey, Key, Colon, Value, FirstValue, More };
enum class Key : unsigned char { Other, Properties, Name, Value };
enum class CountKey : unsigned char { Other, Pi, Bots, Maximum };
enum class Text : unsigned char { Properties, Name, Value, Pi, Bots, Maximum };
struct Word { const char* text; std::size_t size; };
constexpr Word kWords[]{{"op", 2}, {"k", 1}, {"v", 1}, {"PI_COUNT", 8},
    {"BotPlayerCount", 14}, {"MaxPlayerCount", 14}};

// Streaming equality bits and a decimal accumulator retain no string contents.
// Unknown metadata (including player names) never enters a secondary buffer.
struct StringValue {
    std::size_t length{};
    std::uint32_t number{};
    unsigned matches{63};
    bool decimal{true};
    bool leadingZero{};

    void Add(std::uint32_t scalar) noexcept {
        for (unsigned i = 0; matches && i < 6; ++i) {
            const auto bit = 1U << i;
            if ((matches & bit) && (length >= kWords[i].size ||
                scalar != static_cast<unsigned char>(kWords[i].text[length]))) matches &= ~bit;
        }
        if (scalar < '0' || scalar > '9' || (length && leadingZero)) decimal = false;
        if (!length) leadingZero = scalar == '0';
        if (decimal) {
            const auto digit = scalar - '0';
            if (number > (UINT32_MAX - digit) / 10) decimal = false;
            else number = number * 10 + digit;
        }
        ++length;
    }
    bool Is(Text word) const noexcept {
        const auto index = static_cast<unsigned>(word);
        return (matches & (1U << index)) != 0 && kWords[index].size == length;
    }
    bool IsDecimal() const noexcept { return decimal && length != 0; }
};

struct Frame {
    Role role{};
    State state{};
    Key key{};
    CountKey countKey{};
    std::uint32_t value{};
    bool object{};
    bool haveName{};
    bool haveValue{};
    bool decimalValue{};
};

class Reader {
public:
    Reader(const char* bytes, std::size_t size) noexcept : bytes_(bytes), size_(size) {}

    Reason Run(const NativeCounts& expected) noexcept {
        Space();
        if (!Take('{') || !Token() || !Push(true, Role::Root)) return Failure();
        while (depth_ && error_ == Reason::None) {
            Space();
            auto& frame = stack_[depth_ - 1];
            if (frame.object) {
                switch (frame.state) {
                case State::FirstKey:
                    if (Take('}')) { Close(); break; }
                    [[fallthrough]];
                case State::Key:
                    ReadKey(frame);
                    break;
                case State::Colon:
                    if (!Take(':')) Fail(Reason::PreparedMalformed);
                    else frame.state = State::Value;
                    break;
                case State::Value:
                    ReadValue(frame);
                    break;
                case State::More:
                    if (Take('}')) Close();
                    else if (Take(',')) frame.state = State::Key;
                    else Fail(Reason::PreparedMalformed);
                    break;
                default:
                    Fail(Reason::PreparedMalformed);
                    break;
                }
            } else {
                switch (frame.state) {
                case State::FirstValue:
                    if (Take(']')) { Close(); break; }
                    [[fallthrough]];
                case State::Value:
                    ReadValue(frame);
                    break;
                case State::More:
                    if (Take(']')) Close();
                    else if (Take(',')) frame.state = State::Value;
                    else Fail(Reason::PreparedMalformed);
                    break;
                default:
                    Fail(Reason::PreparedMalformed);
                    break;
                }
            }
        }
        if (error_ != Reason::None) return error_;
        Space();
        if (cursor_ != size_ || seen_ != 7) return Reason::PreparedMalformed;
        return EqualCounts(counts_, expected) ? Reason::None : Reason::PreparedMismatch;
    }

private:
    const char* bytes_;
    std::size_t size_;
    std::size_t cursor_{};
    std::size_t tokens_{};
    std::size_t depth_{};
    Frame stack_[kJsonDepth]{};
    Reason error_{Reason::None};
    NativeCounts counts_{};
    unsigned seen_{};

    void Fail(Reason reason) noexcept { if (error_ == Reason::None) error_ = reason; }
    Reason Failure() const noexcept {
        return error_ == Reason::None ? Reason::PreparedMalformed : error_;
    }
    unsigned char Peek() const noexcept {
        return cursor_ < size_ ? static_cast<unsigned char>(bytes_[cursor_]) : 0;
    }
    bool Take(char c) noexcept {
        if (cursor_ == size_ || bytes_[cursor_] != c) return false;
        ++cursor_;
        return true;
    }
    void Space() noexcept {
        while (cursor_ < size_) {
            const auto c = bytes_[cursor_];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
            ++cursor_;
        }
    }
    bool Token() noexcept {
        if (tokens_ == kJsonTokens) { Fail(Reason::PreparedLimit); return false; }
        ++tokens_;
        return true;
    }
    bool Push(bool object, Role role) noexcept {
        if (depth_ == kJsonDepth) { Fail(Reason::PreparedLimit); return false; }
        auto& frame = stack_[depth_++];
        frame = {};
        frame.object = object;
        frame.role = role;
        frame.state = object ? State::FirstKey : State::FirstValue;
        return true;
    }
    void Close() noexcept {
        const auto& frame = stack_[depth_ - 1];
        if (frame.role == Role::Root && !frame.haveName) Fail(Reason::PreparedMalformed);
        if (frame.role == Role::Property) {
            if (!frame.haveName || !frame.haveValue) Fail(Reason::PreparedMalformed);
            if (frame.countKey != CountKey::Other) {
                const unsigned bit = frame.countKey == CountKey::Pi ? 1U :
                    frame.countKey == CountKey::Bots ? 2U : 4U;
                if (!frame.decimalValue || (seen_ & bit)) Fail(Reason::PreparedMalformed);
                else {
                    seen_ |= bit;
                    if (frame.countKey == CountKey::Pi) counts_.pi = frame.value;
                    else if (frame.countKey == CountKey::Bots) counts_.bots = frame.value;
                    else counts_.maximum = frame.value;
                }
            }
        }
        --depth_;
    }
    void ReadKey(Frame& frame) noexcept {
        StringValue key{};
        if (!Token() || !String(key)) { Fail(Reason::PreparedMalformed); return; }
        frame.key = Key::Other;
        if (frame.role == Role::Root && key.Is(Text::Properties)) {
            if (frame.haveName) { Fail(Reason::PreparedMalformed); return; }
            frame.haveName = true;
            frame.key = Key::Properties;
        } else if (frame.role == Role::Property && key.Is(Text::Name)) {
            if (frame.haveName) { Fail(Reason::PreparedMalformed); return; }
            frame.haveName = true;
            frame.key = Key::Name;
        } else if (frame.role == Role::Property && key.Is(Text::Value)) {
            if (frame.haveValue) { Fail(Reason::PreparedMalformed); return; }
            frame.haveValue = true;
            frame.key = Key::Value;
        }
        frame.state = State::Colon;
    }
    void ReadValue(Frame& parent) noexcept {
        if (!Token()) return;
        const auto first = Peek();
        Role child = Role::Generic;
        if (parent.key == Key::Properties && parent.role == Role::Root) {
            if (first != '[') { Fail(Reason::PreparedMalformed); return; }
            child = Role::Properties;
        } else if (parent.role == Role::Properties) {
            if (first != '{') { Fail(Reason::PreparedMalformed); return; }
            child = Role::Property;
        } else if (parent.role == Role::Property && parent.key == Key::Name && first != '"') {
            Fail(Reason::PreparedMalformed); return;
        }
        parent.state = State::More;
        if (first == '{' || first == '[') {
            ++cursor_;
            Push(first == '{', child);
        } else if (first == '"') {
            StringValue value{};
            if (!String(value)) { Fail(Reason::PreparedMalformed); return; }
            if (parent.role == Role::Property && parent.key == Key::Name) {
                parent.countKey = value.Is(Text::Pi) ? CountKey::Pi :
                    value.Is(Text::Bots) ? CountKey::Bots :
                    value.Is(Text::Maximum) ? CountKey::Maximum : CountKey::Other;
            } else if (parent.role == Role::Property && parent.key == Key::Value) {
                parent.decimalValue = value.IsDecimal();
                parent.value = value.number;
            }
        } else if (first == 't') Literal("true");
        else if (first == 'f') Literal("false");
        else if (first == 'n') Literal("null");
        else if (first == '-' || (first >= '0' && first <= '9')) Number();
        else Fail(Reason::PreparedMalformed);
    }
    void Literal(const char* text) noexcept {
        const auto length = std::strlen(text);
        if (length > size_ - cursor_ || std::memcmp(bytes_ + cursor_, text, length))
            Fail(Reason::PreparedMalformed);
        else cursor_ += length;
    }
    bool Digit() const noexcept { return Peek() >= '0' && Peek() <= '9'; }
    void Number() noexcept {
        Take('-');
        if (Take('0')) { /* A following digit is rejected by container syntax. */ }
        else {
            if (Peek() < '1' || Peek() > '9') { Fail(Reason::PreparedMalformed); return; }
            do { ++cursor_; } while (Digit());
        }
        if (Take('.')) {
            if (!Digit()) { Fail(Reason::PreparedMalformed); return; }
            do { ++cursor_; } while (Digit());
        }
        if (Take('e') || Take('E')) {
            if (!Take('+')) Take('-');
            if (!Digit()) { Fail(Reason::PreparedMalformed); return; }
            do { ++cursor_; } while (Digit());
        }
    }
    bool HexWord(std::uint32_t& scalar) noexcept {
        scalar = 0;
        if (size_ - cursor_ < 4) return false;
        for (unsigned i = 0; i < 4; ++i) {
            const auto c = static_cast<unsigned char>(bytes_[cursor_++]);
            unsigned value{};
            if (c >= '0' && c <= '9') value = c - '0';
            else if (c >= 'a' && c <= 'f') value = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') value = c - 'A' + 10;
            else return false;
            scalar = (scalar << 4) | value;
        }
        return true;
    }
    bool Escape(std::uint32_t& scalar) noexcept {
        if (cursor_ == size_) return false;
        switch (bytes_[cursor_++]) {
        case '"': scalar = '"'; return true;
        case '\\': scalar = '\\'; return true;
        case '/': scalar = '/'; return true;
        case 'b': scalar = '\b'; return true;
        case 'f': scalar = '\f'; return true;
        case 'n': scalar = '\n'; return true;
        case 'r': scalar = '\r'; return true;
        case 't': scalar = '\t'; return true;
        case 'u':
            if (!HexWord(scalar)) return false;
            if (scalar >= 0xD800 && scalar <= 0xDBFF) {
                std::uint32_t low{};
                if (!Take('\\') || !Take('u') || !HexWord(low) || low < 0xDC00 || low > 0xDFFF)
                    return false;
                scalar = 0x10000 + ((scalar - 0xD800) << 10) + (low - 0xDC00);
            } else if (scalar >= 0xDC00 && scalar <= 0xDFFF) return false;
            return true;
        default: return false;
        }
    }
    bool Utf8(unsigned char first, std::uint32_t& scalar) noexcept {
        unsigned continuation{};
        std::uint32_t minimum{};
        if (first >= 0xC2 && first <= 0xDF) { continuation = 1; scalar = first & 0x1FU; minimum = 0x80; }
        else if (first >= 0xE0 && first <= 0xEF) { continuation = 2; scalar = first & 0x0FU; minimum = 0x800; }
        else if (first >= 0xF0 && first <= 0xF4) { continuation = 3; scalar = first & 0x07U; minimum = 0x10000; }
        else return false;
        if (continuation > size_ - cursor_) return false;
        for (unsigned i = 0; i < continuation; ++i) {
            const auto c = static_cast<unsigned char>(bytes_[cursor_++]);
            if ((c & 0xC0U) != 0x80U) return false;
            scalar = (scalar << 6) | (c & 0x3FU);
        }
        return scalar >= minimum && scalar <= 0x10FFFF && !(scalar >= 0xD800 && scalar <= 0xDFFF);
    }
    bool String(StringValue& value) noexcept {
        if (!Take('"')) return false;
        while (cursor_ < size_) {
            const auto c = static_cast<unsigned char>(bytes_[cursor_++]);
            if (c == '"') return true;
            if (c < 0x20) return false;
            std::uint32_t scalar = c;
            if (c == '\\') { if (!Escape(scalar)) return false; }
            else if (c >= 0x80 && !Utf8(c, scalar)) return false;
            value.Add(scalar);
        }
        return false;
    }
};
} // namespace

Reason ValidatePreparedJson(const char* bytes, std::size_t size,
    const NativeCounts& expected) noexcept {
    if (!bytes || !size) return Reason::PreparedUnavailable;
    if (size > kJsonBytes) return Reason::PreparedLimit;
    Reader reader(bytes, size);
    return reader.Run(expected);
}
} // namespace rs2fix::reporting
