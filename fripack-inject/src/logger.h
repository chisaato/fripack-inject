#ifdef __ANDROID__
#include <android/log.h>
#include <jni.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

#include <string>
#include <fmt/chrono.h>
#include <fmt/format.h>

namespace fripack::logger {

#ifdef __ANDROID__
inline void log(const char *tag, const std::string &message) {
  __android_log_write(ANDROID_LOG_INFO, tag, message.c_str());
}

#else
inline void log(const char *tag, const std::string &message) {
  auto now = std::chrono::system_clock::now();
  auto time_t = std::chrono::system_clock::to_time_t(now);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) %
            1000;

  std::string formatted = fmt::format("[{:%Y-%m-%d %H:%M:%S}.{:03d}] [{}] {}",
                                      now, ms.count(), tag, message);

  fmt::println("{}", formatted);

#ifdef _WIN32
  OutputDebugStringA(formatted.c_str());
  OutputDebugStringA("\n");
#endif
}
#endif

template <typename... Args>
void println(fmt::format_string<Args...> format, Args &&...args) {
  std::string message = fmt::format(format, std::forward<Args>(args)...);
  log("FriPackInject", message);
}
} // namespace fripack::logger