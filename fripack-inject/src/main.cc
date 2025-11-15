#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "logger.h"

#ifdef __ANDROID__
#include <android/log.h>
#include <jni.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

#include "frida-gumjs.h"

#include "hooks.h"
#include "stacktrace.h"
#include "config.h"

namespace fripack {

class GumJSHookManager {
private:
  std::unique_ptr<std::thread> hook_thread_;

  GumScriptBackend *backend_ = nullptr;
  GCancellable *cancellable_ = nullptr;
  GError *error_ = nullptr;
  GumScript *script_ = nullptr;
  GMainContext *context_ = nullptr;
  GMainLoop *loop_ = nullptr;
  bool initialized_ = false;

public:
  GumJSHookManager() = default;
  ~GumJSHookManager() { cleanup(); }

  GumJSHookManager(const GumJSHookManager &) = delete;
  GumJSHookManager &operator=(const GumJSHookManager &) = delete;

  static void on_message(const gchar *message, GBytes *data,
                         gpointer user_data) {
    JsonParser *parser = json_parser_new();
    if (!json_parser_load_from_data(parser, message, -1, nullptr)) {
      logger::println("Failed to parse JSON message");
      g_object_unref(parser);
      return;
    }

    JsonNode *root_node = json_parser_get_root(parser);
    if (!root_node) {
      g_object_unref(parser);
      return;
    }

    JsonObject *root = json_node_get_object(root_node);
    if (!root) {
      g_object_unref(parser);
      return;
    }

    const gchar *type = json_object_get_string_member(root, "type");
    if (type && strcmp(type, "log") == 0) {
      const gchar *log_message = json_object_get_string_member(root, "payload");
      if (log_message) {
        logger::println("[*] log: {}", log_message);
      }
    } else {
      logger::println("[*] {}", message);
    }

    g_object_unref(parser);
  }

  std::promise<void> start_js_thread(const std::string &js_content) {
    logger::println("[*] Starting GumJS hook thread");
    std::promise<void> init_promise;
    std::future<void> init_future = init_promise.get_future();
    std::thread([this, js_content = std::move(js_content),
                 promise = std::move(init_promise)]() mutable {
      gum_init_embedded();

      backend_ = gum_script_backend_obtain_qjs();
      logger::println("[*] Obtained Gum Script Backend");

      fripack::hooks::init();

      script_ =
          gum_script_backend_create_sync(backend_, "script", js_content.data(),
                                         nullptr, cancellable_, &error_);
      logger::println("[*] Created Gum Script");
      // return;
      if (error_) {
        throw std::runtime_error(
            fmt::format("Failed to create script: {}", error_->message));
      }

      gum_script_set_message_handler(script_, on_message, nullptr, nullptr);
      gum_script_load_sync(script_, cancellable_);
      context_ = g_main_context_get_thread_default();
      while (g_main_context_pending(context_)) {
        g_main_context_iteration(context_, FALSE);
      }

      promise.set_value();
      loop_ = g_main_loop_new(g_main_context_get_thread_default(), FALSE);
      g_main_loop_run(loop_);
    }).detach();
    // init_future.get();
    return init_promise;
  }

  void stop() {
    if (loop_) {
      g_main_loop_quit(loop_);
    }

    if (hook_thread_ && hook_thread_->joinable()) {
      hook_thread_->join();
    }
  }

private:
  void cleanup() {
    stop();

    if (script_) {
      g_object_unref(script_);
      script_ = nullptr;
    }

    if (cancellable_) {
      g_object_unref(cancellable_);
      cancellable_ = nullptr;
    }

    if (loop_) {
      g_main_loop_unref(loop_);
      loop_ = nullptr;
    }

    if (error_) {
      g_error_free(error_);
      error_ = nullptr;
    }
  }
};

void _fi_main() {
  logger::println("[*] Library loaded, starting GumJS hook");

  // logger::println("Embedded config offset: {}, size: {}, JSON: {}",
  //                 g_embedded_config.data_offset, g_embedded_config.data_size,
  //                 json_str);
  try {
    std::thread([=]() {
      GumJSHookManager *gumjs_hook_manager;
      auto config = fripack::config::configData();

      gumjs_hook_manager = new GumJSHookManager();
      std::string js_content;
      if (config.mode == config::EmbeddedConfigData::Mode::EmbedJs) {
        if (config.js_content) {
          js_content = *config.js_content;
          gumjs_hook_manager->start_js_thread(js_content);
        } else {
          logger::println("No JS content or filepath provided");
          return;
        }
      } else {
        logger::println("Unsupported embedded config mode: {}",
                        static_cast<int32_t>(config.mode));
        return;
      }
    }).detach();
  } catch (const std::exception &e) {
    logger::println("Exception while parsing embedded config data: {}",
                    e.what());
    return;
  }
}
} // namespace fripack

#ifdef _WIN32
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    fripack::_fi_main();
    break;
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}
#else
__attribute__((constructor)) static void _library_main() {
  fripack::_fi_main();
}
#endif