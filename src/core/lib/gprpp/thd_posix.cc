/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/* Posix implementation for gpr threads. */

#include <grpc/support/port_platform.h>

#include <grpc/support/time.h>

#ifdef GPR_POSIX_SYNC

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <grpc/support/log.h>
#include <grpc/support/sync.h>
#include <grpc/support/thd_id.h>

#include "src/core/lib/gpr/useful.h"
#include "src/core/lib/gprpp/fork.h"
#include "src/core/lib/gprpp/thd.h"

namespace grpc_core {
namespace {
class ThreadInternalsPosix;

struct thd_arg {
  ThreadInternalsPosix* thread;
  void (*body)(void* arg); /* body of a thread */
  void* arg;               /* argument to a thread */
  const char* name;        /* name of thread. Can be nullptr. */
  bool joinable;
  bool tracked;
};

size_t RoundUpToPageSize(size_t size) {
  // TODO(yunjiaw): Change this variable (page_size) to a function-level static
  // when possible
  size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  return (size + page_size - 1) & ~(page_size - 1);
}

// Returns the minimum valid stack size that can be passed to
// pthread_attr_setstacksize.
size_t MinValidStackSize(size_t request_size) {
  size_t min_stacksize = sysconf(_SC_THREAD_STACK_MIN);
  if (request_size < min_stacksize) {
    request_size = min_stacksize;
  }

  // On some systems, pthread_attr_setstacksize() can fail if stacksize is
  // not a multiple of the system page size.
  return RoundUpToPageSize(request_size);
}

class ThreadInternalsPosix : public internal::ThreadInternalsInterface {
 public:
  ThreadInternalsPosix(const char* thd_name, void (*thd_body)(void* arg),
                       void* arg, bool* success, const Thread::Options& options)
      : started_(false) {
    gpr_mu_init(&mu_);
    gpr_cv_init(&ready_);
    pthread_attr_t attr;
    /* don't use gpr_malloc as we may cause an infinite recursion with
     * the profiling code */
    thd_arg* info = static_cast<thd_arg*>(malloc(sizeof(*info)));
    GPR_ASSERT(info != nullptr);
    info->thread = this;
    info->body = thd_body;
    info->arg = arg;
    info->name = thd_name;
    info->joinable = options.joinable();
    info->tracked = options.tracked();
    if (options.tracked()) {
      Fork::IncThreadCount();
    }

    GPR_ASSERT(pthread_attr_init(&attr) == 0);
    if (options.joinable()) {
      GPR_ASSERT(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE) ==
                 0);
    } else {
      GPR_ASSERT(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) ==
                 0);
    }

    if (options.stack_size() != 0) {
      size_t stack_size = MinValidStackSize(options.stack_size());
      GPR_ASSERT(pthread_attr_setstacksize(&attr, stack_size) == 0);
    }

    *success = (pthread_create(
                    &pthread_id_, &attr,
                    [](void* v) -> void* {
                      thd_arg arg = *static_cast<thd_arg*>(v);
                      free(v);
                      if (arg.name != nullptr) {
#if GPR_APPLE_PTHREAD_NAME
                        /* Apple supports 64 characters, and will
                         * truncate if it's longer. */
                        pthread_setname_np(arg.name);
#elif GPR_LINUX_PTHREAD_NAME
                        /* Linux supports 16 characters max, and will
                         * error if it's longer. */
                        char buf[16];
                        size_t buf_len = GPR_ARRAY_SIZE(buf) - 1;
                        strncpy(buf, arg.name, buf_len);
                        buf[buf_len] = '\0';
                        pthread_setname_np(pthread_self(), buf);
#endif  // GPR_APPLE_PTHREAD_NAME
                      }

                      gpr_mu_lock(&arg.thread->mu_);
                      while (!arg.thread->started_) {
                        gpr_cv_wait(&arg.thread->ready_, &arg.thread->mu_,
                                    gpr_inf_future(GPR_CLOCK_MONOTONIC));
                      }
                      gpr_mu_unlock(&arg.thread->mu_);

                      if (!arg.joinable) {
                        delete arg.thread;
                      }

                      (*arg.body)(arg.arg);
                      if (arg.tracked) {
                        Fork::DecThreadCount();
                      }
                      return nullptr;
                    },
                    info) == 0);

    GPR_ASSERT(pthread_attr_destroy(&attr) == 0);

    if (!(*success)) {
      /* don't use gpr_free, as this was allocated using malloc (see above) */
      free(info);
      if (options.tracked()) {
        Fork::DecThreadCount();
      }
    }
  }

  ~ThreadInternalsPosix() override {
    gpr_mu_destroy(&mu_);
    gpr_cv_destroy(&ready_);
  }

  void Start() override {
    gpr_mu_lock(&mu_);
    started_ = true;
    gpr_cv_signal(&ready_);
    gpr_mu_unlock(&mu_);
  }

  void Join() override { pthread_join(pthread_id_, nullptr); }

 private:
  gpr_mu mu_;
  gpr_cv ready_;
  bool started_;
  pthread_t pthread_id_;
};

}  // namespace

Thread::Thread(const char* thd_name, void (*thd_body)(void* arg), void* arg,
               bool* success, const Options& options)
    : options_(options) {
  bool outcome = false;
  impl_ = new ThreadInternalsPosix(thd_name, thd_body, arg, &outcome, options);
  if (outcome) {
    state_ = ALIVE;
  } else {
    state_ = FAILED;
    delete impl_;
    impl_ = nullptr;
  }

  if (success != nullptr) {
    *success = outcome;
  }
}
}  // namespace grpc_core

// The following is in the external namespace as it is exposed as C89 API
gpr_thd_id gpr_thd_currentid(void) {
  // Use C-style casting because Linux and OSX have different definitions
  // of pthread_t so that a single C++ cast doesn't handle it.
  // NOLINTNEXTLINE(google-readability-casting)
  return (gpr_thd_id)pthread_self();
}

#endif /* GPR_POSIX_SYNC */
