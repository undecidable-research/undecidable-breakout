/* breakout-landlock: minimal Landlock launcher. Compiles on demand (cc).
 * Restricts: filesystem (v1 mask) + TCP bind/connect when the kernel ABI
 * supports it (>= 6.7). Fails closed (exit 126) if Landlock is unavailable,
 * so the runner can mark the profile SKIPPED instead of running unsandboxed.
 * ponytail: v1 access mask only; REFER/TRUNCATE/IOCTL_DEV rules and per-path
 * granularity can come with a real need. Upgrade path: kernel sandboxer.c.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define FS_V1_MASK                                   \
  (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | \
   LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | \
   LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | \
   LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | \
   LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK | \
   LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
   LANDLOCK_ACCESS_FS_MAKE_SYM)

/* landlock_create_ruleset(2) is two distinct operations: ABI probing passes
 * attr == NULL / size == 0 together with LANDLOCK_CREATE_RULESET_VERSION and
 * returns the highest supported ABI (>= 1); actual ruleset creation must use
 * flags == 0. Combining a non-NULL attr with the VERSION flag is invalid
 * usage -- kernels reject it with EINVAL -- which used to kill this helper
 * before exec while containment tests still "passed" on empty stdout. */
struct attr_fs_net { uint64_t fs; uint64_t net; };
struct attr_fs { uint64_t fs; };

static int probe_abi(void) {
  long v = syscall(SYS_landlock_create_ruleset, NULL, 0,
                   LANDLOCK_CREATE_RULESET_VERSION);
  return (int)v;
}

static int create_ruleset(uint64_t fs_mask, uint64_t net_mask) {
  /* flags MUST be 0 for creation; VERSION is probe-only (see above). */
  if (net_mask) {
    struct attr_fs_net a = {.fs = fs_mask, .net = net_mask};
    return (int)syscall(SYS_landlock_create_ruleset, &a, sizeof(a), 0);
  }
  struct attr_fs a = {.fs = fs_mask};
  return (int)syscall(SYS_landlock_create_ruleset, &a, sizeof(a), 0);
}

static int allow_path(int rs, const char *path, uint64_t access) {
  struct landlock_path_beneath_attr pb = {.allowed_access = access};
  pb.parent_fd = open(path, O_PATH | O_CLOEXEC);
  if (pb.parent_fd < 0) return 0; /* path absent on this system: fine */
  int r = syscall(SYS_landlock_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
  close(pb.parent_fd);
  return r == 0 ? 0 : -1;
}

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: breakout-landlock CMD [ARGS...]\n"); return 2; }
  int abi = probe_abi();
  if (abi < 1) {
    int e = errno;
    fprintf(stderr,
            "breakout-landlock: landlock unavailable on this kernel: %s\n",
            strerror(e));
    return 126; /* fail closed: runner marks the profile skipped */
  }
  /* Every right in FS_V1_MASK exists since ABI 1, so the filesystem policy is
   * requestable on any supported kernel; newer ABIs only ADD rights (REFER,
   * TRUNCATE, ...), which stay deliberately unhandled (see file header).
   * Network handling needs handled_access_net, added in ABI 4 (Linux 6.7):
   * older kernels reject the wider attr layout with E2BIG, so gate it on the
   * probed version instead of discovering that via a failed creation. */
  uint64_t net_mask =
      abi >= 4 ? (LANDLOCK_ACCESS_NET_BIND_TCP |
                  LANDLOCK_ACCESS_NET_CONNECT_TCP)
               : 0;
  int rs = create_ruleset(FS_V1_MASK, net_mask);
  if (rs < 0) {
    int e = errno;
    fprintf(stderr, "breakout-landlock: landlock_create_ruleset failed: %s\n",
            strerror(e));
    return 126; /* fail closed: never fall back to running unsandboxed */
  }
  static const char *ro_dirs[] = {"/usr", "/bin", "/sbin", "/lib", "/lib64",
                                  "/lib32", "/etc", "/opt", NULL};
  static const char *ro_proc[] = {"/proc", "/sys", NULL};
  static const char *rw_dirs[] = {"/tmp", "/dev", "/var/tmp", NULL};
  for (int i = 0; ro_dirs[i]; i++)
    if (allow_path(rs, ro_dirs[i], LANDLOCK_ACCESS_FS_READ_FILE |
                                  LANDLOCK_ACCESS_FS_READ_DIR |
                                  LANDLOCK_ACCESS_FS_EXECUTE) != 0) goto fail;
  for (int i = 0; ro_proc[i]; i++)
    if (allow_path(rs, ro_proc[i], LANDLOCK_ACCESS_FS_READ_FILE |
                                  LANDLOCK_ACCESS_FS_READ_DIR) != 0) goto fail;
  for (int i = 0; rw_dirs[i]; i++)
    if (allow_path(rs, rw_dirs[i], FS_V1_MASK) != 0) goto fail;
  /* home intentionally NOT allowed: the decoys must be unreachable */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) goto fail;
  if (syscall(SYS_landlock_restrict_self, rs, 0) != 0) goto fail;
  execvp(argv[1], &argv[1]);
  perror("execvp");
  return 127;
fail:
  fprintf(stderr, "breakout-landlock: failed to apply ruleset\n");
  return 126;
}
