/* Linux host integration tests for the actual byte-message filesystem broker.
 * No guest ELF, Android process, host command fallback, or signal trap is used. */
#include "guest_landlock.h"
#include "guest_directory.h"
#include "trusted_exec_image.h"
#include "workspace_broker.h"
#include "workspace_locks.h"
#include "broker_transport.h"
#include "guest_abi.h"
#include "guest_fds.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    (void)fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #condition, errno); \
    exit(1); \
} } while (0)

struct client { int socket, done; };
static unsigned int skipped_subcases;

static void joined_path(char *out, size_t size, const char *parent, const char *name) {
    int written = snprintf(out, size, "%s/%s", parent, name);
    CHECK(written >= 0 && (size_t)written < size);
}

static struct client connect_broker(const char *workspace) {
    struct client client = { .socket = -1, .done = -1 };
    client.socket = sucrune_workspace_broker(workspace, &client.done);
    CHECK(client.socket >= 0 && client.done >= 0);
    struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
    CHECK(setsockopt(client.socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(client.socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    return client;
}

static void send_bytes(int socket, const void *data, size_t size) {
    ssize_t sent;
    do { sent = send(socket, data, size, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
    CHECK(sent >= 0 && (size_t)sent == size);
}

static void await_eof(int fd, bool socket) {
    struct pollfd wait = { .fd = fd, .events = POLLIN };
    int ready;
    do { ready = poll(&wait, 1U, 2000); } while (ready < 0 && errno == EINTR);
    CHECK(ready == 1);
    char byte;
    ssize_t got;
    do { got = socket ? recv(fd, &byte, 1U, 0) : read(fd, &byte, 1U); } while (got < 0 && errno == EINTR);
    CHECK(got == 0);
}

static void disconnect_broker(struct client *client) {
    CHECK(close(client->socket) == 0);
    client->socket = -1;
    // A closed client alone does not prove that a queued file operation ended.
    // The separate completion EOF is emitted after all broker-owned FDs close.
    await_eof(client->done, false);
    CHECK(close(client->done) == 0);
    client->done = -1;
}

static struct sucrune_response exchange(struct client client, const struct sucrune_request *request) {
    send_bytes(client.socket, request, offsetof(struct sucrune_request, data) + request->size);
    struct sucrune_response response;
    ssize_t got;
    do { got = recv(client.socket, &response, sizeof(response), MSG_TRUNC); } while (got < 0 && errno == EINTR);
    CHECK(got >= (ssize_t)offsetof(struct sucrune_response, data));
    CHECK(got <= (ssize_t)sizeof(response));
    CHECK(response.magic == SUCRUNE_BROKER_MAGIC && response.size <= SUCRUNE_IO_LIMIT);
    CHECK((size_t)got == offsetof(struct sucrune_response, data) + response.size);
    return response;
}

static struct sucrune_request request(uint32_t operation) {
    struct sucrune_request result = { .magic = SUCRUNE_BROKER_MAGIC, .operation = operation };
    return result;
}

static void append_path(struct sucrune_request *packet, const char *path) {
    size_t count = strlen(path) + 1U;
    CHECK(count <= SUCRUNE_IO_LIMIT - packet->size);
    memcpy(packet->data + packet->size, path, count);
    packet->size += (uint32_t)count;
}

static int64_t path_operation(struct client client, uint32_t operation, const char *path, int flags) {
    struct sucrune_request packet = request(operation);
    packet.args[0] = AT_FDCWD;
    packet.args[1] = flags;
    append_path(&packet, path);
    return exchange(client, &packet).result;
}

static int64_t rename_path(struct client client, const char *from, const char *to) {
    struct sucrune_request packet = request(38U);
    packet.args[0] = AT_FDCWD;
    packet.args[1] = AT_FDCWD;
    append_path(&packet, from);
    append_path(&packet, to);
    return exchange(client, &packet).result;
}

static struct sucrune_response file_operation(struct client client, uint32_t operation, int64_t fd, int64_t value, int64_t extra) {
    struct sucrune_request packet = request(operation);
    packet.args[0] = fd;
    packet.args[1] = value;
    packet.args[2] = extra;
    return exchange(client, &packet);
}

static int64_t write_file(struct client client, int64_t fd, const char *text) {
    struct sucrune_request packet = request(64U);
    packet.args[0] = fd;
    packet.size = (uint32_t)strlen(text);
    packet.args[1] = packet.size;
    memcpy(packet.data, text, packet.size);
    return exchange(client, &packet).result;
}

static void check_cwd(struct client client, const char *expected) {
    struct sucrune_request packet = request(17U);
    packet.args[0] = SUCRUNE_PATH_LIMIT;
    struct sucrune_response response = exchange(client, &packet);
    CHECK(response.result == (int64_t)strlen(expected) + 1);
    CHECK(response.size == strlen(expected) + 1U);
    CHECK(memcmp(response.data, expected, response.size) == 0);
}

static int64_t open_read(struct client c, const char *name, int flags, int *right) {
    struct sucrune_request r = request(SUCRUNE_BROKER_OPEN_READ);
    r.args[0] = AT_FDCWD;
    r.args[1] = flags;
    append_path(&r, name);
    struct sucrune_response response;
    CHECK(sucrune_broker_exchange(c.socket, &r, &response, right, 1000) == 0);
    return response.result;
}

static void guest_volume_and_counters(const char *workspace) {
    struct client c={0};
    c.socket=sucrune_workspace_broker_profile(workspace,&c.done,0,0,SUCRUNE_WORKSPACE_LINUX);
    CHECK(c.socket>=0);
    struct sucrune_request q=request(43); q.args[0]=AT_FDCWD; append_path(&q,"/");
    struct sucrune_response a=exchange(c,&q);
    struct statfs v,actual;
    CHECK(a.result==0 && a.size==sizeof(v)); memcpy(&v,a.data,sizeof(v));
    CHECK(statfs(workspace,&actual)==0 && actual.f_blocks==v.f_blocks && actual.f_bsize==v.f_bsize);
    CHECK(v.f_blocks>0 && v.f_bavail<=v.f_blocks);
    int64_t fd=path_operation(c,56,"/",O_DIRECTORY|O_RDONLY);
    CHECK(fd>=3 && file_operation(c,44,fd,0,0).size==sizeof(v));
    CHECK(file_operation(c,44,-1,0,0).result==-EBADF);
    CHECK(path_operation(c,43,"missing-statfs-probe",0)==-ENOENT);
    CHECK(file_operation(c,57,fd,0,0).result==0);
    q=request(SUCRUNE_BROKER_PROC_CONTENTS); q.args[0]=SUCRUNE_SYS_MOUNTS;
    a=exchange(c,&q);
    CHECK(a.result==0 && a.size<sizeof(a.data)); a.data[a.size]=0;
    CHECK(strstr((char *)a.data,"sucrune / sucrunefs") && !strstr((char *)a.data,workspace));
    q.args[0]=SUCRUNE_SYS_MEMINFO; a=exchange(c,&q);
    CHECK(a.result==0 && a.size>=9 && !memcmp(a.data,"MemTotal:",9));
    q.args[0]=SUCRUNE_SYS_UPTIME; a=exchange(c,&q);
    CHECK(a.result==0 && a.size>3 && a.size<sizeof(a.data)); a.data[a.size]=0;
    double uptime,idle; CHECK(sscanf((char *)a.data,"%lf %lf",&uptime,&idle)==2 && uptime>=0 && idle>=0);
    q.args[0]=999; CHECK(exchange(c,&q).result==-EINVAL);
    disconnect_broker(&c);
    puts("PASS guest mount table, disk capacity, memory and uptime counters");
}

static void optional_read_right(const char *workspace) {
    struct client c;
    c.socket = sucrune_workspace_broker_profile(workspace, &c.done, 0, 0, SUCRUNE_WORKSPACE_LINUX);
    CHECK(c.socket >= 0);
    int64_t writer = path_operation(c, 56U, "read-right", O_CREAT | O_EXCL | O_WRONLY);
    CHECK(writer >= 0 && write_file(c, writer, "abcdef") == 6);
    int right;
    int64_t handle = open_read(c, "read-right", O_RDONLY, &right);
    CHECK(handle >= 3 && right >= 0 && (fcntl(right,F_GETFD) & FD_CLOEXEC));
    CHECK((fcntl(right,F_GETFL) & (O_ACCMODE | O_PATH)) == O_RDONLY);
    CHECK(path_operation(c,35U,"read-right",0) == 0);
    char bytes[4] = {0};
    CHECK(read(right,bytes,2) == 2 && memcmp(bytes,"ab",2) == 0);
    struct sucrune_response result = file_operation(c,63U,handle,2,0);
    CHECK(result.result == 2 && result.size == 2U && memcmp(result.data,"cd",2) == 0);
    CHECK(pread(right,bytes,2,1) == 2 && memcmp(bytes,"bc",2) == 0);
    CHECK(close(right) == 0);
    result = file_operation(c,63U,handle,2,0);
    CHECK(result.result == 2 && memcmp(result.data,"ef",2) == 0);

    CHECK(open_read(c,".",O_RDONLY | O_DIRECTORY,&right) >= 3 && right == -1);
    CHECK(open_read(c,"absent",O_RDONLY,&right) == -ENOENT && right == -1);
    CHECK(open_read(c,"../outside/sentinel",O_RDONLY,&right) == -EPERM && right == -1);
    CHECK(open_read(c,"uncreated",O_RDWR | O_CREAT,&right) == -EINVAL && right == -1);
    CHECK(open_read(c,"uncreated",O_WRONLY | O_CREAT,&right) == -EINVAL && right == -1);
    CHECK(open_read(c,".",O_PATH,&right) == -EINVAL && right == -1);
    CHECK(open_read(c,"uncreated",O_RDONLY,&right) == -ENOENT && right == -1);
    disconnect_broker(&c);

    c = connect_broker(workspace);
    CHECK(open_read(c,"read-right",O_RDONLY | O_CREAT,&right) >= 3 && right == -1);
    CHECK(path_operation(c,35U,"read-right",0) == 0);
    disconnect_broker(&c);
}

static void shared_mapping_right(const char *workspace) {
    struct client client = connect_broker(workspace);
    int64_t writer = path_operation(client, 56U, "map-data", O_CREAT | O_RDWR);
    CHECK(writer >= 0 && write_file(client, writer, "map") == 3);
    struct sucrune_request packet = request(SUCRUNE_BROKER_MAP_FILE);
    struct sucrune_response reply;
    packet.args[0] = writer;
    packet.args[1] = 1;
    int right = -1;
    CHECK(sucrune_broker_exchange(client.socket, &packet, &reply, &right, 1000) == 0);
    CHECK(reply.result == 0 && right >= 0 && (fcntl(right, F_GETFL) & O_ACCMODE) == O_RDWR);
    CHECK(pwrite(right, "M", 1, 0) == 1 && close(right) == 0);
    packet.args[0] = path_operation(client, 56U, "map-data", O_WRONLY);
    CHECK(packet.args[0] >= 0);
    CHECK(sucrune_broker_exchange(client.socket, &packet, &reply, &right, 1000) == 0);
    CHECK(reply.result == -EACCES && right < 0);
    packet.args[0] = path_operation(client, 56U, "map-data", O_RDONLY);
    CHECK(packet.args[0] >= 0 && path_operation(client, 35U, "map-data", 0) == 0);
    CHECK(sucrune_broker_exchange(client.socket, &packet, &reply, &right, 1000) == 0);
    CHECK(reply.result == -EACCES && right < 0);
    packet.args[1] = 0;
    CHECK(sucrune_broker_exchange(client.socket, &packet, &reply, &right, 1000) == 0);
    CHECK(reply.result == 0 && right >= 0 && (fcntl(right, F_GETFL) & O_ACCMODE) == O_RDONLY);
    char contents[3];
    CHECK(pread(right, contents, sizeof(contents), 0) == 3 && memcmp(contents, "Map", 3) == 0);
    CHECK(close(right) == 0);
    disconnect_broker(&client);
}

static void preallocate_regular_file(const char *workspace) {
    struct client client = connect_broker(workspace);
    int64_t writer = path_operation(client, 56U, "extent", O_CREAT | O_RDWR);
    int64_t reader = path_operation(client, 56U, "extent", O_RDONLY);
    CHECK(writer >= 0 && reader >= 0 && write_file(client, writer, "kept") == 4);
    struct sucrune_request packet = request(47U);
    packet.args[0] = writer; packet.args[2] = 4096; packet.args[3] = 4096;
    CHECK(exchange(client, &packet).result == 0);
    CHECK(file_operation(client, 62U, writer, 0, SEEK_CUR).result == 4);
    CHECK(file_operation(client, 62U, reader, 0, SEEK_END).result == 8192);
    CHECK(file_operation(client, 62U, reader, 0, SEEK_SET).result == 0);
    struct sucrune_response content = file_operation(client, 63U, reader, 5, 0);
    CHECK(content.result == 5 && content.size == 5U && memcmp(content.data, "kept\0", 5U) == 0);
    packet.args[3] = 0; CHECK(exchange(client, &packet).result == -EINVAL);
    packet.args[3] = INT64_MAX; CHECK(exchange(client, &packet).result == -EFBIG);
    packet.args[2] = -1; packet.args[3] = 4096; CHECK(exchange(client, &packet).result == -EINVAL);
    packet.args[2] = 0; packet.args[1] = 1; CHECK(exchange(client, &packet).result == -EOPNOTSUPP);
    packet.args[0] = reader; packet.args[1] = 0; CHECK(exchange(client, &packet).result == -EBADF);
    packet.args[0] = 999; CHECK(exchange(client, &packet).result == -EBADF);
    CHECK(path_operation(client, 35U, "extent", 0) == 0);
    disconnect_broker(&client);
}

static void path_boundaries(const char *workspace, const char *outside) {
    char link[2048];
    joined_path(link, sizeof(link), workspace, "link");
    CHECK(symlink(outside, link) == 0);
    struct client client = connect_broker(workspace);
    check_cwd(client, "/");
    CHECK(path_operation(client, 56U, "../sentinel", O_RDONLY) == -EPERM);
    CHECK(path_operation(client, 56U, "/../sentinel", O_RDONLY) == -EPERM);
    CHECK(path_operation(client, 56U, "a\\b", O_CREAT | O_WRONLY) == -EINVAL);
    CHECK(path_operation(client, 56U, "link/sentinel", O_RDONLY) < 0);
    CHECK(path_operation(client, 56U, "link", O_RDONLY) < 0);
    CHECK(path_operation(client, 49U, "link", 0) < 0);
    CHECK(path_operation(client, 34U, "link/new", 0) < 0);
    CHECK(rename_path(client, "/../sentinel", "renamed") == -EPERM);
    CHECK(path_operation(client, 35U, "/", AT_REMOVEDIR) < 0);
    CHECK(rename_path(client, "/", "renamed") < 0);
    CHECK(path_operation(client, 56U, "/missing/file", O_CREAT | O_WRONLY) == -ENOENT);
    char long_path[SUCRUNE_PATH_LIMIT + 1U];
    memset(long_path, 'x', sizeof(long_path) - 1U);
    long_path[sizeof(long_path) - 1U] = '\0';
    CHECK(path_operation(client, 56U, long_path, O_RDONLY) == -ENAMETOOLONG);
    struct sucrune_request packet = request(56U);
    packet.args[0] = AT_FDCWD; packet.args[1] = O_RDONLY;
    packet.size = 3U; memcpy(packet.data, "abc", 3U);
    CHECK(exchange(client, &packet).result == -ENAMETOOLONG);
    disconnect_broker(&client);
    CHECK(unlink(link) == 0);
}

static struct sucrune_response query(struct client client, uint32_t operation,
        int64_t directory, const char *path, int64_t value, int64_t flags) {
    struct sucrune_request packet = request(operation);
    packet.args[0] = directory; packet.args[1] = value; packet.args[2] = flags;
    append_path(&packet, path);
    return exchange(client, &packet);
}
static int64_t make_symlink(struct client client, int64_t directory, const char *target, const char *name) {
    struct sucrune_request packet = request(36);
    packet.args[0] = directory;
    append_path(&packet, target);
    append_path(&packet, name);
    return exchange(client, &packet).result;
}
static void distribution_symlinks(const char *workspace) {
    struct client client = connect_broker(workspace);
    CHECK(path_operation(client,34,"/usr",0)==0);
    CHECK(path_operation(client,34,"/usr/bin",0)==0);
    CHECK(make_symlink(client,AT_FDCWD,"usr/bin","/bin")==0);
    int64_t bin=path_operation(client,56,"/bin",O_DIRECTORY|O_RDONLY);
    CHECK(bin>=3);
    CHECK(make_symlink(client,bin,"../bin/missing","tool")==0);
    CHECK(make_symlink(client,bin,"/bin/tool","chain")==0);
    CHECK(make_symlink(client,bin,"sucrune:inode:v1:0123456789abcdef0123456789abcdef","spoof")==-EPERM);
    CHECK(path_operation(client,56,"/bin/chain",O_RDONLY)==-ENOENT);
    CHECK(path_operation(client,56,"/bin/chain",O_CREAT|O_EXCL|O_WRONLY)==-EEXIST);
    int64_t writer=path_operation(client,56,"/bin/chain",O_CREAT|O_WRONLY);
    CHECK(writer>=3 && write_file(client,writer,"payload")==7 && file_operation(client,57,writer,0,0).result==0);
    struct sucrune_response reply=query(client,79,AT_FDCWD,"/bin/tool",AT_SYMLINK_NOFOLLOW,0);
    struct sucrune_arm64_stat st;
    CHECK(reply.size==sizeof(st));memcpy(&st,reply.data,sizeof(st));
    CHECK(S_ISLNK(st.mode) && st.size==14);
    reply=query(client,79,AT_FDCWD,"/bin/tool",0,0);CHECK(reply.size==sizeof(st));
    memcpy(&st,reply.data,sizeof(st));CHECK(S_ISREG(st.mode) && st.size==7);
    CHECK(query(client,56,bin,"tool",O_RDONLY|O_NOFOLLOW,0).result==-ELOOP);
    int64_t symlink=query(client,56,bin,"tool",O_PATH|O_NOFOLLOW,0).result;
    CHECK(symlink>=3);
    reply=query(client,78,symlink,"",4,0);
    CHECK(reply.result==4 && !memcmp(reply.data,"../b",4) && file_operation(client,57,symlink,0,0).result==0);
    CHECK(path_operation(client,49,"/bin/..",0)==0);check_cwd(client,"/usr");
    CHECK(path_operation(client,49,"/bin/",0)==0);check_cwd(client,"/usr/bin");
    CHECK(rename_path(client,"/usr/bin/tool","/bin/replaced")==0);
    CHECK(query(client,79,bin,"chain",0,0).result==-ENOENT);
    CHECK(make_symlink(client,bin,"chain","tool")==0);
    CHECK(query(client,56,bin,"chain",O_RDONLY,0).result==-ELOOP);
    CHECK(path_operation(client,35,"/bin/",AT_REMOVEDIR)==-ENOTDIR);
    CHECK(path_operation(client,35,"/bin",0)==0);
    CHECK(query(client,56,bin,"chain",O_RDONLY,0).result==-ENOENT);
    CHECK(path_operation(client,49,"/",0)==0);
    CHECK(query(client,35,bin,"chain",0,0).result==0);
    CHECK(query(client,35,bin,"tool",0,0).result==0);
    CHECK(query(client,35,bin,"replaced",0,0).result==0);
    CHECK(query(client,35,bin,"missing",0,0).result==0);
    CHECK(file_operation(client,57,bin,0,0).result==0);
    CHECK(path_operation(client,35,"/usr/bin",AT_REMOVEDIR)==0);
    CHECK(path_operation(client,35,"/usr",AT_REMOVEDIR)==0);
    disconnect_broker(&client);
}
static void access_and_readlink_queries(const char *workspace) {
    char link[2048];
    joined_path(link, sizeof(link), workspace, "query-link");
    const char target[] = "../outside/sentinel";
    CHECK(symlink(target, link) == 0);
    struct client client = connect_broker(workspace);
    CHECK(path_operation(client, 34U, "query-dir", 0) == 0);
    int64_t file = path_operation(client, 56U, "query-dir/plain", O_CREAT | O_RDWR | O_EXCL);
    int64_t directory = path_operation(client, 56U, "query-dir", O_RDONLY | O_DIRECTORY);
    CHECK(file >= 3 && directory >= 3);
    CHECK(query(client, 48U, AT_FDCWD, "query-dir/plain", R_OK | W_OK, 0).result == 0);
    CHECK(query(client, 48U, AT_FDCWD, "query-dir/plain", X_OK, 0).result == -EACCES);
    CHECK(query(client, 48U, -999, "/query-dir/plain", F_OK, 0).result == 0);
    CHECK(query(client, 48U, -999, "query-dir/plain", F_OK, 0).result == -EBADF);
    CHECK(query(client, 48U, directory, "plain", R_OK, 0).result == 0);
    CHECK(query(client, 48U, file, "plain", F_OK, 0).result == -ENOTDIR);
    CHECK(query(client, 48U, AT_FDCWD, "query-dir/plain/", F_OK, 0).result == -ENOTDIR);
    CHECK(query(client, 48U, AT_FDCWD, "query-dir/plain/../plain", F_OK, 0).result == -ENOTDIR);
    CHECK(query(client, 48U, AT_FDCWD, "query-dir/missing", F_OK, 0).result == -ENOENT);
    CHECK(query(client, 48U, AT_FDCWD, "../outside/sentinel", F_OK, 0).result == -EPERM);
    CHECK(query(client, 48U, AT_FDCWD, "query-link", F_OK, 0).result == -EPERM);
    CHECK(query(client, 439U, AT_FDCWD, "query-link", F_OK, AT_SYMLINK_NOFOLLOW).result == 0);
    CHECK(query(client, 439U, AT_FDCWD, "query-dir/plain", R_OK, AT_EACCESS | AT_SYMLINK_NOFOLLOW).result == 0);
    CHECK(query(client, 439U, file, "", R_OK | W_OK, AT_EMPTY_PATH | AT_EACCESS).result == 0);
    CHECK(query(client, 439U, AT_FDCWD, "", F_OK, AT_EMPTY_PATH).result == 0);
    CHECK(query(client, 439U, file, "", F_OK, 0).result == -ENOENT);
    CHECK(query(client, 439U, -999, "", F_OK, AT_EMPTY_PATH).result == -EBADF);
    CHECK(query(client, 439U, AT_FDCWD, "query-dir/plain", 8, 0).result == -EINVAL);
    CHECK(query(client, 439U, AT_FDCWD, "query-dir/plain", F_OK, 0x80000000LL).result == -EINVAL);
    CHECK(query(client, 48U, AT_FDCWD, "query-dir/plain", F_OK, AT_EACCESS).result == -EINVAL);
    struct sucrune_response result = query(client, 78U, AT_FDCWD, "query-link", 100, 0);
    CHECK(result.result == (int64_t)(sizeof(target) - 1U) && result.size == sizeof(target) - 1U);
    CHECK(memcmp(result.data, target, sizeof(target) - 1U) == 0);
    result = query(client, 78U, -999, "/query-link", 3, 0);
    CHECK(result.result == 3 && result.size == 3U && memcmp(result.data, "../", 3U) == 0);
    CHECK(query(client, 78U, AT_FDCWD, "query-link", 0, 0).result == -EINVAL);
    CHECK(query(client, 78U, AT_FDCWD, "query-dir/plain", 100, 0).result == -EINVAL);
    CHECK(query(client, 78U, AT_FDCWD, "query-missing", 100, 0).result == -ENOENT);
    CHECK(query(client, 78U, -999, "query-link", 100, 0).result == -EBADF);
    CHECK(query(client, 78U, directory, "plain", 100, 0).result == -EINVAL);
    CHECK(query(client, 78U, file, "", 100, 0).result == -ENOENT);
    CHECK(query(client, 78U, AT_FDCWD, "query-link/sentinel", 100, 0).result < 0);
    CHECK(rename_path(client, "query-dir", "query-renamed") == 0);
    CHECK(query(client, 48U, directory, "plain", R_OK, 0).result == 0);
    CHECK(query(client, 48U, directory, "../../outside/sentinel", F_OK, 0).result == -EPERM);
    CHECK(file_operation(client, 57U, file, 0, 0).result == 0);
    CHECK(query(client, 439U, file, "", F_OK, AT_EMPTY_PATH).result == -EBADF);
    CHECK(file_operation(client, 57U, directory, 0, 0).result == 0);
    CHECK(path_operation(client, 35U, "query-renamed/plain", 0) == 0);
    CHECK(path_operation(client, 35U, "query-renamed", AT_REMOVEDIR) == 0);
    disconnect_broker(&client);
    CHECK(unlink(link) == 0);
}

/* Walk the actual getdents64 reply, open each child directory relative to its
 * parent, and unlink children bottom-up. A caller keeps just the name and the
 * parent handle at each level, as in a recursive filesystem removal. */
static unsigned int remove_directory_contents(struct client client,int64_t parent,unsigned int depth) {
    CHECK(depth<=3U);
    unsigned int removed=0;
    const int flags=O_RDONLY|O_DIRECTORY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC;
    for(;;) {
        struct sucrune_response batch=file_operation(client,61U,parent,SUCRUNE_IO_LIMIT,0);
        CHECK(batch.result>=0 && (uint64_t)batch.result==batch.size);
        if(batch.size==0U) return removed;
        for(size_t offset=0;offset<batch.size;) {
            const unsigned char *entry=batch.data+offset;
            uint16_t length;
            CHECK(batch.size-offset>=20U);
            memcpy(&length,entry+16,sizeof(length));
            CHECK(length>=20U && length<=batch.size-offset && memchr(entry+19,0,length-19U)!=NULL);
            const char *name=(const char *)entry+19;
            offset+=length;
            if(strcmp(name,".")==0 || strcmp(name,"..")==0) continue;
            struct sucrune_response reply=query(client,79U,parent,name,AT_SYMLINK_NOFOLLOW,0);
            struct sucrune_arm64_stat st;
            CHECK(reply.result==0 && reply.size==sizeof(st));
            memcpy(&st,reply.data,sizeof(st));
            int64_t child=query(client,56U,parent,name,flags,0).result;
            if(S_ISDIR(st.mode)) {
                CHECK(child>=3);
                removed+=remove_directory_contents(client,child,depth+1U);
                CHECK(file_operation(client,57U,child,0,0).result==0);
                CHECK(query(client,35U,parent,name,AT_REMOVEDIR,0).result==0);
            } else {
                CHECK(S_ISREG(st.mode) && child==-ENOTDIR);
                CHECK(query(client,35U,parent,name,0,0).result==0);
            }
            removed++;
        }
    }
}

static void relative_directory_operations(const char *workspace,const char *outside) {
    struct client client=connect_broker(workspace);
    const int directory_flags=O_RDONLY|O_NONBLOCK|O_NOCTTY|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC;
    CHECK(path_operation(client,34U,"at-tree",0)==0);
    CHECK(path_operation(client,34U,"at-tree/branch",0)==0);
    CHECK(path_operation(client,34U,"at-tree/branch/deep",0)==0);
    int64_t rootfd=path_operation(client,56U,"at-tree",directory_flags);
    CHECK(rootfd>=3);
    int64_t branch=query(client,56U,rootfd,"branch",directory_flags,0).result;
    CHECK(branch>=3);
    int64_t file=query(client,56U,branch,"deep/item",O_CREAT|O_EXCL|O_RDWR,0600).result;
    CHECK(file>=3 && write_file(client,file,"original")==8);
    struct sucrune_response opened=file_operation(client,80U,file,0,0);
    struct sucrune_arm64_stat original,relative;
    CHECK(opened.result==0 && opened.size==sizeof(original));
    memcpy(&original,opened.data,sizeof(original));
    CHECK(rename_path(client,"at-tree","at-moved")==0);
    CHECK(path_operation(client,34U,"at-tree",0)==0);
    int64_t shadow=path_operation(client,56U,"at-tree/shadow",O_CREAT|O_WRONLY|O_EXCL);
    CHECK(shadow>=3 && write_file(client,shadow,"keep")==4);
    CHECK(file_operation(client,57U,shadow,0,0).result==0);
    struct sucrune_response lookup=query(client,79U,rootfd,"branch/deep/item",0,0);
    CHECK(lookup.result==0 && lookup.size==sizeof(relative));
    memcpy(&relative,lookup.data,sizeof(relative));
    CHECK(relative.device==original.device && relative.inode==original.inode && relative.size==8);
    CHECK(query(client,79U,rootfd,"shadow",0,0).result==-ENOENT);
    CHECK(query(client,79U,branch,"deep/item/",0,0).result==-ENOTDIR);
    CHECK(query(client,56U,branch,"deep/item/../item",O_RDONLY,0).result==-ENOTDIR);
    CHECK(query(client,35U,rootfd,"..",AT_REMOVEDIR,0).result==-EPERM);
    CHECK(file_operation(client,50U,rootfd,0,0).result==0);
    check_cwd(client,"/at-moved");
    CHECK(file_operation(client,50U,file,0,0).result==-ENOTDIR);
    CHECK(file_operation(client,50U,-100,0,0).result==-EBADF);
    check_cwd(client,"/at-moved");
    CHECK(path_operation(client,49U,"/at-moved/branch/deep",0)==0);
    CHECK(query(client,35U,branch,"deep",AT_REMOVEDIR,0).result==-EBUSY);
    check_cwd(client,"/at-moved/branch/deep");
    CHECK(path_operation(client,49U,"/",0)==0);
    CHECK(query(client,35U,rootfd,"branch",AT_REMOVEDIR,0).result==-ENOTEMPTY);
    CHECK(query(client,35U,branch,"deep/item",AT_REMOVEDIR,0).result==-ENOTDIR);
    CHECK(query(client,35U,branch,"deep/item",AT_SYMLINK_NOFOLLOW,0).result==-EINVAL);
    const uint32_t operations[]={56U,79U,35U};
    for(unsigned int i=0;i<sizeof(operations)/sizeof(operations[0]);i++) {
        CHECK(query(client,operations[i],-955,"name",0,0).result==-EBADF);
        CHECK(query(client,operations[i],file,"name",0,0).result==-ENOTDIR);
        CHECK(query(client,operations[i],rootfd,"../../outside/sentinel",0,0).result==-EPERM);
    }
    char link[2048];
    joined_path(link,sizeof(link),workspace,"at-moved/external");
    CHECK(symlink(outside,link)==0);
    CHECK(query(client,56U,rootfd,"external/sentinel",O_WRONLY|O_TRUNC,0).result<0);
    CHECK(query(client,79U,rootfd,"external/sentinel",0,0).result<0);
    CHECK(query(client,35U,rootfd,"external/sentinel",0,0).result<0);
    CHECK(query(client,35U,rootfd,"external",0,0).result==0);
    CHECK(file_operation(client,57U,branch,0,0).result==0);
    CHECK(query(client,79U,branch,"deep",0,0).result==-EBADF);
    int64_t extra=query(client,56U,rootfd,"leaf",O_CREAT|O_WRONLY|O_EXCL,0600).result;
    CHECK(extra>=3 && file_operation(client,57U,extra,0,0).result==0);
    CHECK(remove_directory_contents(client,rootfd,0)==4U);
    /* Removal leaves the already-open file intact. The replacement at the old
     * path is untouched. Absolute calls ignore even an invalid directory FD. */
    CHECK(file_operation(client,62U,file,0,SEEK_SET).result==0);
    lookup=file_operation(client,63U,file,8,0);
    CHECK(lookup.result==8 && lookup.size==8U && memcmp(lookup.data,"original",8)==0);
    CHECK(file_operation(client,57U,file,0,0).result==0);
    CHECK(file_operation(client,57U,rootfd,0,0).result==0);
    CHECK(query(client,35U,-955,"/at-moved",AT_REMOVEDIR,0).result==0);
    shadow=query(client,56U,-955,"/at-tree/shadow",O_RDONLY,0).result;
    CHECK(shadow>=3);
    lookup=file_operation(client,63U,shadow,4,0);
    CHECK(lookup.result==4 && lookup.size==4U && memcmp(lookup.data,"keep",4)==0);
    CHECK(file_operation(client,57U,shadow,0,0).result==0);
    CHECK(query(client,79U,-955,"/at-tree/shadow",0,0).result==0);
    CHECK(query(client,35U,-955,"/at-tree/shadow",0,0).result==0);
    CHECK(path_operation(client,35U,"at-tree",AT_REMOVEDIR)==0);
    disconnect_broker(&client);
}

static int64_t link_paths(struct client client,int64_t srcdir,const char *src,int64_t dstdir,const char *dst,int64_t flags) {
    struct sucrune_request req=request(SUCRUNE_BROKER_LINKAT);
    req.args[0]=srcdir;req.args[1]=dstdir;req.args[2]=flags;
    append_path(&req,src);append_path(&req,dst);
    struct sucrune_response response=exchange(client,&req);
    CHECK(response.size==0U);
    return response.result;
}
static void hard_link_publication(const char *workspace,const char *outside) {
    char external[2048],sentinel[2048];
    joined_path(external,sizeof(external),workspace,"link-outside");
    joined_path(sentinel,sizeof(sentinel),outside,"sentinel");
    struct stat before,after;
    CHECK(stat(sentinel,&before)==0 && symlink(outside,external)==0);
    struct client client=connect_broker(workspace);
    CHECK(path_operation(client,34U,"h-old",0)==0 && path_operation(client,34U,"h-new",0)==0);
    int64_t old=path_operation(client,56U,"h-old",O_RDONLY|O_DIRECTORY);
    int64_t dst=path_operation(client,56U,"h-new",O_RDONLY|O_DIRECTORY);
    int64_t file=path_operation(client,56U,"h-old/tmp",O_CREAT|O_RDWR|O_EXCL);
    CHECK(old>=3 && dst>=3 && file>=3 && write_file(client,file,"history")==7);
    CHECK(rename_path(client,"h-old","h-moved")==0);
    CHECK(link_paths(client,old,"tmp",dst,"final",0)==0);
    CHECK(link_paths(client,old,"tmp",dst,"final",0)==-EEXIST);
    CHECK(link_paths(client,-987,"/h-moved/tmp",-654,"/h-new/second",AT_SYMLINK_FOLLOW)==0);
    int64_t alias=query(client,56U,dst,"final",O_RDONLY,0).result;
    struct sucrune_response a=file_operation(client,80U,file,0,0),b=file_operation(client,80U,alias,0,0);
    struct sucrune_arm64_stat sa,sb;
    CHECK(alias>=3 && a.result==0 && b.result==0 && a.size==sizeof(sa) && b.size==sizeof(sb));
    memcpy(&sa,a.data,sizeof(sa));memcpy(&sb,b.data,sizeof(sb));
    CHECK(sa.device==sb.device && sa.inode==sb.inode && sa.nlink==3U && sb.nlink==3U);
    char alias_path[2048];
    joined_path(alias_path,sizeof(alias_path),workspace,"h-new/final");
    struct stat physical;
    CHECK(lstat(alias_path,&physical)==0);
    if(S_ISLNK(physical.st_mode)) {
        /* Simulate a manager interruption after the entry became durable but
         * before its private counter was committed. Fresh startup must count
         * the three actual names without following the external symlink. */
        char store_path[4096],id[33],refs[4096],dirty[4096],suffix[40];
        CHECK(snprintf(store_path,sizeof(store_path),"%s.sucrune-inodes-v1",workspace)>0);
        CHECK(snprintf(id,sizeof(id),"%016" PRIx64 "%016" PRIx64,sa.device,sa.inode)==32);
        CHECK(snprintf(suffix,sizeof(suffix),"%s.refs",id)==37);
        joined_path(refs,sizeof(refs),store_path,suffix);
        CHECK(chmod(refs,0644)==0 && file_operation(client,80U,alias,0,0).result==-EUCLEAN);
        CHECK(chmod(refs,0600)==0);
        CHECK(snprintf(suffix,sizeof(suffix),"%s.dirty",id)==38);
        joined_path(dirty,sizeof(dirty),store_path,suffix);
        int flag=open(dirty,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);CHECK(flag>=0 && close(flag)==0);
        flag=open(refs,O_WRONLY|O_TRUNC|O_CLOEXEC);
        unsigned char stale_count[]={1,0,0,0};
        CHECK(flag>=0 && write(flag,stale_count,sizeof(stale_count))==4 && close(flag)==0);
        CHECK(file_operation(client,80U,file,0,0).result==-EUCLEAN);
    }
    /* A freshly initialized manager reopens an alias created by its peer.
     * Both observe the original data and actual open file description locks. */
    struct client fresh=connect_broker(workspace);
    int64_t fresh_alias=path_operation(fresh,56U,"h-new/final",O_RDWR);
    CHECK(fresh_alias>=3);
    b=file_operation(fresh,80U,fresh_alias,0,0);CHECK(b.result==0 && b.size==sizeof(sb));
    memcpy(&sb,b.data,sizeof(sb));CHECK(sb.nlink==3U && sb.inode==sa.inode && sb.device==sa.device);
    CHECK(file_operation(client,46U,file,-1,0).result==-EINVAL);
    CHECK(file_operation(client,46U,file,1,1).result==-EINVAL);
    CHECK(file_operation(client,46U,old,0,0).result==-EINVAL);
    int64_t denied=file_operation(client,46U,alias,0,0).result;
    CHECK(denied==-EBADF || denied==-EINVAL);
    CHECK(file_operation(client,46U,-987,0,0).result==-EBADF);
    CHECK(file_operation(client,46U,file,2,0).result==0);
    CHECK(file_operation(client,62U,file,0,SEEK_CUR).result==7);
    b=file_operation(fresh,SUCRUNE_BROKER_PREAD64,fresh_alias,7,0);
    CHECK(b.result==2 && b.size==2U && memcmp(b.data,"hi",2)==0);
    CHECK(file_operation(client,46U,file,9,0).result==0);
    const unsigned char extended[9]={'h','i',0,0,0,0,0,0,0};
    b=file_operation(client,SUCRUNE_BROKER_PREAD64,alias,9,0);
    CHECK(b.result==9 && b.size==9U && memcmp(b.data,extended,sizeof(extended))==0);
    const int64_t limit=INT64_C(256)*1024*1024;
    CHECK(file_operation(client,46U,file,limit+1,0).result==-EFBIG);
    CHECK(file_operation(client,46U,file,INT64_MAX,0).result==-EFBIG);
    b=file_operation(client,80U,alias,0,0);
    CHECK(b.result==0 && b.size==sizeof(sb));
    memcpy(&sb,b.data,sizeof(sb));
    CHECK(sb.size==9 && sb.inode==sa.inode && sb.nlink==3U);
    CHECK(file_operation(client,46U,file,limit,0).result==0);
    b=file_operation(client,80U,alias,0,0);
    CHECK(b.result==0 && b.size==sizeof(sb));
    memcpy(&sb,b.data,sizeof(sb));
    CHECK(sb.size==limit && sb.blocks>=0 && sb.blocks<limit/512);
    b=file_operation(client,SUCRUNE_BROKER_PREAD64,alias,1,limit-1);
    CHECK(b.result==1 && b.size==1 && b.data[0]==0);
    CHECK(file_operation(client,46U,file,0,0).result==0);
    CHECK(write_file(client,file,"")==0 && file_operation(client,62U,file,0,SEEK_CUR).result==7);
    b=file_operation(fresh,SUCRUNE_BROKER_PREAD64,fresh_alias,1,0);
    CHECK(b.result==0 && b.size==0);
    CHECK(file_operation(client,62U,file,0,SEEK_SET).result==0 && write_file(client,file,"history")==7);
    CHECK(file_operation(client,SUCRUNE_BROKER_FLOCK,file,LOCK_EX|LOCK_NB,0).result==0);
    CHECK(file_operation(fresh,SUCRUNE_BROKER_FLOCK,fresh_alias,LOCK_EX|LOCK_NB,0).result==-EWOULDBLOCK);
    CHECK(file_operation(client,SUCRUNE_BROKER_FLOCK,file,LOCK_UN,0).result==0);
    CHECK(file_operation(fresh,SUCRUNE_BROKER_FLOCK,fresh_alias,LOCK_EX|LOCK_NB,0).result==0);
    disconnect_broker(&fresh);
    CHECK(link_paths(client,file,"tmp",dst,"bad",0)==-ENOTDIR);
    CHECK(link_paths(client,old,"tmp",file,"bad",0)==-ENOTDIR);
    CHECK(link_paths(client,-999,"tmp",dst,"bad",0)==-EBADF);
    CHECK(link_paths(client,old,"tmp",-999,"bad",0)==-EBADF);
    CHECK(link_paths(client,-999,"",dst,"bad",AT_EMPTY_PATH)==-EBADF);
    CHECK(link_paths(client,file,"",dst,"bad",0)==-ENOENT);
    CHECK(link_paths(client,old,"tmp",dst,"",0)==-ENOENT);
    CHECK(link_paths(client,old,"missing",dst,"bad",0)==-ENOENT);
    CHECK(link_paths(client,old,"tmp",dst,"bad",AT_SYMLINK_NOFOLLOW)==-EINVAL);
    CHECK(link_paths(client,old,".",dst,"bad",0)==-EPERM);
    CHECK(link_paths(client,old,"../../outside/sentinel",dst,"bad",0)==-EPERM);
    CHECK(link_paths(client,old,"tmp",dst,"../../outside/bad",0)==-EPERM);
    int64_t linked_symlink = link_paths(client,AT_FDCWD,"link-outside",dst,"bad",0);
    if (linked_symlink == 0) {
        CHECK(query(client,78U,dst,"bad",128,0).result == (int64_t)strlen(outside));
        CHECK(query(client,35U,dst,"bad",0,0).result == 0);
    } else CHECK(linked_symlink == -EPERM || linked_symlink == -EACCES || linked_symlink == -EOPNOTSUPP);
    CHECK(link_paths(client,AT_FDCWD,"link-outside",dst,"bad",AT_SYMLINK_FOLLOW)==-ENOENT);
    CHECK(link_paths(client,AT_FDCWD,"link-outside/sentinel",dst,"bad",0)<0);
    CHECK(link_paths(client,old,"tmp",AT_FDCWD,"link-outside/bad",0)<0);
    CHECK(link_paths(client,old,"tmp",AT_FDCWD,"link-outside",0)==-EEXIST);
    CHECK(query(client,35U,old,"tmp",0,0).result==0);
    b=query(client,79U,dst,"final",AT_SYMLINK_NOFOLLOW,0);
    CHECK(b.result==0 && b.size==sizeof(sb));
    memcpy(&sb,b.data,sizeof(sb));
    CHECK(S_ISREG(sb.mode) && sb.inode==sa.inode && sb.device==sa.device && sb.nlink==2U);
    b=file_operation(client,63U,alias,7,0);
    CHECK(b.result==7 && b.size==7U && memcmp(b.data,"history",7)==0);
    CHECK(file_operation(client,57U,alias,0,0).result==0);
    CHECK(path_operation(client,35U,"h-new/final",0)==0 && path_operation(client,35U,"h-new/second",0)==0);
    CHECK(stat(sentinel,&after)==0 && before.st_dev==after.st_dev && before.st_ino==after.st_ino && before.st_nlink==after.st_nlink);
    CHECK(path_operation(client,35U,"h-new",AT_REMOVEDIR)==0 && path_operation(client,35U,"h-moved",AT_REMOVEDIR)==0);
    disconnect_broker(&client);
    CHECK(unlink(external)==0);
}
static void files_and_descriptors(const char *workspace) {
    struct client client = connect_broker(workspace);
    int64_t fd = path_operation(client, 56U, "/data", O_CREAT | O_RDWR | O_EXCL);
    CHECK(fd >= 3 && fd < 67);
    CHECK(write_file(client, fd, "abcdef") == 6);
    CHECK(file_operation(client, 62U, fd, 3, SEEK_SET).result == 3);
    struct sucrune_response response = file_operation(client, 63U, fd, 100, 0);
    CHECK(response.result == 3 && response.size == 3U && memcmp(response.data, "def", 3U) == 0);
    CHECK(file_operation(client, 63U, fd, 100, 0).result == 0);
    CHECK(file_operation(client, 63U, fd, SUCRUNE_IO_LIMIT + 1U, 0).result == -EINVAL);
    struct sucrune_request malformed_write = request(64U);
    malformed_write.args[0] = fd; malformed_write.args[1] = 3;
    malformed_write.size = 2U; memcpy(malformed_write.data, "xx", 2U);
    CHECK(exchange(client, &malformed_write).result == -EINVAL);
    CHECK(file_operation(client, 57U, fd, 0, 0).result == 0);
    CHECK(file_operation(client, 57U, fd, 0, 0).result == -EBADF);
    CHECK(file_operation(client, 63U, fd, 1, 0).result == -EBADF);
    CHECK(file_operation(client, 63U, -1, 1, 0).result == -EBADF);
    CHECK(file_operation(client, 63U, 2, 1, 0).result == -EBADF);
    CHECK(file_operation(client, 63U, 67, 1, 0).result == -EBADF);
    fd = path_operation(client, 56U, "data", O_WRONLY | O_APPEND);
    CHECK(fd >= 3 && write_file(client, fd, "gh") == 2);
    CHECK(file_operation(client, 57U, fd, 0, 0).result == 0);
    fd = path_operation(client, 56U, "data", O_RDONLY);
    CHECK(fd >= 3);
    response = file_operation(client, 63U, fd, 100, 0);
    CHECK(response.result == 8 && response.size == 8U && memcmp(response.data, "abcdefgh", 8U) == 0);
    CHECK(file_operation(client, 57U, fd, 0, 0).result == 0);
    fd = path_operation(client, 56U, "/", O_RDONLY | O_DIRECTORY);
    CHECK(fd >= 3);
    response = file_operation(client, 61U, fd, SUCRUNE_IO_LIMIT, 0);
    CHECK(response.result > 0 && response.result == response.size);
    CHECK(file_operation(client, 57U, fd, 0, 0).result == 0);
    int64_t slots[SUCRUNE_DEFAULT_FILE_RESOURCES];
    for (size_t i = 0U; i < SUCRUNE_DEFAULT_FILE_RESOURCES; i++) {
        slots[i] = path_operation(client, 56U, "data", O_RDONLY);
        CHECK(slots[i] == (int64_t)i + 3);
    }
    CHECK(path_operation(client, 56U, "data", O_RDONLY) == -EMFILE);
    for (size_t i = 0U; i < SUCRUNE_DEFAULT_FILE_RESOURCES; i++)
        CHECK(file_operation(client, 57U, slots[i], 0, 0).result == 0);
    CHECK(path_operation(client, 35U, "data", 0) == 0);
    disconnect_broker(&client);
}

static struct sucrune_response record_region(struct client c,int64_t fd,int cmd,int pid,
                                             short type,short whence,int64_t offset,int64_t length) {
    struct sucrune_request req=request(SUCRUNE_BROKER_RECORD_LOCK);
    struct sucrune_record_lock range={.type=type,.whence=whence,.start=offset,.length=length};
    req.args[0]=fd;req.args[1]=cmd;req.args[2]=pid;req.size=sizeof(range);
    memcpy(req.data,&range,sizeof(range));return exchange(c,&req);
}
static void record_lock_ownership(const char *workspace) {
    struct client a=connect_broker(workspace), b=connect_broker(workspace);
    int64_t first=path_operation(a,56,"records",O_CREAT|O_RDWR|O_TRUNC);
    int64_t other=path_operation(a,56,"records",O_RDWR);
    int64_t peer=path_operation(b,56,"records",O_RDWR);
    CHECK(first>=3 && other>=3 && peer>=3);
    CHECK(write_file(a,first,"abcdefghijkl")==12);
    CHECK(record_region(a,first,F_SETLK,101,F_WRLCK,SEEK_CUR,-12,8).result==0);
    struct sucrune_response reply=record_region(b,peer,F_GETLK,102,F_RDLCK,SEEK_SET,1,1);
    struct sucrune_record_lock found;
    CHECK(reply.result==0 && reply.size==sizeof(found)); memcpy(&found,reply.data,sizeof(found));
    CHECK(found.type==F_WRLCK && found.pid==101 && found.start==0 && found.length==8);
    CHECK(record_region(a,other,F_SETLK,101,F_RDLCK,SEEK_SET,2,2).result==0);
    CHECK(record_region(b,peer,F_SETLK,102,F_RDLCK,SEEK_SET,2,2).result==0);
    CHECK(record_region(b,peer,F_SETLK,102,F_WRLCK,SEEK_END,-6,1).result==-EAGAIN);
    CHECK(file_operation(a,SUCRUNE_BROKER_RECORD_CLOSE,other,0,0).result==0);
    CHECK(record_region(b,peer,F_SETLK,102,F_WRLCK,SEEK_SET,0,0).result==0);
    CHECK(record_region(a,first,F_SETLK,101,F_WRLCK,SEEK_SET,0,0).result==-EAGAIN);
    struct sucrune_request inherit=request(SUCRUNE_BROKER_FORK_SESSION);
    int child=-1;
    CHECK(sucrune_broker_exchange(b.socket,&inherit,&reply,&child,2000)==0 && reply.result==0 && child>=0);
    CHECK(record_region((struct client){.socket=child,.done=-1},peer,F_SETLK,103,F_WRLCK,SEEK_SET,0,0).result==-EAGAIN);
    CHECK(close(child)==0);
    struct sucrune_request commit=request(SUCRUNE_BROKER_EXEC_COMMIT);
    CHECK(exchange(b,&commit).result==0);
    CHECK(record_region(a,first,F_SETLK,101,F_WRLCK,SEEK_SET,0,0).result==-EAGAIN);
    struct sucrune_request mixed=request(25);
    mixed.args[0]=peer;mixed.args[1]=F_SETFD;mixed.args[3]=1;
    CHECK(exchange(b,&mixed).result==0 && exchange(b,&commit).result==0);
    CHECK(record_region(a,first,F_SETLK,101,F_WRLCK,SEEK_SET,1,-1).result==0);
    CHECK(record_region(a,first,F_SETLK,101,F_RDLCK,SEEK_SET,0,-1).result==-EINVAL);
    int64_t ro=path_operation(a,56,"records",O_RDONLY);
    CHECK(ro>=3 && record_region(a,ro,F_SETLK,101,F_WRLCK,SEEK_SET,0,0).result==-EBADF);
    CHECK(file_operation(a,SUCRUNE_BROKER_PRIVATE_CLOSE,ro,0,0).result==0);
    CHECK(record_region(b,peer,F_SETLK,102,F_WRLCK,SEEK_SET,0,0).result==-EAGAIN);
    char path[2048];joined_path(path,sizeof(path),workspace,"records");
    int host=open(path,O_RDWR|O_CLOEXEC);CHECK(host>=0);
    struct flock fl={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_len=1};
    CHECK(fcntl(host,F_SETLK,&fl)<0 && (errno==EAGAIN || errno==EACCES));
    disconnect_broker(&a);
    CHECK(fcntl(host,F_SETLK,&fl)==0);
    reply=record_region(b,peer,F_GETLK,102,F_RDLCK,SEEK_SET,0,1);
    CHECK(reply.result==0 && reply.size==sizeof(found)); memcpy(&found,reply.data,sizeof(found));
    CHECK(found.type==F_WRLCK && found.pid==getpid());
    CHECK(close(host)==0);
    CHECK(record_region(b,peer,F_SETLK,102,F_WRLCK,SEEK_SET,0,0).result==0);
    disconnect_broker(&b);CHECK(unlink(path)==0);
    puts("PASS record locks: inode owners, overlapping regions, fork, exec, aliases, kernel conflicts and cleanup");
}

static void linux_file_capacity(const char *workspace, enum sucrune_workspace_profile profile) {
    struct client client = {.socket=-1, .done=-1};
    client.socket = sucrune_workspace_broker_profile(workspace, &client.done, 0, 0, profile);
    CHECK(client.socket >= 0 && client.done >= 0);
    for (unsigned int i=0; i<SUCRUNE_FILE_RESOURCES; ++i)
        CHECK(path_operation(client, 56U, "/", O_RDONLY | O_DIRECTORY) == (int64_t)(SUCRUNE_BROKER_HANDLE_BASE+i));
    CHECK(path_operation(client, 56U, "overflow", O_CREAT | O_WRONLY) == -EMFILE);
    CHECK(file_operation(client, 57U, SUCRUNE_BROKER_HANDLE_BASE, 0, 0).result == 0);
    CHECK(path_operation(client, 56U, "overflow", O_RDONLY) == -ENOENT);
    disconnect_broker(&client);
}

static void append_status_flags(const char *workspace) {
    struct client client = connect_broker(workspace);
    int64_t fd = path_operation(client, 56U, "/append-state", O_CREAT | O_RDWR | O_EXCL);
    CHECK(fd >= 3 && write_file(client, fd, "abc") == 3);
    int64_t original = file_operation(client, 25U, fd, F_GETFL, 0).result;
    CHECK(original >= 0);
    CHECK(file_operation(client, 25U, fd, F_SETFL, (original & ~O_ACCMODE) | O_RDONLY | O_APPEND).result == 0);
    int64_t flags = file_operation(client, 25U, fd, F_GETFL, 0).result;
    CHECK(flags >= 0 && (flags & O_APPEND) != 0 && (flags & O_ACCMODE) == O_RDWR);
    CHECK((flags & O_NONBLOCK) == 0);
    CHECK(file_operation(client, 62U, fd, 0, SEEK_SET).result == 0);
    CHECK(write_file(client, fd, "Z") == 1);
    CHECK(file_operation(client, 25U, fd, F_SETFL, O_ASYNC).result == -EINVAL);
    CHECK(file_operation(client, 25U, fd, F_GETFL, 0).result == flags);
    CHECK(file_operation(client, 25U, fd, F_SETFL, O_RDWR).result == 0);
    CHECK((file_operation(client, 25U, fd, F_GETFL, 0).result & O_APPEND) == 0);
    CHECK(file_operation(client, 62U, fd, 0, SEEK_SET).result == 0);
    struct sucrune_response content = file_operation(client, 63U, fd, 100, 0);
    CHECK(content.result == 4 && memcmp(content.data, "abcZ", 4U) == 0);
    CHECK(path_operation(client, 35U, "append-state", 0) == 0);
    disconnect_broker(&client);
}

/* Tests share the broker's host process. Find only the uniquely named test
 * file's actual open FD to independently check the hidden nonblock safeguard;
 * no private broker state or testing-only production API is exposed. */
static int actual_open_flags(const char *path) {
    struct stat wanted;
    CHECK(stat(path, &wanted) == 0);
    DIR *directory = opendir("/proc/self/fd");
    CHECK(directory != NULL);
    int found = -1;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        char *end;
        long number = strtol(entry->d_name, &end, 10);
        if (*entry->d_name == '\0' || *end != '\0' || number < 0 || number > INT_MAX) continue;
        struct stat current;
        if (fstat((int)number, &current) == 0 && current.st_dev == wanted.st_dev && current.st_ino == wanted.st_ino) {
            CHECK(found < 0); /* Each caller arranges exactly one open description. */
            found = fcntl((int)number, F_GETFL);
            CHECK(found >= 0);
        }
    }
    CHECK(closedir(directory) == 0 && found >= 0);
    return found;
}

static int release_guest_file(void *context, enum sucrune_fd_kind kind, int handle) {
    if (kind != SUCRUNE_FD_BROKER) return 0;
    struct client *client = context;
    int64_t result = file_operation(*client, 57U, handle, 0, 0).result;
    CHECK(result >= INT_MIN && result <= INT_MAX);
    return (int)result;
}

static int64_t guest_fcntl(struct client client, struct sucrune_fd_table *table,
        int descriptor, int operation, int64_t value) {
    CHECK(descriptor >= 0);
    struct sucrune_fd_resource *resource = sucrune_fds_get(table, (uint64_t)descriptor);
    CHECK(resource != NULL && resource->kind == SUCRUNE_FD_BROKER);
    return file_operation(client, 25U, resource->handle, operation, value).result;
}

static void nonblocking_shared_descriptions(const char *workspace) {
    char path[2048];
    joined_path(path, sizeof(path), workspace, "nonblock-state");
    struct client client = connect_broker(workspace);
    int64_t handle = path_operation(client, 56U, "/nonblock-state", O_CREAT | O_RDWR | O_EXCL | O_NONBLOCK);
    CHECK(handle >= 3 && handle <= INT_MAX);
    struct sucrune_fd_table table;
    sucrune_fds_init(&table, -1, -1, -1, O_RDONLY, O_WRONLY, release_guest_file, &client);
    int first = sucrune_fds_add(&table, SUCRUNE_FD_BROKER, (int)handle, 0, 0U);
    CHECK(first >= 3);
    int alias = sucrune_fds_duplicate(&table, (uint64_t)first, 10U, 1U);
    CHECK(alias >= 10 && alias != first);
    CHECK(sucrune_fds_get(&table, (uint64_t)first) == sucrune_fds_get(&table, (uint64_t)alias));
    CHECK((guest_fcntl(client, &table, first, F_GETFL, 0) & O_NONBLOCK) != 0);
    CHECK((actual_open_flags(path) & O_NONBLOCK) != 0);
    CHECK(guest_fcntl(client, &table, alias, F_SETFL, O_APPEND) == 0);
    int64_t cleared = guest_fcntl(client, &table, first, F_GETFL, 0);
    CHECK(cleared >= 0 && (cleared & O_NONBLOCK) == 0 && (cleared & O_APPEND) != 0 && (cleared & O_ACCMODE) == O_RDWR);
    CHECK((actual_open_flags(path) & (O_NONBLOCK | O_APPEND)) == (O_NONBLOCK | O_APPEND));
    CHECK(guest_fcntl(client, &table, first, F_SETFL, O_NONBLOCK) == 0);
    int64_t set = guest_fcntl(client, &table, alias, F_GETFL, 0);
    CHECK(set >= 0 && (set & O_NONBLOCK) != 0 && (set & O_APPEND) == 0);
    CHECK(guest_fcntl(client, &table, alias, F_SETFL, O_ASYNC) == -EINVAL);
    CHECK(guest_fcntl(client, &table, alias, F_SETFL, -1) == -EINVAL);
    CHECK(guest_fcntl(client, &table, alias, F_SETFL, INT64_C(1) << 32) == -EINVAL);
    CHECK(guest_fcntl(client, &table, first, F_GETFL, 0) == set);
    CHECK((actual_open_flags(path) & O_NONBLOCK) != 0);
    CHECK(sucrune_fds_get_flags(&table, (uint64_t)first) == 0);
    CHECK(sucrune_fds_get_flags(&table, (uint64_t)alias) == SUCRUNE_FD_CLOEXEC);
    CHECK(sucrune_fds_close(&table, (uint64_t)first) == 0);
    CHECK(guest_fcntl(client, &table, alias, F_GETFL, 0) == set);
    CHECK(write_file(client, handle, "still-live") == 10);
    /* Separate opens are independent, even when they refer to the same inode. */
    int64_t separate = path_operation(client, 56U, "/nonblock-state", O_RDONLY);
    CHECK(separate >= 3 && separate != handle);
    CHECK((file_operation(client, 25U, separate, F_GETFL, 0).result & O_NONBLOCK) == 0);
    CHECK(guest_fcntl(client, &table, alias, F_GETFL, 0) == set);
    CHECK(file_operation(client, 57U, separate, 0, 0).result == 0);
    CHECK(sucrune_fds_close(&table, (uint64_t)alias) == 0);
    CHECK(file_operation(client, 25U, handle, F_GETFL, 0).result == -EBADF);
    CHECK(sucrune_fds_destroy(&table) == 0);
    int64_t reused = path_operation(client, 56U, "/nonblock-state", O_RDONLY);
    CHECK(reused == handle);
    CHECK((file_operation(client, 25U, reused, F_GETFL, 0).result & O_NONBLOCK) == 0);
    CHECK((actual_open_flags(path) & O_NONBLOCK) != 0);
    CHECK(file_operation(client, 57U, reused, 0, 0).result == 0);
    CHECK(path_operation(client, 35U, "/nonblock-state", 0) == 0);
    disconnect_broker(&client);
}

static void nonblocking_directory_and_special_files(const char *workspace) {
    struct client client = connect_broker(workspace);
    CHECK(path_operation(client, 34U, "/nonblock-dir", 0) == 0);
    const int flags = O_RDONLY | O_NONBLOCK | O_DIRECTORY | O_CLOEXEC | O_LARGEFILE;
    int64_t directory = path_operation(client, 56U, "/nonblock-dir", flags);
    CHECK(directory >= 3);
    int64_t visible = file_operation(client, 25U, directory, F_GETFL, 0).result;
    CHECK(visible >= 0 && (visible & (O_NONBLOCK | O_DIRECTORY)) == (O_NONBLOCK | O_DIRECTORY));
    CHECK(file_operation(client, 25U, directory, F_GETFD, 0).result == FD_CLOEXEC);
    struct sucrune_response result = file_operation(client, 61U, directory, SUCRUNE_IO_LIMIT, 0);
    CHECK(result.result > 0 && result.result == result.size);
    CHECK(file_operation(client, 61U, directory, SUCRUNE_IO_LIMIT, 0).result == 0);
    CHECK(file_operation(client, 25U, directory, F_SETFL, 0).result == 0);
    CHECK((file_operation(client, 25U, directory, F_GETFL, 0).result & O_NONBLOCK) == 0);
    CHECK(file_operation(client, 62U, directory, 0, SEEK_SET).result == 0);
    CHECK(file_operation(client, 61U, directory, SUCRUNE_IO_LIMIT, 0).result > 0);
    CHECK(path_operation(client, 56U, "/nonblock-missing", flags) == -ENOENT);
    int64_t regular = path_operation(client, 56U, "/nonblock-regular", O_CREAT | O_RDWR | O_EXCL);
    CHECK(regular >= 3);
    CHECK(path_operation(client, 56U, "/nonblock-regular", flags) == -ENOTDIR);
    CHECK(file_operation(client, 61U, regular, SUCRUNE_IO_LIMIT, 0).result == -ENOTDIR);
    CHECK(file_operation(client, 57U, regular, 0, 0).result == 0);
    CHECK(file_operation(client, 57U, directory, 0, 0).result == 0);
    char fifo[2048];
    joined_path(fifo, sizeof(fifo), workspace, "nonblock-fifo");
    if (mkfifo(fifo, 0600) != 0) {
        int error = errno;
        CHECK(error == EPERM || error == EACCES);
        skipped_subcases++;
        (void)printf("SKIP FIFO rejection subcase: platform denied fixture mkfifo (errno=%d); broker FIFO handling was not exercised.\n", error);
    } else {
        CHECK(path_operation(client, 56U, "/nonblock-fifo", O_RDONLY | O_NONBLOCK) == -EACCES);
        CHECK(path_operation(client, 56U, "/nonblock-fifo", O_RDONLY) == -EACCES);
        CHECK(unlink(fifo) == 0);
    }
    CHECK(path_operation(client, 35U, "/nonblock-regular", 0) == 0);
    CHECK(path_operation(client, 35U, "/nonblock-dir", AT_REMOVEDIR) == 0);
    disconnect_broker(&client);
}

static int64_t pwrite_file(struct client client, int64_t fd, int64_t offset, const char *text) {
    struct sucrune_request packet = request(SUCRUNE_BROKER_PWRITE64);
    packet.args[0] = fd; packet.args[1] = (int64_t)strlen(text); packet.args[2] = offset;
    packet.size = (uint32_t)strlen(text); memcpy(packet.data, text, packet.size);
    return exchange(client, &packet).result;
}

static void sendfile_regular_files(const char *workspace) {
    struct client client = connect_broker(workspace);
    int64_t src = path_operation(client, 56U, "/transfer-in", O_CREAT | O_EXCL | O_RDWR);
    int64_t dst = path_operation(client, 56U, "/transfer-out", O_CREAT | O_EXCL | O_RDWR);
    CHECK(src >= 3 && dst >= 3 && write_file(client, src, "abcde") == 5);
    CHECK(file_operation(client, 62U, src, 1, SEEK_SET).result == 1);
    struct sucrune_request packet = request(SUCRUNE_BROKER_SENDFILE);
    packet.args[0] = dst; packet.args[1] = src; packet.args[2] = 8; packet.args[3] = 3;
    struct sucrune_response r = exchange(client, &packet);
    CHECK(r.result == 2 && r.size == 0U);
    CHECK(file_operation(client, 62U, src, 0, SEEK_CUR).result == 1);
    CHECK(file_operation(client, 62U, dst, 0, SEEK_CUR).result == 2);
    packet.args[2] = 2; packet.args[3] = -1;
    CHECK(exchange(client, &packet).result == 2);
    CHECK(file_operation(client, 62U, src, 0, SEEK_CUR).result == 3);
    r = file_operation(client, SUCRUNE_BROKER_PREAD64, dst, 4, 0);
    CHECK(r.result == 4 && r.size == 4U && memcmp(r.data, "debc", 4) == 0);
    packet.args[2] = INT64_MAX; packet.args[3] = 5;
    CHECK(exchange(client, &packet).result == 0);
    packet.args[2] = 0; packet.args[3] = 0;
    CHECK(exchange(client, &packet).result == 0);
    packet.args[2] = -1;
    CHECK(exchange(client, &packet).result == -EINVAL);
    packet.args[2] = 1; packet.args[3] = -2;
    CHECK(exchange(client, &packet).result == -EINVAL);
    packet.args[3] = -1; packet.reserved = 1U;
    CHECK(exchange(client, &packet).result == -EINVAL);
    packet.reserved = 0U; packet.size = 1U;
    CHECK(exchange(client, &packet).result == -EINVAL);
    packet.size = 0U; packet.args[0] = 2;
    CHECK(exchange(client, &packet).result == -EBADF);
    packet.args[0] = dst; packet.args[1] = SUCRUNE_BROKER_HANDLE_BASE + SUCRUNE_FILE_RESOURCES;
    CHECK(exchange(client, &packet).result == -EBADF);
    packet.args[1] = src; packet.args[0] = path_operation(client, 56U, "/transfer-out", O_RDONLY);
    CHECK(packet.args[0] >= 3 && exchange(client, &packet).result == -EBADF);
    packet.args[0] = dst; packet.args[1] = path_operation(client, 56U, "/transfer-in", O_WRONLY);
    CHECK(packet.args[1] >= 3 && exchange(client, &packet).result == -EBADF);
    packet.args[1] = src; packet.args[0] = path_operation(client, 56U, "/transfer-out", O_WRONLY | O_APPEND);
    CHECK(packet.args[0] >= 3 && exchange(client, &packet).result == -EINVAL);
    packet.args[0] = dst; packet.args[1] = path_operation(client, 56U, "/", O_RDONLY | O_DIRECTORY);
    CHECK(packet.args[1] >= 3 && exchange(client, &packet).result == -EINVAL);
    CHECK(path_operation(client, 35U, "/transfer-in", 0) == 0);
    CHECK(path_operation(client, 35U, "/transfer-out", 0) == 0);
    disconnect_broker(&client);
    puts("PASS regular-file sendfile offsets, short transfers, EOF, access modes and rejected endpoints");
}

static void positioned_file_io(const char *workspace) {
    struct client client = connect_broker(workspace);
    int64_t fd = path_operation(client, 56U, "/positioned", O_CREAT | O_RDWR | O_EXCL);
    CHECK(fd >= 3 && write_file(client, fd, "abcdef") == 6);
    CHECK(file_operation(client, 62U, fd, 2, SEEK_SET).result == 2);
    struct sucrune_response response = file_operation(client, SUCRUNE_BROKER_PREAD64, fd, 100, 4);
    CHECK(response.result == 2 && response.size == 2U && memcmp(response.data, "ef", 2U) == 0);
    CHECK(file_operation(client, 62U, fd, 0, SEEK_CUR).result == 2);
    CHECK(pwrite_file(client, fd, 0, "XY") == 2);
    CHECK(file_operation(client, 62U, fd, 0, SEEK_CUR).result == 2);
    response = file_operation(client, SUCRUNE_BROKER_PREAD64, fd, SUCRUNE_IO_LIMIT, 0);
    CHECK(response.result == 6 && response.size == 6U && memcmp(response.data, "XYcdef", 6U) == 0);
    CHECK(file_operation(client, SUCRUNE_BROKER_PREAD64, fd, 1, 6).result == 0);
    CHECK(file_operation(client, SUCRUNE_BROKER_PREAD64, fd, 0, 0).result == 0);
    CHECK(pwrite_file(client, fd, 0, "") == 0);
    CHECK(file_operation(client, SUCRUNE_BROKER_PREAD64, fd, -1, 0).result == -EINVAL);
    CHECK(file_operation(client, SUCRUNE_BROKER_PREAD64, fd, SUCRUNE_IO_LIMIT + 1U, 0).result == -EINVAL);
    CHECK(file_operation(client, SUCRUNE_BROKER_PREAD64, fd, 1, -1).result == -EINVAL);
    CHECK(file_operation(client, SUCRUNE_BROKER_PREAD64, fd, 1, INT64_MAX).result == -EOVERFLOW);
    CHECK(pwrite_file(client, fd, INT64_MAX, "x") == -EOVERFLOW);
    for (int scenario = 0; scenario < 5; scenario++) {
        struct sucrune_request malformed = request(scenario == 0 ? SUCRUNE_BROKER_PREAD64 : SUCRUNE_BROKER_PWRITE64);
        malformed.args[0] = fd; malformed.args[1] = 1;
        malformed.size = 1U; malformed.data[0] = 'Q';
        if (scenario == 1) malformed.size = 0U;
        if (scenario == 2) malformed.args[1] = 0;
        if (scenario == 3) malformed.args[3] = 1;
        if (scenario == 4) malformed.reserved = 1U;
        CHECK(exchange(client, &malformed).result == -EINVAL);
    }
    CHECK(file_operation(client, 62U, fd, 0, SEEK_CUR).result == 2);
    response = file_operation(client, SUCRUNE_BROKER_PREAD64, fd, 6, 0);
    CHECK(response.result == 6 && memcmp(response.data, "XYcdef", 6U) == 0);
    /* Linux pwrite with O_APPEND appends, but still leaves the OFD offset alone. */
    CHECK(file_operation(client, 25U, fd, F_SETFL, O_APPEND).result == 0);
    CHECK(pwrite_file(client, fd, 0, "Z") == 1);
    CHECK(file_operation(client, 62U, fd, 0, SEEK_CUR).result == 2);
    response = file_operation(client, SUCRUNE_BROKER_PREAD64, fd, 8, 0);
    CHECK(response.result == 7 && memcmp(response.data, "XYcdefZ", 7U) == 0);
    CHECK(file_operation(client, 25U, fd, F_SETFL, O_RDWR).result == 0);
    struct sucrune_request full = request(SUCRUNE_BROKER_PWRITE64);
    full.args[0] = fd; full.args[1] = SUCRUNE_IO_LIMIT; full.size = SUCRUNE_IO_LIMIT;
    memset(full.data, 'M', SUCRUNE_IO_LIMIT);
    CHECK(exchange(client, &full).result == SUCRUNE_IO_LIMIT);
    CHECK(file_operation(client, 62U, fd, 0, SEEK_CUR).result == 2);
    response = file_operation(client, SUCRUNE_BROKER_PREAD64, fd, SUCRUNE_IO_LIMIT, 0);
    CHECK(response.result == SUCRUNE_IO_LIMIT && response.size == SUCRUNE_IO_LIMIT);
    CHECK(memcmp(response.data, full.data, SUCRUNE_IO_LIMIT) == 0);
    CHECK(file_operation(client, 57U, fd, 0, 0).result == 0);
    CHECK(file_operation(client, SUCRUNE_BROKER_PREAD64, fd, 1, 0).result == -EBADF);
    CHECK(pwrite_file(client, fd, 0, "x") == -EBADF);
    CHECK(file_operation(client, SUCRUNE_BROKER_PREAD64, 2, 1, 0).result == -EBADF);
    CHECK(file_operation(client, SUCRUNE_BROKER_PREAD64, 67, 1, 0).result == -EBADF);
    fd = path_operation(client, 56U, "/positioned", O_RDONLY);
    CHECK(fd >= 3 && pwrite_file(client, fd, 0, "x") == -EBADF);
    CHECK(file_operation(client, 57U, fd, 0, 0).result == 0);
    fd = path_operation(client, 56U, "/positioned", O_WRONLY);
    CHECK(fd >= 3 && file_operation(client, SUCRUNE_BROKER_PREAD64, fd, 1, 0).result == -EBADF);
    CHECK(file_operation(client, 57U, fd, 0, 0).result == 0);
    CHECK(path_operation(client, 35U, "/positioned", 0) == 0);
    disconnect_broker(&client);
}

static void exec_preserves_open_descriptions(const char *workspace) {
    struct client client = connect_broker(workspace);
    int64_t keep = path_operation(client, 56U, "/exec-keep", O_CREAT | O_RDWR | O_CLOEXEC | O_NONBLOCK);
    int64_t clo_open = path_operation(client, 56U, "/exec-open", O_CREAT | O_RDWR | O_CLOEXEC);
    int64_t clo_fcntl = path_operation(client, 56U, "/exec-fcntl", O_CREAT | O_RDWR);
    CHECK(keep >= 3 && clo_open >= 3 && clo_fcntl >= 3);
    CHECK(file_operation(client, 25U, keep, F_SETFD, 0).result == 0);
    CHECK(file_operation(client, 25U, clo_fcntl, F_SETFD, FD_CLOEXEC).result == 0);
    CHECK(write_file(client, keep, "abc") == 3);
    CHECK(file_operation(client, 62U, keep, 1, SEEK_SET).result == 1);
    CHECK(path_operation(client, 34U, "/exec-cwd", 0) == 0);
    CHECK(path_operation(client, 49U, "/exec-cwd", 0) == 0);
    for (int invalid = 0; invalid < 6; invalid++) {
        struct sucrune_request packet = request(SUCRUNE_BROKER_EXEC_COMMIT);
        if (invalid == 0) packet.reserved = 1U;
        else if (invalid == 1) { packet.size = 1U; packet.data[0] = 1U; }
        else packet.args[invalid - 2] = 1;
        CHECK(exchange(client, &packet).result == -EINVAL);
        CHECK(file_operation(client, 25U, clo_open, F_GETFD, 0).result == FD_CLOEXEC);
        CHECK(file_operation(client, 25U, clo_fcntl, F_GETFD, 0).result == FD_CLOEXEC);
        CHECK(file_operation(client, 62U, keep, 0, SEEK_CUR).result == 1);
        check_cwd(client, "/exec-cwd");
    }
    struct sucrune_request commit = request(SUCRUNE_BROKER_EXEC_COMMIT);
    CHECK(exchange(client, &commit).result == 0);
    CHECK(file_operation(client, 25U, clo_open, F_GETFD, 0).result == -EBADF);
    CHECK(file_operation(client, 25U, clo_fcntl, F_GETFD, 0).result == -EBADF);
    CHECK(file_operation(client, 25U, keep, F_GETFD, 0).result == 0);
    CHECK((file_operation(client, 25U, keep, F_GETFL, 0).result & O_NONBLOCK) != 0);
    check_cwd(client, "/exec-cwd");
    struct sucrune_response remaining = file_operation(client, 63U, keep, 2, 0);
    CHECK(remaining.result == 2 && remaining.size == 2U && memcmp(remaining.data, "bc", 2U) == 0);
    CHECK(exchange(client, &commit).result == 0);
    CHECK(file_operation(client, 62U, keep, 0, SEEK_CUR).result == 3);
    CHECK(file_operation(client, 57U, keep, 0, 0).result == 0);
    CHECK(path_operation(client, 49U, "/", 0) == 0);
    CHECK(path_operation(client, 35U, "/exec-keep", 0) == 0);
    CHECK(path_operation(client, 35U, "/exec-open", 0) == 0);
    CHECK(path_operation(client, 35U, "/exec-fcntl", 0) == 0);
    CHECK(path_operation(client, 35U, "/exec-cwd", AT_REMOVEDIR) == 0);
    disconnect_broker(&client);
}

static void rename_current_directory(const char *workspace) {
    struct client client = connect_broker(workspace);
    CHECK(path_operation(client, 34U, "/a", 0) == 0);
    CHECK(path_operation(client, 34U, "/a/child", 0) == 0);
    CHECK(path_operation(client, 34U, "/other", 0) == 0);
    CHECK(path_operation(client, 49U, "/a/child", 0) == 0);
    CHECK(rename_path(client, "/a", "/b") == 0);
    check_cwd(client, "/b/child");
    int64_t fd = path_operation(client, 56U, "marker", O_CREAT | O_WRONLY);
    CHECK(fd >= 3 && write_file(client, fd, "inside") == 6);
    CHECK(file_operation(client, 57U, fd, 0, 0).result == 0);
    CHECK(rename_path(client, "/other", "/b") == -EBUSY);
    CHECK(path_operation(client, 35U, "/b", AT_REMOVEDIR) == -EBUSY);
    CHECK(path_operation(client, 35U, "/b/child", AT_REMOVEDIR) == -EBUSY);
    CHECK(rename_path(client, "/b/child", "/b/renamed") == 0);
    check_cwd(client, "/b/renamed");
    CHECK(path_operation(client, 56U, "../../../escape", O_CREAT | O_WRONLY) == -EPERM);
    CHECK(path_operation(client, 35U, "marker", 0) == 0);
    CHECK(path_operation(client, 49U, "/", 0) == 0);
    CHECK(path_operation(client, 35U, "/b/renamed", AT_REMOVEDIR) == 0);
    CHECK(path_operation(client, 35U, "/b", AT_REMOVEDIR) == 0);
    CHECK(path_operation(client, 35U, "/other", AT_REMOVEDIR) == 0);
    disconnect_broker(&client);
}

static void malformed_messages(const char *workspace) {
    for (unsigned int scenario = 0U; scenario < 4U; scenario++) {
        struct client client = connect_broker(workspace);
        struct sucrune_request packet = request(17U);
        packet.args[0] = SUCRUNE_PATH_LIMIT;
        if (scenario == 0U) {
            packet.magic = 0;
            send_bytes(client.socket, &packet, offsetof(struct sucrune_request, data));
        } else if (scenario == 1U) {
            send_bytes(client.socket, &packet, 1U);
        } else if (scenario == 2U) {
            packet.size = 1U;
            send_bytes(client.socket, &packet, offsetof(struct sucrune_request, data));
        } else {
            unsigned char oversized[sizeof(packet) + 1U];
            memset(oversized, 0, sizeof(oversized));
            memcpy(oversized, &packet, sizeof(packet));
            send_bytes(client.socket, oversized, sizeof(oversized));
        }
        await_eof(client.socket, true);
        disconnect_broker(&client);
    }
    struct client client = connect_broker(workspace);
    struct sucrune_request unknown = request(UINT32_MAX);
    CHECK(exchange(client, &unknown).result == -ENOSYS);
    check_cwd(client, "/"); // unsupported operation does not corrupt the channel
    disconnect_broker(&client);
}

static void completion_drains_queued_file_operation(const char *workspace) {
    struct client client = connect_broker(workspace);
    int64_t fd = path_operation(client, 56U, "queued", O_WRONLY | O_CREAT | O_EXCL);
    CHECK(fd >= 3);
    const char text[] = "queued-write";
    struct sucrune_request packet = request(64U);
    packet.args[0] = fd; packet.args[1] = (int64_t)strlen(text);
    packet.size = (uint32_t)strlen(text); memcpy(packet.data, text, packet.size);
    send_bytes(client.socket, &packet, offsetof(struct sucrune_request, data) + packet.size);
    disconnect_broker(&client); // no response was read; must still wait for dispatch/cleanup
    char path[2048], content[32];
    joined_path(path, sizeof(path), workspace, "queued");
    int host = open(path, O_RDONLY | O_CLOEXEC);
    CHECK(host >= 0);
    ssize_t count = read(host, content, sizeof(content));
    CHECK(count == (ssize_t)strlen(text) && memcmp(content, text, strlen(text)) == 0);
    CHECK(close(host) == 0 && unlink(path) == 0);
}

static void independent_brokers(const char *workspace, const char *other) {
    struct client first = connect_broker(workspace), second = connect_broker(other);
    int64_t left = path_operation(first, 56U, "same", O_CREAT | O_RDWR | O_EXCL);
    int64_t right = path_operation(second, 56U, "same", O_CREAT | O_RDWR | O_EXCL);
    CHECK(left >= 3 && right >= 3);
    CHECK(write_file(first, left, "left") == 4 && write_file(second, right, "right") == 5);
    CHECK(file_operation(first, 62U, left, 0, SEEK_SET).result == 0);
    CHECK(file_operation(second, 62U, right, 0, SEEK_SET).result == 0);
    struct sucrune_response a = file_operation(first, 63U, left, 100, 0);
    struct sucrune_response b = file_operation(second, 63U, right, 100, 0);
    CHECK(a.result == 4 && memcmp(a.data, "left", 4U) == 0);
    CHECK(b.result == 5 && memcmp(b.data, "right", 5U) == 0);
    CHECK(path_operation(first, 35U, "same", 0) == 0);
    disconnect_broker(&first); // closes still-open left without affecting right
    CHECK(file_operation(second, 62U, right, 0, SEEK_SET).result == 0);
    b = file_operation(second, 63U, right, 100, 0);
    CHECK(b.result == 5 && memcmp(b.data, "right", 5U) == 0);
    CHECK(path_operation(second, 35U, "same", 0) == 0);
    disconnect_broker(&second);
}

static void path_permissions(const char *workspace,const char *outside) {
    struct client client=connect_broker(workspace);
    CHECK(path_operation(client,34U,"chmod-at",0)==0);
    int64_t directory=path_operation(client,56U,"chmod-at",O_DIRECTORY|O_RDONLY);
    CHECK(directory>=3);
    int64_t file=query(client,56U,directory,"body",O_CREAT|O_EXCL|O_RDWR,0600).result;
    CHECK(file>=3 && link_paths(client,directory,"body",directory,"alias",0)==0);
    CHECK(rename_path(client,"chmod-at","chmod-moved")==0);
    CHECK(query(client,53U,directory,"alias",0,0).result==0);
    struct sucrune_arm64_stat body,alias;
    struct sucrune_response response=query(client,79U,directory,"body",0,0);
    CHECK(response.result==0 && response.size==sizeof(body));
    memcpy(&body,response.data,sizeof(body));
    CHECK(S_ISREG(body.mode) && (body.mode&0777U)==0 && body.nlink==2U);
    /* Both names are mode 000. Restoration requires a metadata operation that
     * does not first open the body for reading or writing. */
    CHECK(query(client,53U,-992,"/chmod-moved/body",0600,0).result==0);
    response=query(client,79U,directory,"alias",AT_SYMLINK_NOFOLLOW,0);
    CHECK(response.result==0 && response.size==sizeof(alias));
    memcpy(&alias,response.data,sizeof(alias));
    CHECK((alias.mode&0777U)==0600U && alias.device==body.device && alias.inode==body.inode && alias.nlink==2U);
    CHECK(query(client,53U,directory,"body",04700,0).result==-EINVAL);
    CHECK(query(client,53U,directory,"body",-1,0).result==-EINVAL);
    CHECK(query(client,53U,-992,"body",0400,0).result==-EBADF);
    CHECK(query(client,53U,file,"body",0400,0).result==-ENOTDIR);
    CHECK(query(client,53U,directory,"missing",0400,0).result==-ENOENT);
    CHECK(query(client,53U,directory,"../../outside/sentinel",0400,0).result==-EPERM);
    char sentinel[2048],link[2048],dir_link[2048];
    joined_path(sentinel,sizeof(sentinel),outside,"sentinel");
    joined_path(link,sizeof(link),workspace,"chmod-moved/foreign");
    joined_path(dir_link,sizeof(dir_link),workspace,"chmod-moved/outside");
    struct stat before,after;
    CHECK(stat(sentinel,&before)==0 && symlink(sentinel,link)==0 && symlink(outside,dir_link)==0);
    CHECK(query(client,53U,directory,"foreign",0,0).result<0);
    CHECK(query(client,53U,directory,"outside/sentinel",0,0).result<0);
    CHECK(stat(sentinel,&after)==0 && before.st_dev==after.st_dev && before.st_ino==after.st_ino &&
          before.st_mode==after.st_mode);
    response=file_operation(client,80U,file,0,0);
    CHECK(response.result==0 && response.size==sizeof(body));
    memcpy(&body,response.data,sizeof(body));
    CHECK((body.mode&0777U)==0600U && body.nlink==2U);
    CHECK(unlink(link)==0 && unlink(dir_link)==0);
    CHECK(query(client,35U,directory,"alias",0,0).result==0);
    CHECK(query(client,35U,directory,"body",0,0).result==0);
    CHECK(file_operation(client,57U,file,0,0).result==0);
    CHECK(file_operation(client,57U,directory,0,0).result==0);
    CHECK(path_operation(client,35U,"chmod-moved",AT_REMOVEDIR)==0);
    disconnect_broker(&client);
}

static int64_t set_times(struct client client, int64_t directory, const char *path, int flags,
                         const struct timespec *times) {
    struct sucrune_request packet = request(SUCRUNE_BROKER_UTIMENSAT);
    packet.args[0] = directory;
    packet.args[1] = flags;
    append_path(&packet, path);
    if (times != NULL) {
        packet.args[2] = 1;
        memcpy(packet.data + packet.size, times, 2U * sizeof(*times));
        packet.size += (uint32_t)(2U * sizeof(*times));
    }
    return exchange(client, &packet).result;
}

static void file_timestamps(const char *workspace, const char *outside) {
    struct client client = connect_broker(workspace);
    CHECK(path_operation(client, 34U, "time-dir", 0) == 0);
    int64_t dir = path_operation(client, 56U, "time-dir", O_RDONLY | O_DIRECTORY);
    int64_t file = query(client, 56U, dir, "body", O_CREAT | O_RDWR | O_EXCL, 0600).result;
    CHECK(dir >= 3 && file >= 3);
    struct timespec times[2] = {{1512345678, 100000000}, {1612345678, 200000000}};
    CHECK(set_times(client, dir, "body", AT_SYMLINK_NOFOLLOW, times) == 0);
    struct sucrune_arm64_stat st;
    struct sucrune_response result = file_operation(client, 80U, file, 0, 0);
    CHECK(result.result == 0 && result.size == sizeof(st));
    memcpy(&st, result.data, sizeof(st));
    CHECK(st.atime_sec == times[0].tv_sec && st.atime_nsec == (uint64_t)times[0].tv_nsec &&
          st.mtime_sec == times[1].tv_sec && st.mtime_nsec == (uint64_t)times[1].tv_nsec);
    times[0].tv_nsec = UTIME_OMIT;
    times[1].tv_nsec = UTIME_NOW;
    CHECK(set_times(client, file, "", AT_EMPTY_PATH, times) == 0);
    result = file_operation(client, 80U, file, 0, 0);
    CHECK(result.result == 0 && result.size == sizeof(st));
    memcpy(&st, result.data, sizeof(st));
    CHECK(st.atime_sec == times[0].tv_sec && st.atime_nsec == 100000000U && st.mtime_sec != times[1].tv_sec);
    CHECK(set_times(client, -999, "/time-dir/body", 0, NULL) == 0);
    CHECK(set_times(client, file, "", 0, NULL) == -ENOENT);
    CHECK(set_times(client, -1, "", AT_EMPTY_PATH, NULL) == -EBADF);
    CHECK(set_times(client, dir, "../..", 0, NULL) == -EPERM);
    times[1].tv_nsec = 1000000000;
    CHECK(set_times(client, dir, "body", 0, times) == -EINVAL);
    times[1].tv_nsec = UTIME_OMIT;
    CHECK(set_times(client, -1, "absent", 0, times) == 0);
    struct sucrune_request malformed = request(SUCRUNE_BROKER_UTIMENSAT);
    append_path(&malformed, "body");
    malformed.args[2] = 1;
    CHECK(exchange(client, &malformed).result == -EINVAL);
    char link[2048], sentinel[2048];
    joined_path(link, sizeof(link), workspace, "time-dir/link");
    joined_path(sentinel, sizeof(sentinel), outside, "sentinel");
    struct stat before, after;
    CHECK(stat(sentinel, &before) == 0 && symlink(sentinel, link) == 0);
    CHECK(set_times(client, dir, "link", 0, NULL) == -ENOENT);
    times[0].tv_nsec = times[1].tv_nsec = 100000000;
    int64_t changed = set_times(client, dir, "link", AT_SYMLINK_NOFOLLOW, times);
    CHECK(changed == 0 || changed == -ENOTSUP);
    if (changed == 0) CHECK(lstat(link, &after) == 0 && after.st_mtim.tv_sec == times[1].tv_sec);
    CHECK(stat(sentinel, &after) == 0 && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
          before.st_mtim.tv_nsec == after.st_mtim.tv_nsec);
    CHECK(unlink(link) == 0 && query(client, 35U, dir, "body", 0, 0).result == 0);
    CHECK(set_times(client, file, "", AT_EMPTY_PATH, times) == 0); /* unlinked, still open */
    CHECK(file_operation(client, 57U, file, 0, 0).result == 0);
    CHECK(file_operation(client, 57U, dir, 0, 0).result == 0);
    CHECK(path_operation(client, 35U, "time-dir", AT_REMOVEDIR) == 0);
    disconnect_broker(&client);
}

static void creation_modes(const char *workspace) {
    struct client client = connect_broker(workspace);
    CHECK(file_operation(client, SUCRUNE_BROKER_UMASK, 0027, 0, 0).result == 0077);
    int64_t dir = path_operation(client, 56U, "/", O_RDONLY | O_DIRECTORY);
    CHECK(dir >= 3);
    struct sucrune_request create = request(34);
    create.args[0] = dir;
    create.args[2] = 0777;
    create.args[3] = 1;
    append_path(&create, "mode-dir/");
    CHECK(exchange(client, &create).result == 0);
    create = request(56);
    create.args[0] = dir;
    create.args[1] = O_RDWR | O_CREAT;
    create.args[2] = 0666;
    create.args[3] = 1;
    append_path(&create, "mode-dir/new");
    int64_t file = exchange(client, &create).result;
    CHECK(file >= 3);
    CHECK(file_operation(client, 57U, file, 0, 0).result == 0);
    CHECK(file_operation(client, SUCRUNE_BROKER_UMASK, 0777, 0, 0).result == 0027);
    file = exchange(client, &create).result;
    CHECK(file >= 3); /* O_CREAT on an existing file must leave permissions intact. */
    char name[2048];
    struct stat st;
    joined_path(name, sizeof(name), workspace, "mode-dir");
    CHECK(stat(name, &st) == 0 && (st.st_mode & 0777U) == 0750U);
    joined_path(name, sizeof(name), workspace, "mode-dir/new");
    CHECK(stat(name, &st) == 0 && (st.st_mode & 0777U) == 0640U);
    CHECK(file_operation(client, 57U, file, 0, 0).result == 0);
    CHECK(file_operation(client, 57U, dir, 0, 0).result == 0);
    CHECK(path_operation(client, 35U, "mode-dir/new", 0) == 0);
    CHECK(path_operation(client, 35U, "mode-dir", AT_REMOVEDIR) == 0);
    disconnect_broker(&client);
}

static void descriptor_permissions(const char *workspace) {
    struct client client = connect_broker(workspace);
    int64_t file = path_operation(client, 56U, "mode-file", O_CREAT | O_EXCL | O_RDWR);
    CHECK(file >= 3);
    CHECK(file_operation(client, 52U, file, 0750, 0).result == 0);
    struct sucrune_response response = file_operation(client, 80U, file, 0, 0);
    CHECK(response.result == 0 && response.size == sizeof(struct sucrune_arm64_stat));
    struct sucrune_arm64_stat st;
    memcpy(&st, response.data, sizeof(st));
    CHECK((st.mode & 0777U) == 0750U);
    CHECK(file_operation(client, 52U, file, 04750, 0).result == -EINVAL);
    CHECK(file_operation(client, 52U, file, 0600, 1).result == -EINVAL);
    response = file_operation(client, 80U, file, 0, 0);
    memcpy(&st, response.data, sizeof(st));
    CHECK((st.mode & 07777U) == 0750U);
    CHECK(file_operation(client, 57U, file, 0, 0).result == 0);
    CHECK(file_operation(client, 52U, file, 0600, 0).result == -EBADF);
    CHECK(path_operation(client, 35U, "mode-file", 0) == 0);
    disconnect_broker(&client);
}

static void file_lock_descriptions(const char *workspace) {
    struct client client = connect_broker(workspace), contender = connect_broker(workspace);
    int64_t first = path_operation(client, 56U, "session.lock", O_CREAT | O_EXCL | O_RDWR);
    int64_t second = path_operation(client, 56U, "session.lock", O_RDWR);
    int64_t other = path_operation(contender, 56U, "session.lock", O_RDWR);
    CHECK(first >= 3 && second >= 3 && other >= 3);
    CHECK(write_file(client, first, "durable-lock") == 12);
    CHECK(file_operation(client, SUCRUNE_BROKER_FSYNC, first, 0, 0).result == 0);
    CHECK(file_operation(client, SUCRUNE_BROKER_FDATASYNC, first, 0, 0).result == 0);
    CHECK(file_operation(client, SUCRUNE_BROKER_FSYNC, first, 1, 0).result == -EINVAL);
    int64_t directory = path_operation(client, 56U, "/", O_RDONLY | O_DIRECTORY);
    CHECK(directory >= 3);
    CHECK(file_operation(client, SUCRUNE_BROKER_FSYNC, directory, 0, 0).result == 0);
    CHECK(file_operation(client, 57U, directory, 0, 0).result == 0);
    CHECK(file_operation(client, SUCRUNE_BROKER_FLOCK, first, LOCK_EX | LOCK_NB, 0).result == 0);
    CHECK(file_operation(client, SUCRUNE_BROKER_FLOCK, first, LOCK_EX | LOCK_NB, 0).result == 0);
    CHECK(file_operation(client, SUCRUNE_BROKER_FLOCK, second, LOCK_EX | LOCK_NB, 0).result == -EWOULDBLOCK);
    CHECK(file_operation(contender, SUCRUNE_BROKER_FLOCK, other, LOCK_SH | LOCK_NB, 0).result == -EWOULDBLOCK);
    CHECK(file_operation(client, SUCRUNE_BROKER_FLOCK, second, LOCK_EX, 0).result == -EOPNOTSUPP);
    CHECK(file_operation(client, SUCRUNE_BROKER_FLOCK, first, LOCK_EX | LOCK_NB, 1).result == -EINVAL);
    CHECK(file_operation(client, SUCRUNE_BROKER_FLOCK, first, LOCK_UN, 0).result == 0);
    CHECK(file_operation(client, SUCRUNE_BROKER_FLOCK, second, LOCK_SH | LOCK_NB, 0).result == 0);
    CHECK(file_operation(contender, SUCRUNE_BROKER_FLOCK, other, LOCK_SH | LOCK_NB, 0).result == 0);
    CHECK(file_operation(client, 57U, second, 0, 0).result == 0);
    CHECK(file_operation(contender, SUCRUNE_BROKER_FLOCK, other, LOCK_EX | LOCK_NB, 0).result == 0);
    disconnect_broker(&contender);
    CHECK(file_operation(client, SUCRUNE_BROKER_FLOCK, first, LOCK_EX | LOCK_NB, 0).result == 0);
    CHECK(file_operation(client, 57U, first, 0, 0).result == 0);
    CHECK(file_operation(client, SUCRUNE_BROKER_FLOCK, first, LOCK_UN, 0).result == -EBADF);
    CHECK(path_operation(client, 35U, "session.lock", 0) == 0);
    disconnect_broker(&client);
}

static void bulk_regular_file_reads(const char *workspace) {
    char path[2048];
    joined_path(path, sizeof(path), workspace, "bulk-input");
    unsigned char expected[SUCRUNE_IO_LIMIT * 3U + 29U];
    for (size_t i = 0; i < sizeof(expected); i++) expected[i] = (unsigned char)(i * 37U);
    int fixture = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    CHECK(fixture >= 0 && write(fixture, expected, sizeof(expected)) == (ssize_t)sizeof(expected));
    struct client parent = connect_broker(workspace);
    int64_t fd = path_operation(parent, 56U, "/bulk-input", O_RDONLY);
    CHECK(fd >= 3);
    struct sucrune_request begin = request(SUCRUNE_BROKER_BULK_READ);
    struct sucrune_request next = request(SUCRUNE_BROKER_BULK_NEXT);
    struct sucrune_request abort_read = request(SUCRUNE_BROKER_BULK_ABORT);
    begin.args[0] = fd;
    begin.args[1] = SUCRUNE_IO_LIMIT;
    CHECK(exchange(parent, &begin).result == -EINVAL);
    begin.args[1] = SUCRUNE_BULK_READ_LIMIT + 1;
    CHECK(exchange(parent, &begin).result == -EINVAL);
    begin.args[1] = SUCRUNE_BULK_READ_LIMIT;
    begin.args[2] = 2;
    CHECK(exchange(parent, &begin).result == -EINVAL);
    begin.args[2] = 1;
    begin.args[3] = INT64_MAX;
    CHECK(exchange(parent, &begin).result == -EOVERFLOW);
    begin.args[3] = -1;
    CHECK(exchange(parent, &begin).result == -EINVAL);
    begin.args[2] = 0;
    begin.args[3] = 1;
    CHECK(exchange(parent, &begin).result == -EINVAL);
    begin.args[3] = 0;
    begin.size = 1U;
    CHECK(exchange(parent, &begin).result == -EINVAL);
    begin.size = 0U;
    begin.args[0] = -1;
    CHECK(exchange(parent, &begin).result == -EBADF);
    begin.args[0] = path_operation(parent, 56U, "/", O_RDONLY | O_DIRECTORY);
    CHECK(begin.args[0] >= 3 && exchange(parent, &begin).result == -EISDIR);
    begin.args[0] = fd;
    struct sucrune_response packet = exchange(parent, &begin);
    /* Read 1 MiB at EOF of a smaller regular file: only initialized bytes
     * are available, and the entire shared offset has advanced immediately. */
    CHECK(packet.result == (int64_t)sizeof(expected) && packet.size == SUCRUNE_IO_LIMIT);
    CHECK(memcmp(packet.data, expected, packet.size) == 0);
    CHECK(exchange(parent, &begin).result == -EBUSY);
    next.args[0] = 1;
    CHECK(exchange(parent, &next).result == -EINVAL);
    next.args[0] = 0;
    abort_read.size = 1U;
    CHECK(exchange(parent, &abort_read).result == -EINVAL);
    abort_read.size = 0U;
    struct sucrune_request fork_request = request(SUCRUNE_BROKER_FORK_SESSION);
    int child_socket = -1;
    CHECK(sucrune_broker_exchange(parent.socket, &fork_request, &packet, &child_socket, 2000) == 0);
    CHECK(packet.result == 0 && child_socket >= 0);
    struct client child = {.socket = child_socket, .done = -1};
    CHECK(exchange(child, &next).result == -ENOENT);
    CHECK(file_operation(child, 62U, fd, 0, SEEK_CUR).result == (int64_t)sizeof(expected));
    packet = exchange(child, &begin);
    CHECK(packet.result == 0 && packet.size == 0U);
    CHECK(pwrite(fixture, "X", 1U, (off_t)SUCRUNE_IO_LIMIT) == 1);
    for (size_t pos = SUCRUNE_IO_LIMIT; pos < sizeof(expected);) {
        size_t count = sizeof(expected) - pos;
        if (count > SUCRUNE_IO_LIMIT) count = SUCRUNE_IO_LIMIT;
        packet = exchange(parent, &next);
        CHECK(packet.result == (int64_t)count && packet.size == count);
        CHECK(memcmp(packet.data, expected + pos, count) == 0);
        pos += count;
    }
    CHECK(exchange(parent, &next).result == -ENOENT);
    begin.args[2] = 1;
    begin.args[3] = SUCRUNE_IO_LIMIT;
    packet = exchange(child, &begin);
    CHECK(packet.result == (int64_t)(sizeof(expected) - SUCRUNE_IO_LIMIT) && packet.data[0] == 'X');
    CHECK(file_operation(parent, 62U, fd, 0, SEEK_CUR).result == (int64_t)sizeof(expected));
    CHECK(exchange(child, &abort_read).result == 0 && exchange(child, &abort_read).result == 0);
    CHECK(exchange(child, &next).result == -ENOENT);
    begin.args[3] = (int64_t)sizeof(expected) - 29;
    packet = exchange(child, &begin);
    CHECK(packet.result == 29 && packet.size == 29U && exchange(child, &next).result == -ENOENT);
    begin.args[3] = 0;
    CHECK(exchange(child, &begin).result == (int64_t)sizeof(expected));
    CHECK(close(child.socket) == 0); /* Undrained snapshot is discarded on broker EOF. */
    CHECK(close(fixture) == 0 && unlink(path) == 0);
    disconnect_broker(&parent);
    (void)puts("PASS bulk regular-file snapshot, shared OFD, positioned read, short EOF, invalid/aborted/abandoned requests");
}

struct append_upload {
    struct client client;
    int64_t handle;
    size_t count;
    pthread_barrier_t *ready;
    unsigned char byte;
};
static void *append_upload(void *arg) {
    struct append_upload *job=arg;
    struct sucrune_request begin=request(SUCRUNE_BROKER_BULK_WRITE),push=request(SUCRUNE_BROKER_BULK_PUSH);
    struct sucrune_request commit=request(SUCRUNE_BROKER_BULK_COMMIT);
    begin.args[0]=job->handle;begin.args[1]=(int64_t)job->count;
    CHECK(exchange(job->client,&begin).result==0);
    CHECK(exchange(job->client,&begin).result==-EBUSY);
    CHECK(exchange(job->client,&commit).result==-EINVAL);
    memset(push.data,job->byte,sizeof(push.data));
    for(size_t at=0;at<job->count;) {
        size_t n=job->count-at;
        if(n>sizeof(push.data)) n=sizeof(push.data);
        push.args[0]=(int64_t)at;push.size=(uint32_t)n;
        CHECK(exchange(job->client,&push).result==0);
        CHECK(exchange(job->client,&push).result==-EINVAL); /* replayed offset */
        at+=n;
    }
    CHECK(file_operation(job->client,62U,job->handle,0,SEEK_END).result==0);
    int ready=pthread_barrier_wait(job->ready);
    CHECK(ready==0 || ready==PTHREAD_BARRIER_SERIAL_THREAD);
    struct sucrune_response written=exchange(job->client,&commit);
    CHECK(written.result==(int64_t)job->count && written.size==0);
    CHECK(exchange(job->client,&commit).result==-ENOENT); /* no repeated write */
    return NULL;
}
static void bulk_regular_file_writes(const char *workspace) {
    char path[2048];joined_path(path,sizeof(path),workspace,"bulk-output");
    struct client baseline=connect_broker(workspace);
    struct sucrune_request begin=request(SUCRUNE_BROKER_BULK_WRITE),push=request(SUCRUNE_BROKER_BULK_PUSH);
    struct sucrune_request commit=request(SUCRUNE_BROKER_BULK_COMMIT),drop=request(SUCRUNE_BROKER_BULK_DROP);
    int64_t file=path_operation(baseline,56U,"bulk-output",O_CREAT|O_RDWR|O_EXCL);
    CHECK(file>=3);
    const size_t count=SUCRUNE_BULK_WRITE_LIMIT+13U;
    begin.args[0]=file;begin.args[1]=(int64_t)count;
    CHECK(exchange(baseline,&begin).result==-EINVAL);
    begin.args[1]=SUCRUNE_IO_LIMIT+1;
    begin.args[0]=path_operation(baseline,56U,"/",O_RDONLY|O_DIRECTORY);
    CHECK(exchange(baseline,&begin).result==-EISDIR);
    begin.args[0]=path_operation(baseline,56U,"bulk-output",O_RDONLY);
    CHECK(exchange(baseline,&begin).result==-EBADF);
    begin.args[0]=file;begin.args[2]=1;begin.args[3]=INT64_MAX;
    CHECK(exchange(baseline,&begin).result==-EOVERFLOW);
    begin.args[3]=1;
    CHECK(exchange(baseline,&begin).result==0);
    push.size=SUCRUNE_IO_LIMIT;memset(push.data,'P',sizeof(push.data));
    CHECK(exchange(baseline,&push).result==0 && exchange(baseline,&drop).result==0);
    CHECK(exchange(baseline,&drop).result==0 && exchange(baseline,&commit).result==-ENOENT);
    CHECK(exchange(baseline,&begin).result==0 && exchange(baseline,&push).result==0);
    CHECK(file_operation(baseline,57U,file,0,0).result==0);
    CHECK(path_operation(baseline,56U,"bulk-output",O_RDWR)==file && exchange(baseline,&commit).result==-ENOENT);
    struct stat st;CHECK(stat(path,&st)==0 && st.st_size==0);
    struct append_upload jobs[2];pthread_t threads[2];pthread_barrier_t ready;
    CHECK(pthread_barrier_init(&ready,NULL,2)==0);
    for(unsigned int i=0;i<2;i++) {
        struct client client={.socket=-1,.done=-1};
        client.socket=sucrune_workspace_broker_profile(workspace,&client.done,0,0,SUCRUNE_WORKSPACE_BUILD);
        CHECK(client.socket>=0 && client.done>=0);
        int64_t fd=path_operation(client,56U,"bulk-output",O_WRONLY|O_APPEND);
        CHECK(fd>=3);
        jobs[i]=(struct append_upload){client,fd,count,&ready,(unsigned char)('A'+i)};
        CHECK(pthread_create(&threads[i],NULL,append_upload,&jobs[i])==0);
    }
    for(size_t i=0;i<2;i++) {CHECK(pthread_join(threads[i],NULL)==0);disconnect_broker(&jobs[i].client);}
    CHECK(pthread_barrier_destroy(&ready)==0);
    int actual=open(path,O_RDONLY|O_CLOEXEC);CHECK(actual>=0 && fstat(actual,&st)==0 && st.st_size==(off_t)(2U*count));
    unsigned char *bytes=malloc(2U*count);CHECK(bytes!=NULL && read(actual,bytes,2U*count)==(ssize_t)(2U*count));
    CHECK((bytes[0]=='A' || bytes[0]=='B') && bytes[count]!=bytes[0]);
    for(size_t i=0;i<count;i++) CHECK(bytes[i]==bytes[0] && bytes[count+i]==bytes[count]);
    free(bytes);
    CHECK(exchange(baseline,&begin).result==0 && exchange(baseline,&push).result==0);
    push.args[0]=SUCRUNE_IO_LIMIT;push.size=1;
    CHECK(exchange(baseline,&push).result==0 && exchange(baseline,&commit).result==SUCRUNE_IO_LIMIT+1);
    CHECK(file_operation(baseline,62U,file,0,SEEK_CUR).result==0);
    unsigned char patch[SUCRUNE_IO_LIMIT+1];
    CHECK(pread(actual,patch,sizeof(patch),1)==(ssize_t)sizeof(patch));
    for(size_t i=0;i<sizeof(patch);i++) CHECK(patch[i]=='P');
    CHECK(exchange(baseline,&begin).result==0);
    disconnect_broker(&baseline); /* unfinished upload dies with the session */
    struct client appender={.socket=-1,.done=-1};
    appender.socket=sucrune_workspace_broker_profile(workspace,&appender.done,0,0,SUCRUNE_WORKSPACE_BUILD);
    CHECK(appender.socket>=0 && appender.done>=0);
    int64_t append_fd=path_operation(appender,56U,"bulk-output",O_WRONLY|O_APPEND);
    CHECK(append_fd>=3 && file_operation(appender,62U,append_fd,27,SEEK_SET).result==27);
    begin.args[0]=append_fd;begin.args[1]=SUCRUNE_BUILD_BULK_WRITE_LIMIT+1;begin.args[2]=1;begin.args[3]=0;
    CHECK(exchange(appender,&begin).result==-EINVAL);
    begin.args[1]=SUCRUNE_BUILD_BULK_WRITE_LIMIT;
    CHECK(exchange(appender,&begin).result==0);
    push.size=SUCRUNE_IO_LIMIT;
    for(size_t at=0;at<SUCRUNE_BUILD_BULK_WRITE_LIMIT;at+=push.size) {
        push.args[0]=(int64_t)at;
        CHECK(exchange(appender,&push).result==0);
    }
    CHECK(fstat(actual,&st)==0 && st.st_size==(off_t)(2U*count));
    CHECK(exchange(appender,&commit).result==SUCRUNE_BUILD_BULK_WRITE_LIMIT);
    /* On Linux pwrite on O_APPEND appends despite the supplied offset,
     * while leaving the OFD position unchanged. */
    CHECK(file_operation(appender,62U,append_fd,0,SEEK_CUR).result==27);
    CHECK(fstat(actual,&st)==0 && st.st_size==(off_t)(2U*count+SUCRUNE_BUILD_BULK_WRITE_LIMIT));
    CHECK(pread(actual,patch,1,(off_t)(2U*count))==1 && patch[0]=='P');
    CHECK(pread(actual,patch,1,st.st_size-1)==1 && patch[0]=='P');
    disconnect_broker(&appender);
    CHECK(close(actual)==0 && unlink(path)==0);
    (void)puts("PASS bulk regular writes: concurrent 1 MiB + 13 append, 16 MiB positioned append, limits, abort/close/disconnect");
}

static void scoped_writes(const char *root) {
    struct client setup = connect_broker(root);
    CHECK(path_operation(setup, 34, "/workspace", 0) == 0);
    CHECK(path_operation(setup, 34, "/tmp", 0) == 0);
    CHECK(path_operation(setup, 34, "/workspace-else", 0) == 0);
    int64_t sentinel = path_operation(setup, 56, "/workspace-else/sentinel", O_CREAT | O_RDWR);
    CHECK(sentinel >= 3 && write_file(setup, sentinel, "unchanged") == 9);
    struct sucrune_request sym = request(36);
    sym.args[0] = AT_FDCWD;
    append_path(&sym, "../workspace-else/sentinel");
    append_path(&sym, "/workspace/link");
    CHECK(exchange(setup, &sym).result == 0);
    char real[2048], alias[2048];
    joined_path(real, sizeof(real), root, "workspace-else/sentinel");
    joined_path(alias, sizeof(alias), root, "workspace/hard");
    CHECK(link(real, alias) == 0);
    char temp_hard[2048];
    joined_path(temp_hard, sizeof(temp_hard), root, "tmp/foreign");
    CHECK(link(real, temp_hard) == 0);
    for (int scope = SUCRUNE_WRITE_READ_ONLY; scope <= SUCRUNE_WRITE_PROJECT; scope++) {
        struct client c;
        c.socket = sucrune_workspace_broker_scoped(root, &c.done, 0, 0, SUCRUNE_WORKSPACE_LINUX, (enum sucrune_write_scope)scope);
        CHECK(c.socket >= 0 && path_operation(c, 49, "/workspace", 0) == 0);
        CHECK(path_operation(c, 34, "/", 0) == -EEXIST);
        CHECK(path_operation(c, 34, "/workspace", 0) == -EEXIST);
        CHECK(path_operation(c, 34, "/workspace-else", 0) == -EEXIST);
        CHECK(path_operation(c, 34, "/workspace-else/sentinel", 0) == -EEXIST);
        CHECK(path_operation(c, 34, "/workspace/link", 0) == -EEXIST);
        int64_t created = path_operation(c, 34, "/workspace/Desktop", 0);
        if (scope == SUCRUNE_WRITE_PROJECT) {
            CHECK(created == 0 && path_operation(c, 34, "/workspace/Desktop", 0) == -EEXIST);
            CHECK(path_operation(c, 34, "/workspace/Desktop/nested/", 0) == 0);
            CHECK(path_operation(c, 35, "/workspace/Desktop/nested", AT_REMOVEDIR) == 0);
            CHECK(path_operation(c, 35, "/workspace/Desktop", AT_REMOVEDIR) == 0);
        } else CHECK(created == -EACCES);
        int64_t outside = path_operation(c, 56, "/workspace-else", O_PATH|O_NOCTTY|O_DIRECTORY);
        CHECK(outside>=3 && file_operation(c,50,outside,0,0).result==0);
        CHECK(path_operation(c,56,"sentinel",O_RDWR|O_TRUNC)==-EACCES);
        CHECK(file_operation(c,57,outside,0,0).result==0);
        CHECK(path_operation(c,49,"/workspace",0)==0);
        int64_t readfd = path_operation(c, 56, "/workspace-else/sentinel", O_RDONLY);
        CHECK(readfd >= 3 && file_operation(c, 52, readfd, 0777, 0).result == -EACCES);
        CHECK(path_operation(c, 56, "/workspace-else/sentinel", O_RDWR | O_TRUNC) == -EACCES);
        CHECK(path_operation(c, 56, "link", O_WRONLY | O_TRUNC) == -EACCES);
        CHECK(path_operation(c, 56, "hard", O_WRONLY | O_TRUNC) == -EACCES);
        CHECK(path_operation(c, 34, "../workspace-else/bad", 0) == -EACCES);
        CHECK(path_operation(c, 35, "../workspace-else/sentinel", 0) == -EACCES);
        struct sucrune_request fork_req = request(SUCRUNE_BROKER_FORK_SESSION);
        struct sucrune_response result;
        struct client child = {.socket = -1, .done = -1};
        CHECK(sucrune_broker_exchange(c.socket, &fork_req, &result, &child.socket, 2000) == 0 && child.socket >= 0);
        CHECK(path_operation(child, 56, "/workspace-else/child", O_CREAT | O_WRONLY) == -EACCES);
        int64_t data = path_operation(child, 56, "ok", O_CREAT | O_RDWR);
        int64_t tmp = path_operation(c, 56, "/tmp/temp", O_CREAT | O_WRONLY);
        if (scope == SUCRUNE_WRITE_PROJECT) {
            CHECK(data >= 3 && write_file(child, data, "test") == 4 && tmp >= 3);
            CHECK(link_paths(c,AT_FDCWD,"/workspace-else/sentinel",AT_FDCWD,"/tmp/bad",0)==-EACCES);
            CHECK(link_paths(c,AT_FDCWD,"/tmp/foreign",AT_FDCWD,"/tmp/bad",0)==-EACCES);
            CHECK(link_paths(c,AT_FDCWD,"/tmp/temp",AT_FDCWD,"/workspace-else/bad",0)==-EACCES);
            CHECK(link_paths(c,readfd,"",AT_FDCWD,"/tmp/bad",AT_EMPTY_PATH)==-EACCES);
            CHECK(path_operation(c,56,"/tmp/foreign",O_RDWR|O_TRUNC)==-EACCES);
            CHECK(path_operation(c,34,"/tmp/profile",0)==0);
            CHECK(link_paths(c,AT_FDCWD,"/tmp/temp",AT_FDCWD,"/tmp/profile/session",0)==0);
            CHECK(link_paths(c,AT_FDCWD,"/tmp/temp",AT_FDCWD,"/tmp/profile/session",0)==-EEXIST);
            // Another unrestricted consumer can publish an alias to a protected
            // directory. The scoped consumer must then reject writes through the temp names.
            CHECK(link_paths(setup,AT_FDCWD,"/tmp/temp",AT_FDCWD,"/workspace-else/published",0)==0);
            CHECK(path_operation(c,56,"/tmp/profile/session",O_WRONLY|O_TRUNC)==-EACCES);
            CHECK(link_paths(c,AT_FDCWD,"/tmp/temp",AT_FDCWD,"/tmp/bad",0)==-EACCES);
            CHECK(path_operation(setup,35,"/workspace-else/published",0)==0);
            int64_t linked=path_operation(child,56,"/tmp/profile/session",O_WRONLY|O_APPEND);
            CHECK(linked>=3 && write_file(child,linked,"hello")==5);
            CHECK(path_operation(c,35,"/tmp/temp",0)==0);
            CHECK(write_file(child,linked,"!")==1);
            CHECK(file_operation(child,57,linked,0,0).result==0);
            linked=path_operation(c,56,"/tmp/profile/session",O_WRONLY|O_APPEND);
            CHECK(linked>=3 && write_file(c,linked,"?")==1 && file_operation(c,57,linked,0,0).result==0);
            linked=path_operation(c,56,"/tmp/profile/session",O_RDONLY);
            CHECK(linked>=3);
            struct sucrune_response line=file_operation(c,63,linked,7,0);
            CHECK(line.result==7 && !memcmp(line.data,"hello!?",7));
            CHECK(file_operation(c,57,linked,0,0).result==0);
            CHECK(path_operation(c,35,"/tmp/profile/session",0)==0);
            CHECK(path_operation(c,35,"/tmp/profile",AT_REMOVEDIR)==0);
            CHECK(rename_path(c, "ok", "/workspace-else/moved") == -EACCES);
            CHECK(rename_path(c, "/workspace-else/sentinel", "replaced") == -EACCES);
            CHECK(path_operation(c, 35, "ok", 0) == 0);
        } else {
            CHECK(data == -EACCES && tmp == -EACCES);
            CHECK(link_paths(c,AT_FDCWD,"/tmp/foreign",AT_FDCWD,"/tmp/new",0)==-EACCES);
        }
        close(child.socket);
        disconnect_broker(&c);
    }
    struct sucrune_response bytes = file_operation(setup, SUCRUNE_BROKER_PREAD64, sentinel, 9, 0);
    CHECK(bytes.result == 9 && memcmp(bytes.data, "unchanged", 9) == 0);
    CHECK(path_operation(setup, 35, "/workspace/link", 0) == 0 && unlink(alias) == 0 && unlink(temp_hard)==0);
    CHECK(path_operation(setup, 35, "/workspace-else/sentinel", 0) == 0);
    CHECK(path_operation(setup, 35, "/workspace-else", AT_REMOVEDIR) == 0);
    CHECK(path_operation(setup, 35, "/tmp", AT_REMOVEDIR) == 0 && path_operation(setup, 35, "/workspace", AT_REMOVEDIR) == 0);
    disconnect_broker(&setup);
}

static int64_t ll_wire(struct client c, uint32_t op, int64_t a, int64_t b, int64_t d, int64_t e) {
    struct sucrune_request r = request(op);
    r.args[0] = a; r.args[1] = b; r.args[2] = d; r.args[3] = e;
    return exchange(c, &r).result;
}
static struct client landlock_client(const char *workspace) {
    struct client c;
    c.socket = sucrune_workspace_broker_profile(workspace, &c.done, 0, 0, SUCRUNE_WORKSPACE_LINUX);
    CHECK(c.socket >= 0);
    return c;
}
static struct client landlock_fork(struct client parent) {
    struct sucrune_request fork_request = request(SUCRUNE_BROKER_FORK_SESSION);
    struct sucrune_response response;
    struct client child = {.socket = -1, .done = -1};
    CHECK(sucrune_broker_exchange(parent.socket, &fork_request, &response, &child.socket, 2000) == 0);
    CHECK(response.result == 0 && child.socket >= 0);
    return child;
}
static void add_path_rule(struct client c, int64_t set, const char *name, int rights) {
    int64_t pin = path_operation(c, 56, name, O_PATH);
    CHECK(pin >= 3 && ll_wire(c, 445, set, 1, rights, pin) == 0);
    CHECK(ll_wire(c, 57, pin, 0, 0, 0) == 0);
}
/* The backing directory is outside the guest filesystem. Only these owner callbacks
 * can reach it. The phone tests use a SAF owner instead of this POSIX fixture. */
struct mounted_fixture { int root; unsigned int released; };
static void mount_release(void *ctx) { ((struct mounted_fixture *)ctx)->released++; }
static int mount_status(void *ctx,const char *name,struct stat *out) {
    return fstatat(((struct mounted_fixture *)ctx)->root,*name?name:".",out,AT_SYMLINK_NOFOLLOW)<0 ? -errno : 0;
}
static int mount_list(void *ctx,const char *name,char ***items,size_t *count) {
    int fd=openat(((struct mounted_fixture *)ctx)->root,*name?name:".",O_RDONLY|O_DIRECTORY);
    if (fd<0) return -errno;
    DIR *d=fdopendir(fd); CHECK(d);
    *count=0; *items=NULL;
    struct dirent *e;
    while ((e=readdir(d))!=NULL) {
        if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
        char **next=realloc(*items,(*count+1)*sizeof(*next)); CHECK(next);
        *items=next; next[*count]=strdup(e->d_name); CHECK(next[*count]); ++*count;
    }
    closedir(d); return 0;
}
static int mount_file_open(void *ctx,const char *name,int flags,mode_t mode) {
    int fd=openat(((struct mounted_fixture *)ctx)->root,*name?name:".",flags|O_CLOEXEC|O_NOFOLLOW,mode);
    return fd<0 ? -errno : fd;
}
static int mount_mkdir(void *ctx,const char *name) {
    return mkdirat(((struct mounted_fixture *)ctx)->root,name,0700)<0 ? -errno : 0;
}
static int mount_remove(void *ctx,const char *name,bool dir) {
    return unlinkat(((struct mounted_fixture *)ctx)->root,name,dir?AT_REMOVEDIR:0)<0 ? -errno : 0;
}
static int mount_move(void *ctx,const char *from,const char *to,unsigned int flags) {
    if(flags) return -EINVAL;
    int root=((struct mounted_fixture *)ctx)->root;
    return renameat(root,from,root,to)<0 ? -errno : 0;
}
static void mounted_tree(const char *root,const char *outside) {
    char anchor[2048],private_file[2048],alias[2048];
    joined_path(anchor,sizeof(anchor),root,"workspace");
    CHECK(mkdir(anchor,0700)==0);
    joined_path(alias,sizeof(alias),root,"mounted-alias");
    CHECK(symlink("workspace",alias)==0);
    joined_path(private_file,sizeof(private_file),anchor,"sentinel");
    struct mounted_fixture fixture={.root=open(outside,O_RDONLY|O_DIRECTORY|O_CLOEXEC)};
    CHECK(fixture.root>=0);
    struct sucrune_guest_directory mount={&fixture,mount_release,mount_status,mount_list,mount_file_open,
        mount_mkdir,mount_remove,mount_move};
    struct client reader;
    reader.socket=sucrune_workspace_broker_mounted(root,&reader.done,0,0,SUCRUNE_WORKSPACE_LINUX,
                                                  SUCRUNE_WRITE_READ_ONLY,NULL,&mount);
    CHECK(reader.socket>=0);
    CHECK(path_operation(reader,34,"/workspace",0)==-EEXIST);
    CHECK(path_operation(reader,34,"/workspace/sentinel",0)==-EEXIST);
    CHECK(path_operation(reader,43,"/workspace/sentinel",0)==-EOPNOTSUPP);
    CHECK(path_operation(reader,43,"/workspace/no-volume-file",0)==-ENOENT);
    CHECK(path_operation(reader,34,"/workspace/new-dir",0)==-EACCES);
    int exported=-1;
    CHECK(open_read(reader,"/mounted-alias/sentinel",O_RDONLY,&exported)>=3 && exported>=0);
    CHECK((fcntl(exported,F_GETFL)&O_ACCMODE)==O_RDONLY && close(exported)==0);
    CHECK(path_operation(reader,56,"/mounted-alias/sentinel",O_WRONLY|O_TRUNC)==-EACCES);
    CHECK(path_operation(reader,56,"/workspace/blocked",O_WRONLY|O_CREAT)==-EACCES);
    CHECK(path_operation(reader,35,"/workspace/sentinel",0)==-EACCES);
    disconnect_broker(&reader);
    CHECK(fixture.released==1);
    struct client c;
    c.socket=sucrune_workspace_broker_mounted(root,&c.done,0,0,SUCRUNE_WORKSPACE_LINUX,
                                             SUCRUNE_WRITE_PROJECT,NULL,&mount);
    CHECK(c.socket>=0);
    CHECK(path_operation(c,49,"/workspace",0)==0); check_cwd(c,"/workspace");
    int64_t file=path_operation(c,56,"sentinel",O_RDONLY);
    CHECK(file>=3);
    CHECK(link_paths(c,AT_FDCWD,"sentinel",AT_FDCWD,"/tmp/foreign",0)==-EXDEV);
    CHECK(file_operation(c,44,file,0,0).result==-EOPNOTSUPP);
    struct sucrune_response got=file_operation(c,63,file,9,0);
    CHECK(got.result==9 && !memcmp(got.data,"untouched",9));
    CHECK(path_operation(c,79,"/workspace/../workspace/sentinel",0)==0);
    CHECK(path_operation(c,34,"nested",0)==0);
    CHECK(path_operation(c,49,"nested",0)==0); check_cwd(c,"/workspace/nested");
    CHECK(renameat(fixture.root,"nested",fixture.root,"moved-dir")==0);
    CHECK(mkdirat(fixture.root,"nested",0700)==0);
    CHECK(path_operation(c,56,"accidental",O_WRONLY|O_CREAT)==-ESTALE);
    CHECK(unlinkat(fixture.root,"nested",AT_REMOVEDIR)==0);
    CHECK(renameat(fixture.root,"moved-dir",fixture.root,"nested")==0);
    int64_t output=path_operation(c,56,"a",O_CREAT|O_WRONLY|O_EXCL);
    CHECK(output>=3 && write_file(c,output,"live")==4);
    struct stat disk; CHECK(fstatat(fixture.root,"nested/a",&disk,0)==0 && disk.st_size==4);
    CHECK(rename_path(c,"a","b")==0);
    CHECK(rename_path(c,"b","/separate")==-EXDEV && rename_path(c,"/workspace","/other")==-EBUSY);
    CHECK(path_operation(c,49,"..",0)==0);
    int64_t dir=path_operation(c,56,"nested",O_DIRECTORY|O_RDONLY);
    CHECK(dir>=3);
    got=file_operation(c,61,dir,512,0);
    CHECK(got.result>0 && memmem(got.data,got.size,"b",2)!=NULL);
    CHECK(file_operation(c,62,dir,0,SEEK_SET).result==0);
    int64_t set=ll_wire(c,444,LL_ALL,8,0,0); CHECK(set>=3);
    CHECK(ll_wire(c,445,set,1,LL_READ_DIR,dir)==-EOPNOTSUPP);
    add_path_rule(c,set,"/workspace",LL_READ_DIR|LL_READ_FILE);
    CHECK(ll_wire(c,167,38,1,0,0)==0 && ll_wire(c,446,set,0,0,0)==0);
    CHECK(path_operation(c,34,"/workspace/nested/.",0)==-EEXIST);
    CHECK(file_operation(c,50,dir,0,0).result==0);
    check_cwd(c,"/workspace/nested");
    CHECK(path_operation(c,34,"blocked",0)==-EACCES);
    CHECK(path_operation(c,49,"/workspace",0)==0);
    CHECK(path_operation(c,34,"/workspace/nested/blocked",0)==-EACCES);
    CHECK(path_operation(c,56,"nested/b",O_WRONLY|O_TRUNC)==-EACCES);
    CHECK(path_operation(c,35,"nested/b",0)==-EACCES);
    struct client child=landlock_fork(c);
    CHECK(ll_wire(child,SUCRUNE_BROKER_EXEC_COMMIT,0,0,0,0)==0);
    check_cwd(child,"/workspace");
    CHECK(path_operation(child,56,"nested/b",O_RDONLY)>=3);
    CHECK(path_operation(child,56,"new",O_CREAT|O_WRONLY)==-EACCES);
    CHECK(close(child.socket)==0);
    disconnect_broker(&c);
    CHECK(fixture.released==2 && access(private_file,F_OK)<0 && errno==ENOENT);
    CHECK(unlinkat(fixture.root,"nested/b",0)==0 && unlinkat(fixture.root,"nested",AT_REMOVEDIR)==0);
    CHECK(close(fixture.root)==0 && rmdir(anchor)==0 && unlink(alias)==0);
    (void)puts("PASS live /workspace mount: original bytes, scoped writes, Landlock, stale cwd, fork/exec and readonly FD");
}
static void trusted_image_metadata(const char *workspace) {
    const char name[] = "/trusted-launcher";
    struct { Elf64_Ehdr eh; Elf64_Phdr ph; } elf = {0};
    memcpy(elf.eh.e_ident, ELFMAG, SELFMAG);
    elf.eh.e_ident[EI_CLASS] = ELFCLASS64;
    elf.eh.e_ident[EI_DATA] = ELFDATA2LSB;
    elf.eh.e_machine = EM_AARCH64;
    elf.eh.e_type = ET_EXEC;
    elf.eh.e_phentsize = sizeof(Elf64_Phdr);
    elf.eh.e_phnum = 1;
    elf.eh.e_phoff = sizeof(Elf64_Ehdr);
    elf.ph.p_type = PT_LOAD;
    struct sucrune_exec_image *image = NULL;
    CHECK(sucrune_exec_image_create(name, &elf, sizeof(elf), &image) == 0);
    struct client c;
    c.socket = sucrune_workspace_broker_with_image(workspace, &c.done, 0, 0, SUCRUNE_WORKSPACE_LINUX,
                                                   SUCRUNE_WRITE_UNRESTRICTED, image);
    CHECK(c.socket >= 0);
    sucrune_exec_image_release(image);
    int64_t original = path_operation(c, 56, name, O_CREAT | O_RDWR);
    CHECK(original >= 3 && write_file(c, original, "guest") == 5);
    CHECK(ll_wire(c, 52, original, 0600, 0, 0) == 0);
    int64_t no_exec = path_operation(c, SUCRUNE_BROKER_OPEN_EXEC, name, O_RDONLY);
    CHECK(no_exec >= 3);
    const struct sucrune_project_owner owner = {
        .broker_uid = (uint32_t)getuid(), .broker_gid = (uint32_t)getgid(), .guest_uid = 45, .guest_gid = 46
    };
    struct sucrune_response info = file_operation(c, 80, no_exec, 0, 0);
    struct sucrune_arm64_stat st;
    CHECK(info.result == 0 && info.size == sizeof(st));
    memcpy(&st, info.data, sizeof(st));
    CHECK(st.size == (int64_t)sizeof(elf) && !sucrune_project_executable(&st, &owner));
    CHECK(rename_path(c, name, "/trusted-old") == 0);
    int64_t replacement = path_operation(c, 56, name, O_CREAT | O_RDWR);
    CHECK(replacement >= 3 && write_file(c, replacement, "replaced") == 8);
    CHECK(ll_wire(c, 52, replacement, 0700, 0, 0) == 0);
    struct client child = landlock_fork(c);
    int64_t execute = path_operation(child, SUCRUNE_BROKER_OPEN_EXEC, name, O_RDONLY);
    CHECK(execute >= 3);
    info = file_operation(child, 80, execute, 0, 0);
    CHECK(info.result == 0 && info.size == sizeof(st));
    memcpy(&st, info.data, sizeof(st));
    CHECK(st.size == (int64_t)sizeof(elf) && sucrune_project_executable(&st, &owner));
    struct sucrune_response bytes = file_operation(child, SUCRUNE_BROKER_PREAD64, execute, sizeof(elf), 0);
    CHECK(bytes.result == (int64_t)sizeof(elf) && !memcmp(bytes.data, &elf, sizeof(elf)));
    bytes = file_operation(c, SUCRUNE_BROKER_PREAD64, replacement, 8, 0);
    CHECK(bytes.result == 8 && !memcmp(bytes.data, "replaced", 8));
    int64_t set = ll_wire(child, 444, LL_READ_FILE | LL_EXECUTE, 8, 0, 0);
    CHECK(set >= 3 && ll_wire(child, 167, 38, 1, 0, 0) == 0);
    add_path_rule(child, set, name, LL_EXECUTE);
    CHECK(ll_wire(child, 446, set, 0, 0, 0) == 0);
    CHECK(path_operation(child, SUCRUNE_BROKER_OPEN_EXEC, name, O_RDONLY) == -EACCES);
    CHECK(close(child.socket) == 0);
    CHECK(path_operation(c, 35, "/trusted-old", 0) == 0 && path_operation(c, 35, name, 0) == 0);
    disconnect_broker(&c);
    (void)puts("PASS trusted exec image: original mode/owner, sealed replacement bytes, inherited read and execution checks");
}
static void landlock_policy(const char *workspace) {
    struct client manager = connect_broker(workspace), c = landlock_client(workspace);
    CHECK(path_operation(manager, 34, "ll-src", 0) == 0);
    CHECK(path_operation(manager, 34, "ll-other", 0) == 0);
    int64_t protected_file = path_operation(manager, 56, "ll-other/tool", O_CREAT | O_RDWR);
    CHECK(protected_file >= 3 && write_file(manager, protected_file, "original") == 8);
    CHECK(ll_wire(c, 444, 0, 0, 1, 0) == 3);
    CHECK(ll_wire(c, 444, 0, 8, 0, 0) == -ENOMSG);
    CHECK(ll_wire(c, 444, 1 << 15, 8, 0, 0) == -EINVAL);
    int64_t saved = path_operation(c, 56, "ll-other/tool", O_RDWR);
    int64_t set = ll_wire(c, 444, LL_ALL, 8, 0, 0);
    CHECK(saved >= 3 && set >= 3 && ll_wire(c, 25, set, F_GETFD, 0, 0) == FD_CLOEXEC);
    CHECK(ll_wire(c, 445, set, 1, LL_READ_DIR, saved) == -EINVAL);
    CHECK(ll_wire(c, 446, set, 0, 0, 0) == -EPERM);
    CHECK(ll_wire(c, 167, 38, 1, 0, 0) == 0);
    CHECK(ll_wire(c, 167, 39, 0, 0, 0) == 1);
    add_path_rule(c, set, "/", LL_READ_DIR | LL_READ_FILE);
    add_path_rule(c, set, "ll-src", LL_ALL);
    add_path_rule(c, set, "ll-other/tool", LL_EXECUTE | LL_WRITE_FILE);
    CHECK(ll_wire(c, 445, set, 1, LL_READ_FILE | LL_WRITE_FILE, LL_DEV_NULL) == 0);
    CHECK(ll_wire(c, 446, set, 0, 0, 0) == 0);
    CHECK(ll_wire(c, SUCRUNE_BROKER_LL_SPECIAL, LL_DEV_NULL, LL_WRITE_FILE, 0, 0) == 0);
    CHECK(ll_wire(c, SUCRUNE_BROKER_LL_SPECIAL, LL_OTHER_SPECIAL, LL_WRITE_FILE, 0, 0) == -EACCES);
    CHECK(path_operation(c, SUCRUNE_BROKER_OPEN_EXEC, "ll-other/tool", O_RDONLY) >= 3);
    CHECK(path_operation(c, 56, "ll-other/x", O_CREAT | O_RDWR) == -EACCES);
    CHECK(path_operation(c, 34, "/", 0) == -EEXIST);
    CHECK(path_operation(c, 34, "/ll-other", 0) == -EEXIST);
    CHECK(path_operation(c, 34, "/ll-other/blocked", 0) == -EACCES);
    CHECK(path_operation(c, 34, "/ll-src/nested", 0) == 0);
    CHECK(path_operation(c, 35, "/ll-src/nested", AT_REMOVEDIR) == 0);
    CHECK(path_operation(c, 56, "ll-src/new", O_CREAT | O_RDWR) >= 3);
    CHECK(path_operation(c, 56, "ll-other/tool", O_RDWR | O_TRUNC) == -EACCES);
    int64_t limited = path_operation(c, 56, "ll-other/tool", O_RDWR);
    CHECK(limited >= 3 && ll_wire(c, 46, limited, 1, 0, 0) == -EACCES);
    CHECK(file_operation(manager, SUCRUNE_BROKER_PREAD64, protected_file, 8, 0).result == 8);
    CHECK(ll_wire(c, 46, saved, 5, 0, 0) == 0); /* FD opened before restriction. */

    /* Adding rights to the builder cannot loosen a previously installed layer.
     * Rename the allowed directory and replace its old name with another inode. */
    add_path_rule(c, set, "ll-other", LL_ALL);
    CHECK(path_operation(c, 56, "ll-other/x", O_CREAT | O_WRONLY) == -EACCES);
    CHECK(rename_path(manager, "ll-src", "ll-moved") == 0);
    CHECK(path_operation(manager, 34, "ll-src", 0) == 0);
    CHECK(path_operation(c, 56, "ll-src/new", O_CREAT | O_WRONLY) == -EACCES);
    CHECK(path_operation(c, 56, "ll-moved/second", O_CREAT | O_WRONLY) >= 3);
    struct sucrune_request symlink_request = request(36);
    symlink_request.args[0] = AT_FDCWD;
    append_path(&symlink_request, "../ll-other/tool");
    append_path(&symlink_request, "ll-moved/link");
    CHECK(exchange(c, &symlink_request).result == 0);
    CHECK(path_operation(c, 56, "ll-moved/link", O_WRONLY | O_TRUNC) == -EACCES);

    /* Nested domain on the child only. Exec closes ruleset FDs and keeps the
     * restrictions and NNP. The unrestricted manager remains independent. */
    struct client child = landlock_fork(c);
    CHECK(ll_wire(child, 167, 39, 0, 0, 0) == 1);
    CHECK(ll_wire(child, 46, limited, 0, 0, 0) == -EACCES);
    int64_t second = ll_wire(child, 444, LL_WRITE_FILE | LL_EXECUTE, 8, 0, 0);
    CHECK(second >= 3 && ll_wire(child, 446, second, 0, 0, 0) == 0);
    CHECK(ll_wire(child, SUCRUNE_BROKER_EXEC_COMMIT, 0, 0, 0, 0) == 0);
    CHECK(ll_wire(child, 446, second, 0, 0, 0) == -EBADF);
    CHECK(ll_wire(child, 167, 39, 0, 0, 0) == 1);
    CHECK(path_operation(child, SUCRUNE_BROKER_OPEN_EXEC, "ll-other/tool", O_RDONLY) == -EACCES);
    CHECK(path_operation(child, 56, "ll-moved/new", O_RDONLY) >= 3);
    CHECK(path_operation(child, 56, "ll-moved/new", O_WRONLY) == -EACCES);
    CHECK(path_operation(c, 56, "ll-moved/new", O_WRONLY) >= 3);
    CHECK(close(child.socket) == 0);
    disconnect_broker(&c);

    c = landlock_client(workspace);
    set = ll_wire(c, 444, LL_WRITE_FILE | LL_REFER, 8, 0, 0);
    CHECK(set >= 3 && ll_wire(c, 167, 38, 1, 0, 0) == 0);
    add_path_rule(c, set, "ll-moved", LL_WRITE_FILE | LL_REFER);
    add_path_rule(c, set, "ll-other", LL_REFER);
    CHECK(ll_wire(c, 446, set, 0, 0, 0) == 0);
    CHECK(rename_path(c, "ll-other/tool", "ll-moved/escape") == -EXDEV);
    CHECK(rename_path(c, "ll-moved/new", "ll-other/reduced") == 0);
    CHECK(path_operation(c, 56, "ll-other/reduced", O_WRONLY) == -EACCES);
    CHECK(rename_path(c, "ll-moved/second", "ll-moved/third") == 0);
    disconnect_broker(&c);

    CHECK(path_operation(manager, 35, "ll-other/reduced", 0) == 0);
    CHECK(path_operation(manager, 35, "ll-other/tool", 0) == 0);
    CHECK(path_operation(manager, 35, "ll-moved/link", 0) == 0);
    CHECK(path_operation(manager, 35, "ll-moved/third", 0) == 0);
    CHECK(path_operation(manager, 35, "ll-other", AT_REMOVEDIR) == 0);
    CHECK(path_operation(manager, 35, "ll-src", AT_REMOVEDIR) == 0);
    CHECK(path_operation(manager, 35, "ll-moved", AT_REMOVEDIR) == 0);
    disconnect_broker(&manager);
    (void)puts("PASS Landlock ABI 3: ruleset FD, NNP, directory identity, immutable layers, inherited FD rights, reparent, fork/exec boundaries");
}
static void forked_session_semantics(const char *workspace) {
    struct client parent=connect_broker(workspace);
    CHECK(file_operation(parent,SUCRUNE_BROKER_UMASK,0027,0,0).result==0077);
    int64_t file=path_operation(parent,56U,"/forked",O_RDWR|O_CREAT|O_EXCL);
    CHECK(file>=3 && write_file(parent,file,"abc")==3);
    CHECK(file_operation(parent,62U,file,0,SEEK_SET).result==0);
    CHECK(path_operation(parent,34U,"/fork-cwd",0)==0);
    CHECK(path_operation(parent,49U,"/fork-cwd",0)==0);
    CHECK(file_operation(parent,SUCRUNE_BROKER_FLOCK,file,LOCK_EX|LOCK_NB,0).result==0);
    struct sucrune_request fork_request=request(SUCRUNE_BROKER_FORK_SESSION);
    struct sucrune_response response;
    int childfd=-1;
    CHECK(sucrune_broker_exchange(parent.socket,&fork_request,&response,&childfd,2000)==0);
    CHECK(response.result==0 && response.size==0 && childfd>=0);
    struct client child={.socket=childfd,.done=-1};
    CHECK(file_operation(child,SUCRUNE_BROKER_UMASK,0002,0,0).result==0027);
    CHECK(file_operation(parent,SUCRUNE_BROKER_UMASK,0007,0,0).result==0027);
    struct sucrune_request commit=request(SUCRUNE_BROKER_EXEC_COMMIT);
    CHECK(exchange(child,&commit).result==0);
    CHECK(file_operation(child,SUCRUNE_BROKER_UMASK,0000,0,0).result==0002);
    check_cwd(child,"/fork-cwd");
    CHECK(path_operation(child,49U,"/",0)==0);
    check_cwd(parent,"/fork-cwd");
    CHECK(file_operation(child,25U,file,F_SETFD,FD_CLOEXEC).result==0);
    CHECK(file_operation(parent,25U,file,F_GETFD,0).result==0);
    CHECK(file_operation(child,25U,file,F_SETFL,O_NONBLOCK|O_APPEND).result==0);
    CHECK((file_operation(parent,25U,file,F_GETFL,0).result&(O_NONBLOCK|O_APPEND))==(O_NONBLOCK|O_APPEND));
    response=file_operation(child,63U,file,1,0);CHECK(response.result==1 && response.data[0]=='a');
    response=file_operation(parent,63U,file,1,0);CHECK(response.result==1 && response.data[0]=='b');
    CHECK(file_operation(child,46U,file,4,0).result==0);
    CHECK(file_operation(parent,62U,file,0,SEEK_CUR).result==2);
    response=file_operation(parent,SUCRUNE_BROKER_PREAD64,file,1,3);
    CHECK(response.result==1 && response.size==1U && response.data[0]==0);
    CHECK(file_operation(child,SUCRUNE_BROKER_FLOCK,file,LOCK_UN,0).result==0);
    CHECK(path_operation(parent,35U,"/forked",0)==0);
    CHECK(close(parent.socket)==0);parent.socket=-1;
    struct pollfd completion={.fd=parent.done,.events=POLLIN};
    CHECK(poll(&completion,1,30)==0);
    response=file_operation(child,63U,file,1,0);CHECK(response.result==1 && response.data[0]=='c');
    CHECK(path_operation(child,35U,"/fork-cwd",AT_REMOVEDIR)==0);
    CHECK(close(child.socket)==0);
    await_eof(parent.done,false);CHECK(close(parent.done)==0);
}
static void guest_exec_mode_classes(void) {
    const uint32_t groups[] = {51U, 52U};
    const struct sucrune_project_owner owner = {
        .broker_uid=41U, .broker_gid=42U, .guest_uid=61U, .guest_gid=62U, .groups=groups, .group_count=2U
    };
    const struct {uint32_t uid, gid, mode; int executable;} cases[] = {
        {41U, 42U, 0100641U, 0}, {41U, 42U, 0100610U, 0}, {41U, 42U, 0100700U, 1},
        {31U, 42U, 0100001U, 0}, {31U, 42U, 0100010U, 1}, {31U, 52U, 0100001U, 0},
        {31U, 52U, 0100010U, 1}, {31U, 32U, 0100010U, 0}, {31U, 32U, 0100001U, 1},
        {41U, 42U, 0040700U, 0}
    };
    for (size_t i=0; i<sizeof(cases)/sizeof(cases[0]); i++) {
        struct sucrune_arm64_stat st={.uid=cases[i].uid, .gid=cases[i].gid, .mode=cases[i].mode};
        CHECK(sucrune_project_executable(&st,&owner)==cases[i].executable);
    }
}

static void shared_tool_copyup(const char *root) {
    const char *key = "0700-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char environments[2048], store[2048], blob[2048], marker[100];
    joined_path(environments, sizeof(environments), root, "environments");
    joined_path(store, sizeof(store), root, "shared-tools-v1");
    joined_path(blob, sizeof(blob), store, key);
    snprintf(marker, sizeof(marker), "sucrune:base:v1:%s", key);
    CHECK(mkdir(environments,0700)==0 && mkdir(store,0700)==0);
    CHECK(chmod(store,0700)==0);
    int body = open(blob, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0700);
    CHECK(body >= 0 && write(body, "package", 7) == 7 && fchmod(body,0700)==0);
    char env[2][2048], workspace[2][2048], link[2][2048];
    struct client client[2];
    for (unsigned i=0; i<2; ++i) {
        joined_path(env[i],sizeof(env[i]),environments,i?"b":"a");
        joined_path(workspace[i],sizeof(workspace[i]),env[i],"workspace");
        joined_path(link[i],sizeof(link[i]),workspace[i],"tool");
        CHECK(mkdir(env[i],0700)==0 && mkdir(workspace[i],0700)==0);
        CHECK(symlink(marker,link[i])==0);
        client[i].socket = sucrune_workspace_broker_profile(workspace[i], &client[i].done, 0, 0, SUCRUNE_WORKSPACE_LINUX);
        CHECK(client[i].socket >= 0);
    }
    int direct = -1;
    int64_t lower = open_read(client[0],"tool",O_RDONLY,&direct);
    CHECK(lower>=3 && direct>=0 && (fcntl(direct,F_GETFL) & O_ACCMODE)==O_RDONLY);
    struct stat direct_stat, blob_stat;
    CHECK(fstat(direct,&direct_stat)==0 && fstat(body,&blob_stat)==0 && direct_stat.st_ino==blob_stat.st_ino);
    CHECK(link_paths(client[0],lower,"",AT_FDCWD,"alias",AT_EMPTY_PATH)==-EOPNOTSUPP);
    CHECK(make_symlink(client[0],AT_FDCWD,marker,"forged")==-EPERM);
    struct sucrune_request map=request(SUCRUNE_BROKER_MAP_FILE);
    map.args[0]=lower; map.args[1]=1;
    struct sucrune_response response;
    int right=-1;
    CHECK(sucrune_broker_exchange(client[0].socket,&map,&response,&right,1000)==0);
    CHECK(response.result==-EACCES && right==-1);
    struct client restricted;
    restricted.socket=sucrune_workspace_broker_scoped(workspace[0],&restricted.done,0,0,SUCRUNE_WORKSPACE_LINUX,SUCRUNE_WRITE_PROJECT);
    CHECK(restricted.socket>=0 && path_operation(restricted,56,"tool",O_RDWR|O_TRUNC)==-EACCES);
    CHECK(path_operation(restricted,53,"tool",0600)==-EACCES);
    disconnect_broker(&restricted);
    struct client ll=landlock_client(workspace[0]);
    int64_t rules=ll_wire(ll,444,LL_ALL,8,0,0);
    CHECK(rules>=3 && ll_wire(ll,167,38,1,0,0)==0);
    add_path_rule(ll,rules,"tool",LL_READ_FILE|LL_EXECUTE);
    CHECK(ll_wire(ll,446,rules,0,0,0)==0);
    CHECK(path_operation(ll,SUCRUNE_BROKER_OPEN_EXEC,"tool",O_RDONLY)>=3);
    CHECK(path_operation(ll,56,"tool",O_WRONLY|O_TRUNC)==-EACCES);
    disconnect_broker(&ll);
    struct stat st;
    CHECK(lstat(link[0],&st)==0 && S_ISLNK(st.st_mode));
    CHECK(rename_path(client[0],"tool","moved")==0 && rename_path(client[0],"moved","tool")==0);
    ll=landlock_client(workspace[0]);
    rules=ll_wire(ll,444,LL_ALL,8,0,0);
    CHECK(rules>=3 && ll_wire(ll,167,38,1,0,0)==0);
    add_path_rule(ll,rules,"/",LL_ALL);
    CHECK(ll_wire(ll,446,rules,0,0,0)==0);
    int64_t writer=path_operation(ll,56,"tool",O_RDWR);
    CHECK(writer>=3 && write_file(ll,writer,"private")==7);
    disconnect_broker(&ll);
    CHECK(file_operation(client[0],52,lower,0777,0).result==-ESTALE);
    CHECK(set_times(client[0],lower,"",AT_EMPTY_PATH,NULL)==-ESTALE);
    CHECK(lstat(link[0],&st)==0 && S_ISREG(st.st_mode));
    CHECK(lstat(link[1],&st)==0 && S_ISLNK(st.st_mode));
    char bytes[8]={0};
    CHECK(pread(direct,bytes,7,0)==7 && !strcmp(bytes,"package") && close(direct)==0);
    int64_t sibling=path_operation(client[1],56,"tool",O_RDONLY);
    response=file_operation(client[1],63,sibling,7,0);
    CHECK(response.result==7 && !memcmp(response.data,"package",7));
    CHECK(rename_path(client[1],"tool","renamed")==0);
    CHECK(file_operation(client[1],52,sibling,0644,0).result==0);
    CHECK(set_times(client[1],sibling,"",AT_EMPTY_PATH,NULL)==0);
    CHECK(rename_path(client[1],"renamed","tool")==0);
    CHECK(path_operation(client[1],53,"tool",0600)==0);
    CHECK(lstat(link[1],&st)==0 && S_ISREG(st.st_mode) && (st.st_mode&0777)==0600);
    CHECK(fstat(body,&st)==0 && (st.st_mode&0777)==0700 && st.st_nlink==1);
    CHECK(pread(body,bytes,7,0)==7 && !strcmp(bytes,"package"));
    for (unsigned i=0;i<2;++i) {
        CHECK(path_operation(client[i],35,"tool",0)==0);
        disconnect_broker(&client[i]);
        CHECK(rmdir(workspace[i])==0 && rmdir(env[i])==0);
    }
    CHECK(close(body)==0 && unlink(blob)==0 && rmdir(store)==0 && rmdir(environments)==0);
    puts("PASS two workspace shared read FD, copy-up, scoped writes, metadata, mmap rights and immutable base");
}

int main(void) {
    guest_exec_mode_classes();
    const char *temporary_directory = getenv("TMPDIR");
    if (temporary_directory == NULL || temporary_directory[0] == '\0') temporary_directory = "/tmp";
    CHECK(temporary_directory[0] == '/');
    char temporary[2048];
    joined_path(temporary, sizeof(temporary), temporary_directory, "sucrune-broker-XXXXXX");
    char *root = mkdtemp(temporary);
    CHECK(root != NULL);
    shared_tool_copyup(root);
    char workspace[2048], outside[2048], sentinel[2048];
    joined_path(workspace, sizeof(workspace), root, "workspace");
    joined_path(outside, sizeof(outside), root, "outside");
    joined_path(sentinel, sizeof(sentinel), outside, "sentinel");
    CHECK(mkdir(workspace, 0700) == 0 && mkdir(outside, 0700) == 0);
    int host = open(sentinel, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(host >= 0 && write(host, "untouched", 9U) == 9 && close(host) == 0);
    path_boundaries(workspace, outside);
    preallocate_regular_file(workspace);
    shared_mapping_right(workspace);
    guest_volume_and_counters(workspace);
    optional_read_right(workspace);
    access_and_readlink_queries(workspace);
    distribution_symlinks(workspace);
    relative_directory_operations(workspace,outside);
    hard_link_publication(workspace,outside);
    path_permissions(workspace,outside);
    file_timestamps(workspace,outside);
    creation_modes(workspace);
    descriptor_permissions(workspace);
    file_lock_descriptions(workspace);
    files_and_descriptors(workspace);
    linux_file_capacity(workspace, SUCRUNE_WORKSPACE_LINUX);
    linux_file_capacity(workspace, SUCRUNE_WORKSPACE_BUILD);
    record_lock_ownership(workspace);
    append_status_flags(workspace);
    nonblocking_shared_descriptions(workspace);
    nonblocking_directory_and_special_files(workspace);
    positioned_file_io(workspace);
    sendfile_regular_files(workspace);
    bulk_regular_file_reads(workspace);
    bulk_regular_file_writes(workspace);
    exec_preserves_open_descriptions(workspace);
    rename_current_directory(workspace);
    malformed_messages(workspace);
    completion_drains_queued_file_operation(workspace);
    independent_brokers(workspace, outside);
    forked_session_semantics(workspace);
    scoped_writes(workspace);
    landlock_policy(workspace);
    mounted_tree(workspace,outside);
    trusted_image_metadata(workspace);
    char content[16];
    host = open(sentinel, O_RDONLY | O_CLOEXEC);
    CHECK(host >= 0 && read(host, content, sizeof(content)) == 9 && memcmp(content, "untouched", 9U) == 0);
    CHECK(close(host) == 0 && unlink(sentinel) == 0);
    char inode_store[2048];
    joined_path(inode_store,sizeof(inode_store),root,"workspace.sucrune-inodes-v1");
    CHECK(rmdir(inode_store)==0 || errno==ENOENT);
    CHECK(rmdir(outside) == 0 && rmdir(workspace) == 0 && rmdir(root) == 0);
    (void)puts("workspace broker boundaries, relative directory removal after rename, path chmod with mode 000 restoration and alias identity, access/readlink queries, pinned hard link publication and isolation, real flock conflict/shared/release, 64 resources, shared append/nonblock flags, directory reads, host nonblock safeguard, positioned IO, exec commit, rename and completion passed");
    (void)printf("Skipped subcases: %u (FIFO fixture creation is reported separately, never counted as a pass).\n", skipped_subcases);
    return 0;
}
