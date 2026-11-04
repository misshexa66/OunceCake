#ifndef NS2_FTP_NATIVE_H
#define NS2_FTP_NATIVE_H
#define FTP_MAX_CLIENTS 12
#define TAR_OUTPUT_BYTES 0x40000
#define NODE_TAR 2u
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;
typedef struct {u8 length, family; u16 port; u32 address; u8 zero[8];} Address;
typedef struct {int fd; short events, revents;} PollFd;
typedef struct {
    int (*socket)(int, int, int);
    int (*bind)(int, const Address *, u32);
    int (*listen)(int, int);
    int (*accept)(int, Address *, u32 *);
    s64 (*recv)(int, void *, u64, int);
    s64 (*send)(int, const void *, u64, int);
    int (*close)(int);
    int (*poll)(PollFd *, u64, int);
    int (*sockname)(int, Address *, u32 *);
    int (*fcntl)(int, int, ...);
    int (*get_errno)(void);
    u32 (*ipc)(void *, u64, u32);
    u32 (*close_handle)(u32);
    int (*thread_create)(u64 *, void *, void *(*)(void *), void *);
    int (*thread_join)(u64, void **);
} FtpFunctions;
// kinds: 0 = held storage, 1 = held filesystem, 2 = storage by path, 3 = filesystem by path
typedef struct {
    u32 handle; u8 kind, attributes, proxy_type, reserved;
    union {u64 size; u64 program_id;};
} Source;
typedef struct {
    u32 parent, child, next, type, name_offset, name_length, mount, source_path;
    u64 offset, size;
} Node;
// struct for tar file handling. 
typedef struct {
    u64 start, size, offset;
    u32 name_offset, name_length, prefix_offset, prefix_length;
    u32 source_path, pax_offset, pax_bytes, directory;
    u64 end;
} TarMember;
typedef struct FtpConfigTag {
    u64 magic;
    u32 version;
    volatile u32 stop, state, result;
    u32 port, reserved;
    volatile u64 sent, files, native_result;
    u8 ip[4]; u32 phase;
    FtpFunctions *functions;
    const u8 *index; u64 index_bytes;
    const Source *sources; u64 source_count;
    u8 *data; u64 data_bytes;
    u8 *ipc_buffer;
    u64 output_bytes;
    u8 reserved_config[88]; // padding to align with layout from ftp.cjs
    volatile u32 io_lock; u32 padding;
    u8 *slots; u64 slot_bytes;
    struct FtpConfigTag *owner;
} FtpConfig;
_Static_assert(sizeof(Address) == 16 && sizeof(PollFd) == 8 && sizeof(Node) == 48, "wire ABI");
_Static_assert(sizeof(Source) == 16, "source ABI");
_Static_assert(sizeof(TarMember) == 64, "tar member ABI");
_Static_assert(__builtin_offsetof(FtpConfig, functions) == 64 && sizeof(FtpConfig) == 256, "configuration ABI");
_Static_assert(__builtin_offsetof(FtpConfig, output_bytes) == 128 &&
    __builtin_offsetof(FtpConfig, io_lock) == 224 && __builtin_offsetof(FtpConfig, slots) == 232, "buffer ABI");
void *ftp_main(void *configuration);
#endif
