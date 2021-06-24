let threads = Process.enumerateThreads() // A bug that returns empty for the threads? Haven't seen it
threads.forEach(thread => {
    let entryObj = {}
    let exitObj = {}
    Stalker.follow(thread.id, {
        transform: function (iterator) {
            const instruction = iterator.next();
            let parseReturn = false
            do {
                if (parseReturn === true) { // This might not be the correct way to detect once a system call has finished...
                    parseReturn = false
                    iterator.putCallout((context) => {
                        exitObj = {
                            "context": context,
                            "syscall": {
                                "returnValue": context["x0"]
                            }
                        }
                        exitObj.tid = thread.id
                        send({onEnter: entryObj, onExit: exitObj})
                        entryObj = {}
                        exitObj = {}
                    })
                }
                if (instruction.mnemonic === "svc") { // OnEntry
                    iterator.putCallout((context) => {
                        const syscall = sysCallMap[context['x8']]

                        entryObj.syscall = {
                            name: syscall.name,
                            number: context['x8'],
                            arguments: parseParameters(syscall.arguments, context), // You can actually read the value of registers
                            // so if the syscall is open and you know the parameter is a cstring, then you can do context['x1'].readCString()
                        }
                        entryObj.context = context
                        entryObj.tid = thread.id

                    })
                    parseReturn = true
                }
                iterator.keep()
            } while (iterator.next() !== null)
        }
    });
})

function parseParameters(parameters, context) {
    let params = []
    for (const i in parameters) {
       parameters[i]['value'] = context[`x${i}`]
    }
    return parameters
}


let sysCallMap = {
    "0x0": {
        "name": "io_setup",
        "number": "0x0",
        "arguments": [{"type": "unsigned int", "arg": "nr_events"}, {"type": "aio_context_t *", "arg": "ctx_idp"}]
    },
    "0x1": {"name": "io_destroy", "number": "0x1", "arguments": [{"type": "aio_context_t", "arg": "ctx_id"}]},
    "0x2": {
        "name": "io_submit",
        "number": "0x2",
        "arguments": [{"type": "aio_context_t", "arg": "ctx_id"}, {
            "type": "long",
            "arg": "nr"
        }, {"type": "struct iocb **", "arg": "iocbpp"}]
    },
    "0x3": {
        "name": "io_cancel",
        "number": "0x3",
        "arguments": [{"type": "aio_context_t", "arg": "ctx_id"}, {
            "type": "struct iocb *",
            "arg": "iocb"
        }, {"type": "struct io_event *", "arg": "result"}]
    },
    "0x4": {
        "name": "io_getevents",
        "number": "0x4",
        "arguments": [{"type": "aio_context_t", "arg": "ctx_id"}, {"type": "long", "arg": "min_nr"}, {
            "type": "long",
            "arg": "nr"
        }, {"type": "struct io_event *", "arg": "events"}, {"type": "struct timespec *", "arg": "timeout"}]
    },
    "0x5": {
        "name": "setxattr",
        "number": "0x5",
        "arguments": [{"type": "const char *", "arg": "path"}, {
            "type": "const char *",
            "arg": "name"
        }, {"type": "const void *", "arg": "value"}, {"type": "size_t", "arg": "size"}, {"type": "int", "arg": "flags"}]
    },
    "0x6": {
        "name": "lsetxattr",
        "number": "0x6",
        "arguments": [{"type": "const char *", "arg": "path"}, {
            "type": "const char *",
            "arg": "name"
        }, {"type": "const void *", "arg": "value"}, {"type": "size_t", "arg": "size"}, {"type": "int", "arg": "flags"}]
    },
    "0x7": {
        "name": "fsetxattr",
        "number": "0x7",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "const char *", "arg": "name"}, {
            "type": "const void *",
            "arg": "value"
        }, {"type": "size_t", "arg": "size"}, {"type": "int", "arg": "flags"}]
    },
    "0x8": {
        "name": "getxattr",
        "number": "0x8",
        "arguments": [{"type": "const char *", "arg": "path"}, {
            "type": "const char *",
            "arg": "name"
        }, {"type": "void *", "arg": "value"}, {"type": "size_t", "arg": "size"}]
    },
    "0x9": {
        "name": "lgetxattr",
        "number": "0x9",
        "arguments": [{"type": "const char *", "arg": "path"}, {
            "type": "const char *",
            "arg": "name"
        }, {"type": "void *", "arg": "value"}, {"type": "size_t", "arg": "size"}]
    },
    "0xa": {
        "name": "fgetxattr",
        "number": "0xa",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "const char *", "arg": "name"}, {
            "type": "void *",
            "arg": "value"
        }, {"type": "size_t", "arg": "size"}]
    },
    "0xb": {
        "name": "listxattr",
        "number": "0xb",
        "arguments": [{"type": "const char *", "arg": "path"}, {"type": "char *", "arg": "list"}, {
            "type": "size_t",
            "arg": "size"
        }]
    },
    "0xc": {
        "name": "llistxattr",
        "number": "0xc",
        "arguments": [{"type": "const char *", "arg": "path"}, {"type": "char *", "arg": "list"}, {
            "type": "size_t",
            "arg": "size"
        }]
    },
    "0xd": {
        "name": "flistxattr",
        "number": "0xd",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "char *", "arg": "list"}, {
            "type": "size_t",
            "arg": "size"
        }]
    },
    "0xe": {
        "name": "removexattr",
        "number": "0xe",
        "arguments": [{"type": "const char *", "arg": "path"}, {"type": "const char *", "arg": "name"}]
    },
    "0xf": {
        "name": "lremovexattr",
        "number": "0xf",
        "arguments": [{"type": "const char *", "arg": "path"}, {"type": "const char *", "arg": "name"}]
    },
    "0x10": {
        "name": "fremovexattr",
        "number": "0x10",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "const char *", "arg": "name"}]
    },
    "0x11": {
        "name": "getcwd",
        "number": "0x11",
        "arguments": [{"type": "char *", "arg": "buf"}, {"type": "size_t", "arg": "size"}]
    },
    "0x12": {
        "name": "lookup_dcookie",
        "number": "0x12",
        "arguments": [{"type": "uint64_t", "arg": "cookie"}, {"type": "char *", "arg": "buffer"}, {
            "type": "size_t",
            "arg": "len"
        }]
    },
    "0x13": {"name": "eventfd2", "number": "0x13", "arguments": null},
    "0x14": {"name": "epoll_create1", "number": "0x14", "arguments": [{"type": "int", "arg": "flags"}]},
    "0x15": {
        "name": "epoll_ctl",
        "number": "0x15",
        "arguments": [{"type": "int", "arg": "epfd"}, {"type": "int", "arg": "op"}, {
            "type": "int",
            "arg": "fd"
        }, {"type": "struct epoll_event *", "arg": "event"}]
    },
    "0x16": {
        "name": "epoll_pwait",
        "number": "0x16",
        "arguments": [{"type": "int", "arg": "epfd"}, {"type": "struct epoll_event *", "arg": "events"}, {
            "type": "int",
            "arg": "maxevents"
        }, {"type": "int", "arg": "timeout"}, {"type": "const sigset_t *", "arg": "sigmask"}]
    },
    "0x17": {"name": "dup", "number": "0x17", "arguments": [{"type": "int", "arg": "oldfd"}]},
    "0x18": {
        "name": "dup3",
        "number": "0x18",
        "arguments": [{"type": "int", "arg": "oldfd"}, {"type": "int", "arg": "newfd"}, {"type": "int", "arg": "flags"}]
    },
    "0x19": {
        "name": "fcntl",
        "number": "0x19",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "int", "arg": "cmd"}]
    },
    "0x1a": {"name": "inotify_init1", "number": "0x1a", "arguments": [{"type": "int", "arg": "flags"}]},
    "0x1b": {
        "name": "inotify_add_watch",
        "number": "0x1b",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "const char *", "arg": "pathname"}, {
            "type": "uint32_t",
            "arg": "mask"
        }]
    },
    "0x1c": {
        "name": "inotify_rm_watch",
        "number": "0x1c",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "int", "arg": "wd"}]
    },
    "0x1d": {
        "name": "ioctl",
        "number": "0x1d",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "unsigned long", "arg": "request"}]
    },
    "0x1e": {
        "name": "ioprio_set",
        "number": "0x1e",
        "arguments": [{"type": "int", "arg": "which"}, {"type": "int", "arg": "who"}, {"type": "int", "arg": "ioprio"}]
    },
    "0x1f": {
        "name": "ioprio_get",
        "number": "0x1f",
        "arguments": [{"type": "int", "arg": "which"}, {"type": "int", "arg": "who"}]
    },
    "0x20": {
        "name": "flock",
        "number": "0x20",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "int", "arg": "operation"}]
    },
    "0x21": {
        "name": "mknodat",
        "number": "0x21",
        "arguments": [{"type": "int", "arg": "dirfd"}, {"type": "const char *", "arg": "pathname"}, {
            "type": "mode_t",
            "arg": "mode"
        }, {"type": "dev_t", "arg": "dev"}]
    },
    "0x22": {
        "name": "mkdirat",
        "number": "0x22",
        "arguments": [{"type": "int", "arg": "dirfd"}, {"type": "const char *", "arg": "pathname"}, {
            "type": "mode_t",
            "arg": "mode"
        }]
    },
    "0x23": {
        "name": "unlinkat",
        "number": "0x23",
        "arguments": [{"type": "int", "arg": "dirfd"}, {"type": "const char *", "arg": "pathname"}, {
            "type": "int",
            "arg": "flags"
        }]
    },
    "0x24": {
        "name": "symlinkat",
        "number": "0x24",
        "arguments": [{"type": "const char *", "arg": "target"}, {
            "type": "int",
            "arg": "newdirfd"
        }, {"type": "const char *", "arg": "linkpath"}]
    },
    "0x25": {
        "name": "linkat",
        "number": "0x25",
        "arguments": [{"type": "int", "arg": "olddirfd"}, {"type": "const char *", "arg": "oldpath"}, {
            "type": "int",
            "arg": "newdirfd"
        }, {"type": "const char *", "arg": "newpath"}, {"type": "int", "arg": "flags"}]
    },
    "0x26": {
        "name": "renameat",
        "number": "0x26",
        "arguments": [{"type": "int", "arg": "olddirfd"}, {"type": "const char *", "arg": "oldpath"}, {
            "type": "int",
            "arg": "newdirfd"
        }, {"type": "const char *", "arg": "newpath"}]
    },
    "0x27": {
        "name": "umount2",
        "number": "0x27",
        "arguments": [{"type": "const char *", "arg": "target"}, {"type": "int", "arg": "flags"}]
    },
    "0x28": {
        "name": "mount",
        "number": "0x28",
        "arguments": [{"type": "const char *", "arg": "source"}, {
            "type": "const char *",
            "arg": "target"
        }, {"type": "const char *", "arg": "filesystemtype"}, {
            "type": "unsigned long",
            "arg": "mountflags"
        }, {"type": "const void *", "arg": "data"}]
    },
    "0x29": {
        "name": "pivot_root",
        "number": "0x29",
        "arguments": [{"type": "const char *", "arg": "new_root"}, {"type": "const char *", "arg": "put_old"}]
    },
    "0x2a": {
        "name": "nfsservctl",
        "number": "0x2a",
        "arguments": [{"type": "int", "arg": "cmd"}, {
            "type": "struct nfsctl_arg *",
            "arg": "argp"
        }, {"type": "union nfsctl_res *", "arg": "resp"}]
    },
    "0x2b": {
        "name": "statfs",
        "number": "0x2b",
        "arguments": [{"type": "const char *", "arg": "path"}, {"type": "struct statfs *", "arg": "buf"}]
    },
    "0x2c": {
        "name": "fstatfs",
        "number": "0x2c",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "struct statfs *", "arg": "buf"}]
    },
    "0x2d": {
        "name": "truncate",
        "number": "0x2d",
        "arguments": [{"type": "const char *", "arg": "path"}, {"type": "off_t", "arg": "length"}]
    },
    "0x2e": {
        "name": "ftruncate",
        "number": "0x2e",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "off_t", "arg": "length"}]
    },
    "0x2f": {
        "name": "fallocate",
        "number": "0x2f",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "int", "arg": "mode"}, {
            "type": "off_t",
            "arg": "offset"
        }, {"type": "off_t", "arg": "len"}]
    },
    "0x30": {
        "name": "faccessat",
        "number": "0x30",
        "arguments": [{"type": "int", "arg": "dirfd"}, {"type": "const char *", "arg": "pathname"}, {
            "type": "int",
            "arg": "mode"
        }, {"type": "int", "arg": "flags"}]
    },
    "0x31": {"name": "chdir", "number": "0x31", "arguments": [{"type": "const char *", "arg": "path"}]},
    "0x32": {"name": "fchdir", "number": "0x32", "arguments": [{"type": "int", "arg": "fd"}]},
    "0x33": {"name": "chroot", "number": "0x33", "arguments": [{"type": "const char *", "arg": "path"}]},
    "0x34": {
        "name": "fchmod",
        "number": "0x34",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "mode_t", "arg": "mode"}]
    },
    "0x35": {
        "name": "fchmodat",
        "number": "0x35",
        "arguments": [{"type": "int", "arg": "dirfd"}, {"type": "const char *", "arg": "pathname"}, {
            "type": "mode_t",
            "arg": "mode"
        }, {"type": "int", "arg": "flags"}]
    },
    "0x36": {
        "name": "fchownat",
        "number": "0x36",
        "arguments": [{"type": "int", "arg": "dirfd"}, {"type": "const char *", "arg": "pathname"}, {
            "type": "uid_t",
            "arg": "owner"
        }, {"type": "gid_t", "arg": "group"}, {"type": "int", "arg": "flags"}]
    },
    "0x37": {
        "name": "fchown",
        "number": "0x37",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "uid_t", "arg": "owner"}, {
            "type": "gid_t",
            "arg": "group"
        }]
    },
    "0x38": {
        "name": "openat",
        "number": "0x38",
        "arguments": [{"type": "int", "arg": "dirfd"}, {"type": "const char *", "arg": "pathname"}, {
            "type": "int",
            "arg": "flags"
        }]
    },
    "0x39": {"name": "close", "number": "0x39", "arguments": [{"type": "int", "arg": "fd"}]},
    "0x3a": {"name": "vhangup", "number": "0x3a", "arguments": []},
    "0x3b": {"name": "pipe2", "number": "0x3b", "arguments": [{"type": "int pipefd[2], int", "arg": "flags"}]},
    "0x3c": {
        "name": "quotactl",
        "number": "0x3c",
        "arguments": [{"type": "int", "arg": "cmd"}, {"type": "const char *", "arg": "special"}, {
            "type": "int",
            "arg": "id"
        }, {"type": "caddr_t", "arg": "addr"}]
    },
    "0x3d": {
        "name": "getdents64",
        "number": "0x3d",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "void *", "arg": "dirp"}, {
            "type": "size_t",
            "arg": "count"
        }]
    },
    "0x3e": {
        "name": "lseek",
        "number": "0x3e",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "off_t", "arg": "offset"}, {
            "type": "int",
            "arg": "whence"
        }]
    },
    "0x3f": {
        "name": "read",
        "number": "0x3f",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "void *", "arg": "buf"}, {
            "type": "size_t",
            "arg": "count"
        }]
    },
    "0x40": {
        "name": "write",
        "number": "0x40",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "const void *", "arg": "buf"}, {
            "type": "size_t",
            "arg": "count"
        }]
    },
    "0x41": {
        "name": "readv",
        "number": "0x41",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "const struct iovec *", "arg": "iov"}, {
            "type": "int",
            "arg": "iovcnt"
        }]
    },
    "0x42": {
        "name": "writev",
        "number": "0x42",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "const struct iovec *", "arg": "iov"}, {
            "type": "int",
            "arg": "iovcnt"
        }]
    },
    "0x43": {"name": "pread64", "number": "0x43", "arguments": null},
    "0x44": {"name": "pwrite64", "number": "0x44", "arguments": null},
    "0x45": {
        "name": "preadv",
        "number": "0x45",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "const struct iovec *", "arg": "iov"}, {
            "type": "int",
            "arg": "iovcnt"
        }, {"type": "off_t", "arg": "offset"}]
    },
    "0x46": {
        "name": "pwritev",
        "number": "0x46",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "const struct iovec *", "arg": "iov"}, {
            "type": "int",
            "arg": "iovcnt"
        }, {"type": "off_t", "arg": "offset"}]
    },
    "0x47": {
        "name": "sendfile",
        "number": "0x47",
        "arguments": [{"type": "int", "arg": "out_fd"}, {"type": "int", "arg": "in_fd"}, {
            "type": "off_t *",
            "arg": "offset"
        }, {"type": "size_t", "arg": "count"}]
    },
    "0x48": {"name": "pselect6", "number": "0x48", "arguments": null},
    "0x49": {
        "name": "ppoll",
        "number": "0x49",
        "arguments": [{"type": "struct pollfd *", "arg": "fds"}, {
            "type": "nfds_t",
            "arg": "nfds"
        }, {"type": "const struct timespec *", "arg": "tmo_p"}, {"type": "const sigset_t *", "arg": "sigmask"}]
    },
    "0x4a": {"name": "signalfd4", "number": "0x4a", "arguments": null},
    "0x4b": {
        "name": "vmsplice",
        "number": "0x4b",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "const struct iovec *", "arg": "iov"}, {
            "type": "size_t",
            "arg": "nr_segs"
        }, {"type": "unsigned int", "arg": "flags"}]
    },
    "0x4c": {
        "name": "splice",
        "number": "0x4c",
        "arguments": [{"type": "int", "arg": "fd_in"}, {"type": "off64_t *", "arg": "off_in"}, {
            "type": "int",
            "arg": "fd_out"
        }, {"type": "off64_t *", "arg": "off_out"}, {"type": "size_t", "arg": "len"}, {
            "type": "unsigned int",
            "arg": "flags"
        }]
    },
    "0x4d": {
        "name": "tee",
        "number": "0x4d",
        "arguments": [{"type": "int", "arg": "fd_in"}, {"type": "int", "arg": "fd_out"}, {
            "type": "size_t",
            "arg": "len"
        }, {"type": "unsigned int", "arg": "flags"}]
    },
    "0x4e": {
        "name": "readlinkat",
        "number": "0x4e",
        "arguments": [{"type": "int", "arg": "dirfd"}, {
            "type": "const char *restrict",
            "arg": "pathname"
        }, {"type": "char *restrict", "arg": "buf"}, {"type": "size_t", "arg": "bufsiz"}]
    },
    "0x4f": {
        "name": "fstatat",
        "number": "0x4f",
        "arguments": [{"type": "int", "arg": "dirfd"}, {
            "type": "const char *restrict",
            "arg": "pathname"
        }, {"type": "struct stat *restrict", "arg": "statbuf"}, {"type": "int", "arg": "flags"}]
    },
    "0x50": {
        "name": "fstat",
        "number": "0x50",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "struct stat *", "arg": "statbuf"}]
    },
    "0x51": {"name": "sync", "number": "0x51", "arguments": []},
    "0x52": {"name": "fsync", "number": "0x52", "arguments": [{"type": "int", "arg": "fd"}]},
    "0x53": {"name": "fdatasync", "number": "0x53", "arguments": [{"type": "int", "arg": "fd"}]},
    "0x54": {
        "name": "sync_file_range",
        "number": "0x54",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "off64_t", "arg": "offset"}, {
            "type": "off64_t",
            "arg": "nbytes"
        }, {"type": "unsigned int", "arg": "flags"}]
    },
    "0x55": {
        "name": "timerfd_create",
        "number": "0x55",
        "arguments": [{"type": "int", "arg": "clockid"}, {"type": "int", "arg": "flags"}]
    },
    "0x56": {
        "name": "timerfd_settime",
        "number": "0x56",
        "arguments": [{"type": "int", "arg": "fd"}, {
            "type": "int",
            "arg": "flags"
        }, {"type": "const struct itimerspec *", "arg": "new_value"}, {
            "type": "struct itimerspec *",
            "arg": "old_value"
        }]
    },
    "0x57": {
        "name": "timerfd_gettime",
        "number": "0x57",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "struct itimerspec *", "arg": "curr_value"}]
    },
    "0x58": {
        "name": "utimensat",
        "number": "0x58",
        "arguments": [{"type": "int", "arg": "dirfd"}, {
            "type": "const char *",
            "arg": "pathname"
        }, {"type": "const struct timespec times[2], int", "arg": "flags"}]
    },
    "0x59": {"name": "acct", "number": "0x59", "arguments": [{"type": "const char *", "arg": "filename"}]},
    "0x5a": {
        "name": "capget",
        "number": "0x5a",
        "arguments": [{"type": "cap_user_header_t", "arg": "hdrp"}, {"type": "cap_user_data_t", "arg": "datap"}]
    },
    "0x5b": {
        "name": "capset",
        "number": "0x5b",
        "arguments": [{"type": "cap_user_header_t", "arg": "hdrp"}, {"type": "const cap_user_data_t", "arg": "datap"}]
    },
    "0x5c": {"name": "personality", "number": "0x5c", "arguments": [{"type": "unsigned long", "arg": "persona"}]},
    "0x5d": {"name": "exit", "number": "0x5d", "arguments": null},
    "0x5e": {"name": "exit_group", "number": "0x5e", "arguments": [{"type": "int", "arg": "status"}]},
    "0x5f": {
        "name": "waitid",
        "number": "0x5f",
        "arguments": [{"type": "idtype_t", "arg": "idtype"}, {"type": "id_t", "arg": "id"}, {
            "type": "siginfo_t *",
            "arg": "infop"
        }, {"type": "int", "arg": "options"}]
    },
    "0x60": {"name": "set_tid_address", "number": "0x60", "arguments": [{"type": "int *", "arg": "tidptr"}]},
    "0x61": {"name": "unshare", "number": "0x61", "arguments": [{"type": "int", "arg": "flags"}]},
    "0x62": {"name": "futex", "number": "0x62", "arguments": null},
    "0x63": {
        "name": "set_robust_list",
        "number": "0x63",
        "arguments": [{"type": "struct robust_list_head *", "arg": "head"}, {"type": "size_t", "arg": "len"}]
    },
    "0x64": {
        "name": "get_robust_list",
        "number": "0x64",
        "arguments": [{"type": "int", "arg": "pid"}, {
            "type": "struct robust_list_head **",
            "arg": "head_ptr"
        }, {"type": "size_t *", "arg": "len_ptr"}]
    },
    "0x65": {
        "name": "nanosleep",
        "number": "0x65",
        "arguments": [{"type": "const struct timespec *", "arg": "req"}, {"type": "struct timespec *", "arg": "rem"}]
    },
    "0x66": {
        "name": "getitimer",
        "number": "0x66",
        "arguments": [{"type": "int", "arg": "which"}, {"type": "struct itimerval *", "arg": "curr_value"}]
    },
    "0x67": {
        "name": "setitimer",
        "number": "0x67",
        "arguments": [{"type": "int", "arg": "which"}, {
            "type": "const struct itimerval *restrict",
            "arg": "new_value"
        }, {"type": "struct itimerval *restrict", "arg": "old_value"}]
    },
    "0x68": {
        "name": "kexec_load",
        "number": "0x68",
        "arguments": [{"type": "unsigned long", "arg": "entry"}, {
            "type": "unsigned long",
            "arg": "nr_segments"
        }, {"type": "struct kexec_segment *", "arg": "segments"}, {"type": "unsigned long", "arg": "flags"}]
    },
    "0x69": {
        "name": "init_module",
        "number": "0x69",
        "arguments": [{"type": "void *", "arg": "module_image"}, {
            "type": "unsigned long",
            "arg": "len"
        }, {"type": "const char *", "arg": "param_values"}]
    },
    "0x6a": {
        "name": "delete_module",
        "number": "0x6a",
        "arguments": [{"type": "const char *", "arg": "name"}, {"type": "unsigned int", "arg": "flags"}]
    },
    "0x6b": {
        "name": "timer_create",
        "number": "0x6b",
        "arguments": [{"type": "clockid_t", "arg": "clockid"}, {
            "type": "struct sigevent *restrict",
            "arg": "sevp"
        }, {"type": "timer_t *restrict", "arg": "timerid"}]
    },
    "0x6c": {
        "name": "timer_gettime",
        "number": "0x6c",
        "arguments": [{"type": "timer_t", "arg": "timerid"}, {"type": "struct itimerspec *", "arg": "curr_value"}]
    },
    "0x6d": {"name": "timer_getoverrun", "number": "0x6d", "arguments": [{"type": "timer_t", "arg": "timerid"}]},
    "0x6e": {
        "name": "timer_settime",
        "number": "0x6e",
        "arguments": [{"type": "timer_t", "arg": "timerid"}, {
            "type": "int",
            "arg": "flags"
        }, {"type": "const struct itimerspec *restrict", "arg": "new_value"}, {
            "type": "struct itimerspec *restrict",
            "arg": "old_value"
        }]
    },
    "0x6f": {"name": "timer_delete", "number": "0x6f", "arguments": [{"type": "timer_t", "arg": "timerid"}]},
    "0x70": {
        "name": "clock_settime",
        "number": "0x70",
        "arguments": [{"type": "clockid_t", "arg": "clockid"}, {"type": "const struct timespec *", "arg": "tp"}]
    },
    "0x71": {
        "name": "clock_gettime",
        "number": "0x71",
        "arguments": [{"type": "clockid_t", "arg": "clockid"}, {"type": "struct timespec *", "arg": "tp"}]
    },
    "0x72": {
        "name": "clock_getres",
        "number": "0x72",
        "arguments": [{"type": "clockid_t", "arg": "clockid"}, {"type": "struct timespec *", "arg": "res"}]
    },
    "0x73": {
        "name": "clock_nanosleep",
        "number": "0x73",
        "arguments": [{"type": "clockid_t", "arg": "clockid"}, {
            "type": "int",
            "arg": "flags"
        }, {"type": "const struct timespec *", "arg": "request"}, {"type": "struct timespec *", "arg": "remain"}]
    },
    "0x74": {
        "name": "syslog",
        "number": "0x74",
        "arguments": [{"type": "int", "arg": "type"}, {"type": "char *", "arg": "bufp"}, {"type": "int", "arg": "len"}]
    },
    "0x75": {
        "name": "ptrace",
        "number": "0x75",
        "arguments": [{"type": "enum __ptrace_request", "arg": "request"}, {
            "type": "pid_t",
            "arg": "pid"
        }, {"type": "void *", "arg": "addr"}, {"type": "void *", "arg": "data"}]
    },
    "0x76": {
        "name": "sched_setparam",
        "number": "0x76",
        "arguments": [{"type": "pid_t", "arg": "pid"}, {"type": "const struct sched_param *", "arg": "param"}]
    },
    "0x77": {
        "name": "sched_setscheduler",
        "number": "0x77",
        "arguments": [{"type": "pid_t", "arg": "pid"}, {
            "type": "int",
            "arg": "policy"
        }, {"type": "const struct sched_param *", "arg": "param"}]
    },
    "0x78": {"name": "sched_getscheduler", "number": "0x78", "arguments": [{"type": "pid_t", "arg": "pid"}]},
    "0x79": {
        "name": "sched_getparam",
        "number": "0x79",
        "arguments": [{"type": "pid_t", "arg": "pid"}, {"type": "struct sched_param *", "arg": "param"}]
    },
    "0x7a": {
        "name": "sched_setaffinity",
        "number": "0x7a",
        "arguments": [{"type": "pid_t", "arg": "pid"}, {
            "type": "size_t",
            "arg": "cpusetsize"
        }, {"type": "const cpu_set_t *", "arg": "mask"}]
    },
    "0x7b": {
        "name": "sched_getaffinity",
        "number": "0x7b",
        "arguments": [{"type": "pid_t", "arg": "pid"}, {"type": "size_t", "arg": "cpusetsize"}, {
            "type": "cpu_set_t *",
            "arg": "mask"
        }]
    },
    "0x7c": {"name": "sched_yield", "number": "0x7c", "arguments": []},
    "0x7d": {"name": "sched_get_priority_max", "number": "0x7d", "arguments": [{"type": "int", "arg": "policy"}]},
    "0x7e": {"name": "sched_get_priority_min", "number": "0x7e", "arguments": [{"type": "int", "arg": "policy"}]},
    "0x7f": {
        "name": "sched_rr_get_interval",
        "number": "0x7f",
        "arguments": [{"type": "pid_t", "arg": "pid"}, {"type": "struct timespec *", "arg": "tp"}]
    },
    "0x80": {"name": "restart_syscall", "number": "0x80", "arguments": []},
    "0x81": {
        "name": "kill",
        "number": "0x81",
        "arguments": [{"type": "pid_t", "arg": "pid"}, {"type": "int", "arg": "sig"}]
    },
    "0x82": {
        "name": "tkill",
        "number": "0x82",
        "arguments": [{"type": "pid_t", "arg": "tid"}, {"type": "int", "arg": "sig"}]
    },
    "0x83": {
        "name": "tgkill",
        "number": "0x83",
        "arguments": [{"type": "pid_t", "arg": "tgid"}, {"type": "pid_t", "arg": "tid"}, {"type": "int", "arg": "sig"}]
    },
    "0x84": {
        "name": "sigaltstack",
        "number": "0x84",
        "arguments": [{"type": "const stack_t *restrict", "arg": "ss"}, {"type": "stack_t *restrict", "arg": "old_ss"}]
    },
    "0x85": {"name": "rt_sigsuspend", "number": "0x85", "arguments": null},
    "0x86": {"name": "rt_sigaction", "number": "0x86", "arguments": null},
    "0x87": {
        "name": "rt_sigprocmask",
        "number": "0x87",
        "arguments": [{"type": "int", "arg": "how"}, {
            "type": "const kernel_sigset_t *",
            "arg": "set"
        }, {"type": "kernel_sigset_t *", "arg": "oldset"}, {"type": "size_t", "arg": "sigsetsize"}]
    },
    "0x88": {"name": "rt_sigpending", "number": "0x88", "arguments": null},
    "0x89": {"name": "rt_sigtimedwait", "number": "0x89", "arguments": null},
    "0x8a": {
        "name": "rt_sigqueueinfo",
        "number": "0x8a",
        "arguments": [{"type": "pid_t", "arg": "tgid"}, {"type": "int", "arg": "sig"}, {
            "type": "siginfo_t *",
            "arg": "info"
        }]
    },
    "0x8b": {"name": "rt_sigreturn", "number": "0x8b", "arguments": null},
    "0x8c": {
        "name": "setpriority",
        "number": "0x8c",
        "arguments": [{"type": "int", "arg": "which"}, {"type": "id_t", "arg": "who"}, {"type": "int", "arg": "prio"}]
    },
    "0x8d": {
        "name": "getpriority",
        "number": "0x8d",
        "arguments": [{"type": "int", "arg": "which"}, {"type": "id_t", "arg": "who"}]
    },
    "0x8e": {
        "name": "reboot",
        "number": "0x8e",
        "arguments": [{"type": "int", "arg": "magic"}, {"type": "int", "arg": "magic2"}, {
            "type": "int",
            "arg": "cmd"
        }, {"type": "void *", "arg": "arg"}]
    },
    "0x8f": {
        "name": "setregid",
        "number": "0x8f",
        "arguments": [{"type": "gid_t", "arg": "rgid"}, {"type": "gid_t", "arg": "egid"}]
    },
    "0x90": {"name": "setgid", "number": "0x90", "arguments": [{"type": "gid_t", "arg": "gid"}]},
    "0x91": {
        "name": "setreuid",
        "number": "0x91",
        "arguments": [{"type": "uid_t", "arg": "ruid"}, {"type": "uid_t", "arg": "euid"}]
    },
    "0x92": {"name": "setuid", "number": "0x92", "arguments": [{"type": "uid_t", "arg": "uid"}]},
    "0x93": {
        "name": "setresuid",
        "number": "0x93",
        "arguments": [{"type": "uid_t", "arg": "ruid"}, {"type": "uid_t", "arg": "euid"}, {
            "type": "uid_t",
            "arg": "suid"
        }]
    },
    "0x94": {
        "name": "getresuid",
        "number": "0x94",
        "arguments": [{"type": "uid_t *", "arg": "ruid"}, {"type": "uid_t *", "arg": "euid"}, {
            "type": "uid_t *",
            "arg": "suid"
        }]
    },
    "0x95": {
        "name": "setresgid",
        "number": "0x95",
        "arguments": [{"type": "gid_t", "arg": "rgid"}, {"type": "gid_t", "arg": "egid"}, {
            "type": "gid_t",
            "arg": "sgid"
        }]
    },
    "0x96": {
        "name": "getresgid",
        "number": "0x96",
        "arguments": [{"type": "gid_t *", "arg": "rgid"}, {"type": "gid_t *", "arg": "egid"}, {
            "type": "gid_t *",
            "arg": "sgid"
        }]
    },
    "0x97": {"name": "setfsuid", "number": "0x97", "arguments": [{"type": "uid_t", "arg": "fsuid"}]},
    "0x98": {"name": "setfsgid", "number": "0x98", "arguments": [{"type": "gid_t", "arg": "fsgid"}]},
    "0x99": {"name": "times", "number": "0x99", "arguments": [{"type": "struct tms *", "arg": "buf"}]},
    "0x9a": {
        "name": "setpgid",
        "number": "0x9a",
        "arguments": [{"type": "pid_t", "arg": "pid"}, {"type": "pid_t", "arg": "pgid"}]
    },
    "0x9b": {"name": "getpgid", "number": "0x9b", "arguments": [{"type": "pid_t", "arg": "pid"}]},
    "0x9c": {"name": "getsid", "number": "0x9c", "arguments": [{"type": "pid_t", "arg": "pid"}]},
    "0x9d": {"name": "setsid", "number": "0x9d", "arguments": []},
    "0x9e": {"name": "getgroups", "number": "0x9e", "arguments": [{"type": "int", "arg": "size"}]},
    "0x9f": {
        "name": "setgroups",
        "number": "0x9f",
        "arguments": [{"type": "size_t", "arg": "size"}, {"type": "const gid_t *", "arg": "list"}]
    },
    "0xa0": {"name": "uname", "number": "0xa0", "arguments": [{"type": "struct utsname *", "arg": "buf"}]},
    "0xa1": {
        "name": "sethostname",
        "number": "0xa1",
        "arguments": [{"type": "const char *", "arg": "name"}, {"type": "size_t", "arg": "len"}]
    },
    "0xa2": {
        "name": "setdomainname",
        "number": "0xa2",
        "arguments": [{"type": "const char *", "arg": "name"}, {"type": "size_t", "arg": "len"}]
    },
    "0xa3": {
        "name": "getrlimit",
        "number": "0xa3",
        "arguments": [{"type": "int", "arg": "resource"}, {"type": "struct rlimit *", "arg": "rlim"}]
    },
    "0xa4": {
        "name": "setrlimit",
        "number": "0xa4",
        "arguments": [{"type": "int", "arg": "resource"}, {"type": "const struct rlimit *", "arg": "rlim"}]
    },
    "0xa5": {
        "name": "getrusage",
        "number": "0xa5",
        "arguments": [{"type": "int", "arg": "who"}, {"type": "struct rusage *", "arg": "usage"}]
    },
    "0xa6": {"name": "umask", "number": "0xa6", "arguments": [{"type": "mode_t", "arg": "mask"}]},
    "0xa7": {
        "name": "prctl",
        "number": "0xa7",
        "arguments": [{"type": "int", "arg": "option"}, {
            "type": "unsigned long",
            "arg": "arg2"
        }, {"type": "unsigned long", "arg": "arg3"}, {"type": "unsigned long", "arg": "arg4"}, {
            "type": "unsigned long",
            "arg": "arg5"
        }]
    },
    "0xa8": {
        "name": "getcpu",
        "number": "0xa8",
        "arguments": [{"type": "unsigned int *", "arg": "cpu"}, {"type": "unsigned int *", "arg": "node"}]
    },
    "0xa9": {
        "name": "gettimeofday",
        "number": "0xa9",
        "arguments": [{"type": "struct timeval *restrict", "arg": "tv"}, {
            "type": "struct timezone *restrict",
            "arg": "tz"
        }]
    },
    "0xaa": {
        "name": "settimeofday",
        "number": "0xaa",
        "arguments": [{"type": "const struct timeval *", "arg": "tv"}, {"type": "const struct timezone *", "arg": "tz"}]
    },
    "0xab": {"name": "adjtimex", "number": "0xab", "arguments": [{"type": "struct timex *", "arg": "buf"}]},
    "0xac": {"name": "getpid", "number": "0xac", "arguments": []},
    "0xad": {"name": "getppid", "number": "0xad", "arguments": []},
    "0xae": {"name": "getuid", "number": "0xae", "arguments": []},
    "0xaf": {"name": "geteuid", "number": "0xaf", "arguments": []},
    "0xb0": {"name": "getgid", "number": "0xb0", "arguments": []},
    "0xb1": {"name": "getegid", "number": "0xb1", "arguments": []},
    "0xb2": {"name": "gettid", "number": "0xb2", "arguments": []},
    "0xb3": {"name": "sysinfo", "number": "0xb3", "arguments": [{"type": "struct sysinfo *", "arg": "info"}]},
    "0xb4": {
        "name": "mq_open",
        "number": "0xb4",
        "arguments": [{"type": "const char *", "arg": "name"}, {"type": "int", "arg": "oflag"}]
    },
    "0xb5": {"name": "mq_unlink", "number": "0xb5", "arguments": [{"type": "const char *", "arg": "name"}]},
    "0xb6": {
        "name": "mq_timedsend",
        "number": "0xb6",
        "arguments": [{"type": "mqd_t", "arg": "mqdes"}, {"type": "const char *", "arg": "msg_ptr"}, {
            "type": "size_t",
            "arg": "msg_len"
        }, {"type": "unsigned int", "arg": "msg_prio"}, {"type": "const struct timespec *", "arg": "abs_timeout"}]
    },
    "0xb7": {
        "name": "mq_timedreceive",
        "number": "0xb7",
        "arguments": [{"type": "mqd_t", "arg": "mqdes"}, {
            "type": "char *restrict",
            "arg": "msg_ptr"
        }, {"type": "size_t", "arg": "msg_len"}, {
            "type": "unsigned int *restrict",
            "arg": "msg_prio"
        }, {"type": "const struct timespec *restrict", "arg": "abs_timeout"}]
    },
    "0xb8": {
        "name": "mq_notify",
        "number": "0xb8",
        "arguments": [{"type": "mqd_t", "arg": "mqdes"}, {"type": "const struct sigevent *", "arg": "sevp"}]
    },
    "0xb9": {
        "name": "mq_getsetattr",
        "number": "0xb9",
        "arguments": [{"type": "mqd_t", "arg": "mqdes"}, {
            "type": "const struct mq_attr *",
            "arg": "newattr"
        }, {"type": "struct mq_attr *", "arg": "oldattr"}]
    },
    "0xba": {
        "name": "msgget",
        "number": "0xba",
        "arguments": [{"type": "key_t", "arg": "key"}, {"type": "int", "arg": "msgflg"}]
    },
    "0xbb": {
        "name": "msgctl",
        "number": "0xbb",
        "arguments": [{"type": "int", "arg": "msqid"}, {"type": "int", "arg": "cmd"}, {
            "type": "struct msqid_ds *",
            "arg": "buf"
        }]
    },
    "0xbc": {
        "name": "msgrcv",
        "number": "0xbc",
        "arguments": [{"type": "int", "arg": "msqid"}, {"type": "void *", "arg": "msgp"}, {
            "type": "size_t",
            "arg": "msgsz"
        }, {"type": "long", "arg": "msgtyp"}, {"type": "int", "arg": "msgflg"}]
    },
    "0xbd": {
        "name": "msgsnd",
        "number": "0xbd",
        "arguments": [{"type": "int", "arg": "msqid"}, {"type": "const void *", "arg": "msgp"}, {
            "type": "size_t",
            "arg": "msgsz"
        }, {"type": "int", "arg": "msgflg"}]
    },
    "0xbe": {
        "name": "semget",
        "number": "0xbe",
        "arguments": [{"type": "key_t", "arg": "key"}, {"type": "int", "arg": "nsems"}, {
            "type": "int",
            "arg": "semflg"
        }]
    },
    "0xbf": {
        "name": "semctl",
        "number": "0xbf",
        "arguments": [{"type": "int", "arg": "semid"}, {"type": "int", "arg": "semnum"}, {"type": "int", "arg": "cmd"}]
    },
    "0xc0": {
        "name": "semtimedop",
        "number": "0xc0",
        "arguments": [{"type": "int", "arg": "semid"}, {"type": "struct sembuf *", "arg": "sops"}, {
            "type": "size_t",
            "arg": "nsops"
        }, {"type": "const struct timespec *", "arg": "timeout"}]
    },
    "0xc1": {
        "name": "semop",
        "number": "0xc1",
        "arguments": [{"type": "int", "arg": "semid"}, {"type": "struct sembuf *", "arg": "sops"}, {
            "type": "size_t",
            "arg": "nsops"
        }]
    },
    "0xc2": {
        "name": "shmget",
        "number": "0xc2",
        "arguments": [{"type": "key_t", "arg": "key"}, {"type": "size_t", "arg": "size"}, {
            "type": "int",
            "arg": "shmflg"
        }]
    },
    "0xc3": {
        "name": "shmctl",
        "number": "0xc3",
        "arguments": [{"type": "int", "arg": "shmid"}, {"type": "int", "arg": "cmd"}, {
            "type": "struct shmid_ds *",
            "arg": "buf"
        }]
    },
    "0xc4": {
        "name": "shmat",
        "number": "0xc4",
        "arguments": [{"type": "int", "arg": "shmid"}, {"type": "const void *", "arg": "shmaddr"}, {
            "type": "int",
            "arg": "shmflg"
        }]
    },
    "0xc5": {"name": "shmdt", "number": "0xc5", "arguments": [{"type": "const void *", "arg": "shmaddr"}]},
    "0xc6": {
        "name": "socket",
        "number": "0xc6",
        "arguments": [{"type": "int", "arg": "domain"}, {"type": "int", "arg": "type"}, {
            "type": "int",
            "arg": "protocol"
        }]
    },
    "0xc7": {
        "name": "socketpair",
        "number": "0xc7",
        "arguments": [{"type": "int", "arg": "domain"}, {"type": "int", "arg": "type"}, {
            "type": "int",
            "arg": "protocol"
        }]
    },
    "0xc8": {
        "name": "bind",
        "number": "0xc8",
        "arguments": [{"type": "int", "arg": "sockfd"}, {
            "type": "const struct sockaddr *",
            "arg": "addr"
        }, {"type": "socklen_t", "arg": "addrlen"}]
    },
    "0xc9": {
        "name": "listen",
        "number": "0xc9",
        "arguments": [{"type": "int", "arg": "sockfd"}, {"type": "int", "arg": "backlog"}]
    },
    "0xca": {
        "name": "accept",
        "number": "0xca",
        "arguments": [{"type": "int", "arg": "sockfd"}, {
            "type": "struct sockaddr *restrict",
            "arg": "addr"
        }, {"type": "socklen_t *restrict", "arg": "addrlen"}]
    },
    "0xcb": {
        "name": "connect",
        "number": "0xcb",
        "arguments": [{"type": "int", "arg": "sockfd"}, {
            "type": "const struct sockaddr *",
            "arg": "addr"
        }, {"type": "socklen_t", "arg": "addrlen"}]
    },
    "0xcc": {
        "name": "getsockname",
        "number": "0xcc",
        "arguments": [{"type": "int", "arg": "sockfd"}, {
            "type": "struct sockaddr *restrict",
            "arg": "addr"
        }, {"type": "socklen_t *restrict", "arg": "addrlen"}]
    },
    "0xcd": {
        "name": "getpeername",
        "number": "0xcd",
        "arguments": [{"type": "int", "arg": "sockfd"}, {
            "type": "struct sockaddr *restrict",
            "arg": "addr"
        }, {"type": "socklen_t *restrict", "arg": "addrlen"}]
    },
    "0xce": {
        "name": "sendto",
        "number": "0xce",
        "arguments": [{"type": "int", "arg": "sockfd"}, {"type": "const void *", "arg": "buf"}, {
            "type": "size_t",
            "arg": "len"
        }, {"type": "int", "arg": "flags"}, {
            "type": "const struct sockaddr *",
            "arg": "dest_addr"
        }, {"type": "socklen_t", "arg": "addrlen"}]
    },
    "0xcf": {
        "name": "recvfrom",
        "number": "0xcf",
        "arguments": [{"type": "int", "arg": "sockfd"}, {"type": "void *restrict", "arg": "buf"}, {
            "type": "size_t",
            "arg": "len"
        }, {"type": "int", "arg": "flags"}, {
            "type": "struct sockaddr *restrict",
            "arg": "src_addr"
        }, {"type": "socklen_t *restrict", "arg": "addrlen"}]
    },
    "0xd0": {
        "name": "setsockopt",
        "number": "0xd0",
        "arguments": [{"type": "int", "arg": "sockfd"}, {"type": "int", "arg": "level"}, {
            "type": "int",
            "arg": "optname"
        }, {"type": "const void *", "arg": "optval"}, {"type": "socklen_t", "arg": "optlen"}]
    },
    "0xd1": {
        "name": "getsockopt",
        "number": "0xd1",
        "arguments": [{"type": "int", "arg": "sockfd"}, {"type": "int", "arg": "level"}, {
            "type": "int",
            "arg": "optname"
        }, {"type": "void *restrict", "arg": "optval"}, {"type": "socklen_t *restrict", "arg": "optlen"}]
    },
    "0xd2": {
        "name": "shutdown",
        "number": "0xd2",
        "arguments": [{"type": "int", "arg": "sockfd"}, {"type": "int", "arg": "how"}]
    },
    "0xd3": {
        "name": "sendmsg",
        "number": "0xd3",
        "arguments": [{"type": "int", "arg": "sockfd"}, {"type": "const struct msghdr *", "arg": "msg"}, {
            "type": "int",
            "arg": "flags"
        }]
    },
    "0xd4": {
        "name": "recvmsg",
        "number": "0xd4",
        "arguments": [{"type": "int", "arg": "sockfd"}, {"type": "struct msghdr *", "arg": "msg"}, {
            "type": "int",
            "arg": "flags"
        }]
    },
    "0xd5": {
        "name": "readahead",
        "number": "0xd5",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "off64_t", "arg": "offset"}, {
            "type": "size_t",
            "arg": "count"
        }]
    },
    "0xd6": {"name": "brk", "number": "0xd6", "arguments": [{"type": "void *", "arg": "addr"}]},
    "0xd7": {
        "name": "munmap",
        "number": "0xd7",
        "arguments": [{"type": "void *", "arg": "addr"}, {"type": "size_t", "arg": "length"}]
    },
    "0xd8": {
        "name": "mremap",
        "number": "0xd8",
        "arguments": [{"type": "void *", "arg": "old_address"}, {
            "type": "size_t",
            "arg": "old_size"
        }, {"type": "size_t", "arg": "new_size"}, {"type": "int", "arg": "flags"}]
    },
    "0xd9": {
        "name": "add_key",
        "number": "0xd9",
        "arguments": [{"type": "const char *", "arg": "type"}, {
            "type": "const char *",
            "arg": "description"
        }, {"type": "const void *", "arg": "payload"}, {"type": "size_t", "arg": "plen"}, {
            "type": "key_serial_t",
            "arg": "keyring"
        }]
    },
    "0xda": {
        "name": "request_key",
        "number": "0xda",
        "arguments": [{"type": "const char *", "arg": "type"}, {
            "type": "const char *",
            "arg": "description"
        }, {"type": "const char *", "arg": "callout_info"}, {"type": "key_serial_t", "arg": "dest_keyring"}]
    },
    "0xdb": {"name": "keyctl", "number": "0xdb", "arguments": [{"type": "int", "arg": "operation"}]},
    "0xdc": {"name": "clone", "number": "0xdc", "arguments": null},
    "0xdd": {"name": "execve", "number": "0xdd", "arguments": [{"type": "const char *", "arg": "pathname"}]},
    "0xde": {
        "name": "mmap",
        "number": "0xde",
        "arguments": [{"type": "void *", "arg": "addr"}, {"type": "size_t", "arg": "length"}, {
            "type": "int",
            "arg": "prot"
        }, {"type": "int", "arg": "flags"}, {"type": "int", "arg": "fd"}, {"type": "off_t", "arg": "offset"}]
    },
    "0xdf": {"name": "fadvise64", "number": "0xdf", "arguments": null},
    "0xe0": {
        "name": "swapon",
        "number": "0xe0",
        "arguments": [{"type": "const char *", "arg": "path"}, {"type": "int", "arg": "swapflags"}]
    },
    "0xe1": {"name": "swapoff", "number": "0xe1", "arguments": [{"type": "const char *", "arg": "path"}]},
    "0xe2": {
        "name": "mprotect",
        "number": "0xe2",
        "arguments": [{"type": "void *", "arg": "addr"}, {"type": "size_t", "arg": "len"}, {
            "type": "int",
            "arg": "prot"
        }]
    },
    "0xe3": {
        "name": "msync",
        "number": "0xe3",
        "arguments": [{"type": "void *", "arg": "addr"}, {"type": "size_t", "arg": "length"}, {
            "type": "int",
            "arg": "flags"
        }]
    },
    "0xe4": {
        "name": "mlock",
        "number": "0xe4",
        "arguments": [{"type": "const void *", "arg": "addr"}, {"type": "size_t", "arg": "len"}]
    },
    "0xe5": {
        "name": "munlock",
        "number": "0xe5",
        "arguments": [{"type": "const void *", "arg": "addr"}, {"type": "size_t", "arg": "len"}]
    },
    "0xe6": {"name": "mlockall", "number": "0xe6", "arguments": [{"type": "int", "arg": "flags"}]},
    "0xe7": {"name": "munlockall", "number": "0xe7", "arguments": []},
    "0xe8": {
        "name": "mincore",
        "number": "0xe8",
        "arguments": [{"type": "void *", "arg": "addr"}, {
            "type": "size_t",
            "arg": "length"
        }, {"type": "unsigned char *", "arg": "vec"}]
    },
    "0xe9": {
        "name": "madvise",
        "number": "0xe9",
        "arguments": [{"type": "void *", "arg": "addr"}, {"type": "size_t", "arg": "length"}, {
            "type": "int",
            "arg": "advice"
        }]
    },
    "0xea": {
        "name": "remap_file_pages",
        "number": "0xea",
        "arguments": [{"type": "void *", "arg": "addr"}, {"type": "size_t", "arg": "size"}, {
            "type": "int",
            "arg": "prot"
        }, {"type": "size_t", "arg": "pgoff"}, {"type": "int", "arg": "flags"}]
    },
    "0xeb": {
        "name": "mbind",
        "number": "0xeb",
        "arguments": [{"type": "void *", "arg": "addr"}, {"type": "unsigned long", "arg": "len"}, {
            "type": "int",
            "arg": "mode"
        }, {"type": "const unsigned long *", "arg": "nodemask"}, {
            "type": "unsigned long",
            "arg": "maxnode"
        }, {"type": "unsigned int", "arg": "flags"}]
    },
    "0xec": {
        "name": "get_mempolicy",
        "number": "0xec",
        "arguments": [{"type": "int *", "arg": "mode"}, {
            "type": "unsigned long *",
            "arg": "nodemask"
        }, {"type": "unsigned long", "arg": "maxnode"}, {"type": "void *", "arg": "addr"}, {
            "type": "unsigned long",
            "arg": "flags"
        }]
    },
    "0xed": {
        "name": "set_mempolicy",
        "number": "0xed",
        "arguments": [{"type": "int", "arg": "mode"}, {
            "type": "const unsigned long *",
            "arg": "nodemask"
        }, {"type": "unsigned long", "arg": "maxnode"}]
    },
    "0xee": {
        "name": "migrate_pages",
        "number": "0xee",
        "arguments": [{"type": "int", "arg": "pid"}, {
            "type": "unsigned long",
            "arg": "maxnode"
        }, {"type": "const unsigned long *", "arg": "old_nodes"}, {"type": "const unsigned long *", "arg": "new_nodes"}]
    },
    "0xef": {
        "name": "move_pages",
        "number": "0xef",
        "arguments": [{"type": "int", "arg": "pid"}, {"type": "unsigned long", "arg": "count"}, {
            "type": "void **",
            "arg": "pages"
        }, {"type": "const int *", "arg": "nodes"}, {"type": "int *", "arg": "status"}, {"type": "int", "arg": "flags"}]
    },
    "0xf0": {
        "name": "rt_tgsigqueueinfo",
        "number": "0xf0",
        "arguments": [{"type": "pid_t", "arg": "tgid"}, {"type": "pid_t", "arg": "tid"}, {
            "type": "int",
            "arg": "sig"
        }, {"type": "siginfo_t *", "arg": "info"}]
    },
    "0xf1": {
        "name": "perf_event_open",
        "number": "0xf1",
        "arguments": [{"type": "struct perf_event_attr *", "arg": "attr"}, {
            "type": "pid_t",
            "arg": "pid"
        }, {"type": "int", "arg": "cpu"}, {"type": "int", "arg": "group_fd"}, {"type": "unsigned long", "arg": "flags"}]
    },
    "0xf2": {
        "name": "accept4",
        "number": "0xf2",
        "arguments": [{"type": "int", "arg": "sockfd"}, {
            "type": "struct sockaddr *restrict",
            "arg": "addr"
        }, {"type": "socklen_t *restrict", "arg": "addrlen"}, {"type": "int", "arg": "flags"}]
    },
    "0xf3": {
        "name": "recvmmsg",
        "number": "0xf3",
        "arguments": [{"type": "int", "arg": "sockfd"}, {
            "type": "struct mmsghdr *",
            "arg": "msgvec"
        }, {"type": "unsigned int", "arg": "vlen"}, {"type": "int", "arg": "flags"}, {
            "type": "struct timespec *",
            "arg": "timeout"
        }]
    },
    "0xf4": {"name": "arch_specific_syscall", "number": "0xf4", "arguments": null},
    "0x104": {
        "name": "wait4",
        "number": "0x104",
        "arguments": [{"type": "pid_t", "arg": "pid"}, {"type": "int *", "arg": "wstatus"}, {
            "type": "int",
            "arg": "options"
        }, {"type": "struct rusage *", "arg": "rusage"}]
    },
    "0x105": {"name": "prlimit64", "number": "0x105", "arguments": null},
    "0x106": {
        "name": "fanotify_init",
        "number": "0x106",
        "arguments": [{"type": "unsigned int", "arg": "flags"}, {"type": "unsigned int", "arg": "event_f_flags"}]
    },
    "0x107": {
        "name": "fanotify_mark",
        "number": "0x107",
        "arguments": [{"type": "int", "arg": "fanotify_fd"}, {
            "type": "unsigned int",
            "arg": "flags"
        }, {"type": "uint64_t", "arg": "mask"}, {"type": "int", "arg": "dirfd"}, {
            "type": "const char *",
            "arg": "pathname"
        }]
    },
    "0x10a": {
        "name": "clock_adjtime",
        "number": "0x10a",
        "arguments": [{"type": "clockid_t", "arg": "clk_id"}, {"type": "struct timex *", "arg": "buf"}]
    },
    "0x10b": {"name": "syncfs", "number": "0x10b", "arguments": [{"type": "int", "arg": "fd"}]},
    "0x10c": {
        "name": "setns",
        "number": "0x10c",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "int", "arg": "nstype"}]
    },
    "0x10d": {
        "name": "sendmmsg",
        "number": "0x10d",
        "arguments": [{"type": "int", "arg": "sockfd"}, {
            "type": "struct mmsghdr *",
            "arg": "msgvec"
        }, {"type": "unsigned int", "arg": "vlen"}, {"type": "int", "arg": "flags"}]
    },
    "0x10e": {
        "name": "process_vm_readv",
        "number": "0x10e",
        "arguments": [{"type": "pid_t", "arg": "pid"}, {
            "type": "const struct iovec *",
            "arg": "local_iov"
        }, {"type": "unsigned long", "arg": "liovcnt"}, {
            "type": "const struct iovec *",
            "arg": "remote_iov"
        }, {"type": "unsigned long", "arg": "riovcnt"}, {"type": "unsigned long", "arg": "flags"}]
    },
    "0x10f": {
        "name": "process_vm_writev",
        "number": "0x10f",
        "arguments": [{"type": "pid_t", "arg": "pid"}, {
            "type": "const struct iovec *",
            "arg": "local_iov"
        }, {"type": "unsigned long", "arg": "liovcnt"}, {
            "type": "const struct iovec *",
            "arg": "remote_iov"
        }, {"type": "unsigned long", "arg": "riovcnt"}, {"type": "unsigned long", "arg": "flags"}]
    },
    "0x110": {
        "name": "kcmp",
        "number": "0x110",
        "arguments": [{"type": "pid_t", "arg": "pid1"}, {"type": "pid_t", "arg": "pid2"}, {
            "type": "int",
            "arg": "type"
        }, {"type": "unsigned long", "arg": "idx1"}, {"type": "unsigned long", "arg": "idx2"}]
    },
    "0x111": {
        "name": "finit_module",
        "number": "0x111",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "const char *", "arg": "param_values"}, {
            "type": "int",
            "arg": "flags"
        }]
    },
    "0x112": {
        "name": "sched_setattr",
        "number": "0x112",
        "arguments": [{"type": "pid_t", "arg": "pid"}, {
            "type": "struct sched_attr *",
            "arg": "attr"
        }, {"type": "unsigned int", "arg": "flags"}]
    },
    "0x113": {
        "name": "sched_getattr",
        "number": "0x113",
        "arguments": [{"type": "pid_t", "arg": "pid"}, {
            "type": "struct sched_attr *",
            "arg": "attr"
        }, {"type": "unsigned int", "arg": "size"}, {"type": "unsigned int", "arg": "flags"}]
    },
    "0x114": {
        "name": "renameat2",
        "number": "0x114",
        "arguments": [{"type": "int", "arg": "olddirfd"}, {"type": "const char *", "arg": "oldpath"}, {
            "type": "int",
            "arg": "newdirfd"
        }, {"type": "const char *", "arg": "newpath"}, {"type": "unsigned int", "arg": "flags"}]
    },
    "0x115": {
        "name": "seccomp",
        "number": "0x115",
        "arguments": [{"type": "unsigned int", "arg": "operation"}, {
            "type": "unsigned int",
            "arg": "flags"
        }, {"type": "void *", "arg": "args"}]
    },
    "0x116": {
        "name": "getrandom",
        "number": "0x116",
        "arguments": [{"type": "void *", "arg": "buf"}, {"type": "size_t", "arg": "buflen"}, {
            "type": "unsigned int",
            "arg": "flags"
        }]
    },
    "0x117": {
        "name": "memfd_create",
        "number": "0x117",
        "arguments": [{"type": "const char *", "arg": "name"}, {"type": "unsigned int", "arg": "flags"}]
    },
    "0x118": {
        "name": "bpf",
        "number": "0x118",
        "arguments": [{"type": "int", "arg": "cmd"}, {
            "type": "union bpf_attr *",
            "arg": "attr"
        }, {"type": "unsigned int", "arg": "size"}]
    },
    "0x119": {
        "name": "execveat",
        "number": "0x119",
        "arguments": [{"type": "int", "arg": "dirfd"}, {"type": "const char *", "arg": "pathname"}, {
            "type": "int",
            "arg": "flags"
        }]
    },
    "0x11a": {"name": "userfaultfd", "number": "0x11a", "arguments": [{"type": "int", "arg": "flags"}]},
    "0x11b": {
        "name": "membarrier",
        "number": "0x11b",
        "arguments": [{"type": "int", "arg": "cmd"}, {"type": "unsigned int", "arg": "flags"}, {
            "type": "int",
            "arg": "cpu_id"
        }]
    },
    "0x11c": {
        "name": "mlock2",
        "number": "0x11c",
        "arguments": [{"type": "const void *", "arg": "addr"}, {
            "type": "size_t",
            "arg": "len"
        }, {"type": "unsigned int", "arg": "flags"}]
    },
    "0x11d": {
        "name": "copy_file_range",
        "number": "0x11d",
        "arguments": [{"type": "int", "arg": "fd_in"}, {"type": "off64_t *", "arg": "off_in"}, {
            "type": "int",
            "arg": "fd_out"
        }, {"type": "off64_t *", "arg": "off_out"}, {"type": "size_t", "arg": "len"}, {
            "type": "unsigned int",
            "arg": "flags"
        }]
    },
    "0x11e": {
        "name": "preadv2",
        "number": "0x11e",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "const struct iovec *", "arg": "iov"}, {
            "type": "int",
            "arg": "iovcnt"
        }, {"type": "off_t", "arg": "offset"}, {"type": "int", "arg": "flags"}]
    },
    "0x11f": {
        "name": "pwritev2",
        "number": "0x11f",
        "arguments": [{"type": "int", "arg": "fd"}, {"type": "const struct iovec *", "arg": "iov"}, {
            "type": "int",
            "arg": "iovcnt"
        }, {"type": "off_t", "arg": "offset"}, {"type": "int", "arg": "flags"}]
    },
    "0x120": {
        "name": "pkey_mprotect",
        "number": "0x120",
        "arguments": [{"type": "void *", "arg": "addr"}, {"type": "size_t", "arg": "len"}, {
            "type": "int",
            "arg": "prot"
        }, {"type": "int", "arg": "pkey"}]
    },
    "0x121": {
        "name": "pkey_alloc",
        "number": "0x121",
        "arguments": [{"type": "unsigned int", "arg": "flags"}, {"type": "unsigned int", "arg": "access_rights"}]
    },
    "0x122": {"name": "pkey_free", "number": "0x122", "arguments": [{"type": "int", "arg": "pkey"}]},
    "0x123": {
        "name": "statx",
        "number": "0x123",
        "arguments": [{"type": "int", "arg": "dirfd"}, {
            "type": "const char *restrict",
            "arg": "pathname"
        }, {"type": "int", "arg": "flags"}, {"type": "unsigned int", "arg": "mask"}, {
            "type": "struct statx *restrict",
            "arg": "statxbuf"
        }]
    },
    "0x124": {"name": "io_pgetevents", "number": "0x124", "arguments": null},
    "0x125": {"name": "rseq", "number": "0x125", "arguments": null},
    "0x126": {
        "name": "kexec_file_load",
        "number": "0x126",
        "arguments": [{"type": "int", "arg": "kernel_fd"}, {
            "type": "int",
            "arg": "initrd_fd"
        }, {"type": "unsigned long", "arg": "cmdline_len"}, {
            "type": "const char *",
            "arg": "cmdline"
        }, {"type": "unsigned long", "arg": "flags"}]
    },
    "0x193": {"name": "clock_gettime64", "number": "0x193", "arguments": null},
    "0x194": {"name": "clock_settime64", "number": "0x194", "arguments": null},
    "0x195": {"name": "clock_adjtime64", "number": "0x195", "arguments": null},
    "0x196": {"name": "clock_getres_time64", "number": "0x196", "arguments": null},
    "0x197": {"name": "clock_nanosleep_time64", "number": "0x197", "arguments": null},
    "0x198": {"name": "timer_gettime64", "number": "0x198", "arguments": null},
    "0x199": {"name": "timer_settime64", "number": "0x199", "arguments": null},
    "0x19a": {"name": "timerfd_gettime64", "number": "0x19a", "arguments": null},
    "0x19b": {"name": "timerfd_settime64", "number": "0x19b", "arguments": null},
    "0x19c": {"name": "utimensat_time64", "number": "0x19c", "arguments": null},
    "0x19d": {"name": "pselect6_time64", "number": "0x19d", "arguments": null},
    "0x19e": {"name": "ppoll_time64", "number": "0x19e", "arguments": null},
    "0x1a0": {"name": "io_pgetevents_time64", "number": "0x1a0", "arguments": null},
    "0x1a1": {"name": "recvmmsg_time64", "number": "0x1a1", "arguments": null},
    "0x1a2": {"name": "mq_timedsend_time64", "number": "0x1a2", "arguments": null},
    "0x1a3": {"name": "mq_timedreceive_time64", "number": "0x1a3", "arguments": null},
    "0x1a4": {"name": "semtimedop_time64", "number": "0x1a4", "arguments": null},
    "0x1a5": {"name": "rt_sigtimedwait_time64", "number": "0x1a5", "arguments": null},
    "0x1a6": {"name": "futex_time64", "number": "0x1a6", "arguments": null},
    "0x1a7": {"name": "sched_rr_get_interval_time64", "number": "0x1a7", "arguments": null},
    "0x1a8": {
        "name": "pidfd_send_signal",
        "number": "0x1a8",
        "arguments": [{"type": "int", "arg": "pidfd"}, {"type": "int", "arg": "sig"}, {
            "type": "siginfo_t *",
            "arg": "info"
        }, {"type": "unsigned int", "arg": "flags"}]
    },
    "0x1a9": {
        "name": "io_uring_setup",
        "number": "0x1a9",
        "arguments": [{"type": "u32", "arg": "entries"}, {"type": "struct io_uring_params *", "arg": "p"}]
    },
    "0x1aa": {
        "name": "io_uring_enter",
        "number": "0x1aa",
        "arguments": [{"type": "unsigned int", "arg": "fd"}, {
            "type": "unsigned int",
            "arg": "to_submit"
        }, {"type": "unsigned int", "arg": "min_complete"}, {
            "type": "unsigned int",
            "arg": "flags"
        }, {"type": "sigset_t *", "arg": "sig"}]
    },
    "0x1ab": {
        "name": "io_uring_register",
        "number": "0x1ab",
        "arguments": [{"type": "unsigned int", "arg": "fd"}, {
            "type": "unsigned int",
            "arg": "opcode"
        }, {"type": "void *", "arg": "arg"}, {"type": "unsigned int", "arg": "nr_args"}]
    },
    "0x1ac": {"name": "open_tree", "number": "0x1ac", "arguments": null},
    "0x1ad": {"name": "move_mount", "number": "0x1ad", "arguments": null},
    "0x1ae": {"name": "fsopen", "number": "0x1ae", "arguments": null},
    "0x1af": {"name": "fsconfig", "number": "0x1af", "arguments": null},
    "0x1b0": {"name": "fsmount", "number": "0x1b0", "arguments": null},
    "0x1b1": {"name": "fspick", "number": "0x1b1", "arguments": null},
    "0x1b2": {
        "name": "pidfd_open",
        "number": "0x1b2",
        "arguments": [{"type": "pid_t", "arg": "pid"}, {"type": "unsigned int", "arg": "flags"}]
    },
    "0x1b3": {
        "name": "clone3",
        "number": "0x1b3",
        "arguments": [{"type": "struct clone_args *", "arg": "cl_args"}, {"type": "size_t", "arg": "size"}]
    },
    "0x1b4": {
        "name": "close_range",
        "number": "0x1b4",
        "arguments": [{"type": "unsigned int", "arg": "first"}, {
            "type": "unsigned int",
            "arg": "last"
        }, {"type": "unsigned int", "arg": "flags"}]
    },
    "0x1b5": {
        "name": "openat2",
        "number": "0x1b5",
        "arguments": [{"type": "int", "arg": "dirfd"}, {
            "type": "const char *",
            "arg": "pathname"
        }, {"type": "struct open_how *", "arg": "how"}, {"type": "size_t", "arg": "size"}]
    },
    "0x1b6": {
        "name": "pidfd_getfd",
        "number": "0x1b6",
        "arguments": [{"type": "int", "arg": "pidfd"}, {"type": "int", "arg": "targetfd"}, {
            "type": "unsigned int",
            "arg": "flags"
        }]
    },
    "0x1b7": {
        "name": "faccessat2",
        "number": "0x1b7",
        "arguments": [{"type": "int", "arg": "dirfd"}, {"type": "const char *", "arg": "pathname"}, {
            "type": "int",
            "arg": "mode"
        }, {"type": "int", "arg": "flags"}]
    },
    "0x1b8": {
        "name": "process_madvise",
        "number": "0x1b8",
        "arguments": [{"type": "int", "arg": "pidfd"}, {
            "type": "const struct iovec *",
            "arg": "iovec"
        }, {"type": "size_t", "arg": "vlen"}, {"type": "int", "arg": "advice"}, {
            "type": "unsigned int",
            "arg": "flags"
        }]
    },
    "0x1b9": {
        "name": "epoll_pwait2",
        "number": "0x1b9",
        "arguments": [{"type": "int", "arg": "epfd"}, {"type": "struct epoll_event *", "arg": "events"}, {
            "type": "int",
            "arg": "maxevents"
        }, {"type": "const struct timespec *", "arg": "timeout"}, {"type": "const sigset_t *", "arg": "sigmask"}]
    },
    "0x1ba": {"name": "mount_setattr", "number": "0x1ba", "arguments": null},
    "0x1bc": {"name": "landlock_create_ruleset", "number": "0x1bc", "arguments": null},
    "0x1bd": {"name": "landlock_add_rule", "number": "0x1bd", "arguments": null},
    "0x1be": {"name": "landlock_restrict_self", "number": "0x1be", "arguments": null},
    "0x1bf": {"name": "syscalls", "number": "0x1bf", "arguments": null}
}
