/**
 * Black Widow -- Generic Syscall Hooks
 * Tum binary tipleri icin genel syscall izleme.
 *
 * Hook edilen syscall'lar:
 *   open, read, write, close, connect, send, recv,
 *   mmap, dlopen, stat, access, unlink
 *
 * Her hook: send({ type: 'syscall', name: '...', args: [...], retval: ..., timestamp: ... })
 */

(function () {
    'use strict';

    function ts() {
        return Date.now();
    }

    function safeReadString(ptr) {
        try {
            if (ptr && !ptr.isNull()) {
                return ptr.readUtf8String();
            }
        } catch (e) {}
        return null;
    }

    var resolveExport = function (name) {
        try {
            var addr = Module.findExportByName(null, name);
            return addr;
        } catch (e) {
            return null;
        }
    };

    // ---------------------------------------------------------------
    // open()
    // ---------------------------------------------------------------
    var openAddr = resolveExport('open');
    if (openAddr) {
        Interceptor.attach(openAddr, {
            onEnter: function (args) {
                this._path = safeReadString(args[0]);
                this._flags = args[1].toInt32();
            },
            onLeave: function (retval) {
                if (this._path) {
                    send({
                        type: 'syscall',
                        name: 'open',
                        args: { path: this._path, flags: this._flags },
                        retval: retval.toInt32(),
                        timestamp: ts()
                    });
                }
            }
        });
    }

    // ---------------------------------------------------------------
    // read()
    // ---------------------------------------------------------------
    var readAddr = resolveExport('read');
    if (readAddr) {
        Interceptor.attach(readAddr, {
            onEnter: function (args) {
                this._fd = args[0].toInt32();
                this._count = args[2].toInt32();
            },
            onLeave: function (retval) {
                var n = retval.toInt32();
                if (n > 0) {
                    send({
                        type: 'syscall',
                        name: 'read',
                        args: { fd: this._fd, requested: this._count },
                        retval: n,
                        timestamp: ts()
                    });
                }
            }
        });
    }

    // ---------------------------------------------------------------
    // write()
    // ---------------------------------------------------------------
    var writeAddr = resolveExport('write');
    if (writeAddr) {
        Interceptor.attach(writeAddr, {
            onEnter: function (args) {
                this._fd = args[0].toInt32();
                this._count = args[2].toInt32();
            },
            onLeave: function (retval) {
                var n = retval.toInt32();
                // stdout/stderr filtrele
                if (n > 0 && this._fd > 2) {
                    send({
                        type: 'syscall',
                        name: 'write',
                        args: { fd: this._fd, requested: this._count },
                        retval: n,
                        timestamp: ts()
                    });
                }
            }
        });
    }

    // ---------------------------------------------------------------
    // close()
    // ---------------------------------------------------------------
    var closeAddr = resolveExport('close');
    if (closeAddr) {
        Interceptor.attach(closeAddr, {
            onEnter: function (args) {
                this._fd = args[0].toInt32();
            },
            onLeave: function (retval) {
                send({
                    type: 'syscall',
                    name: 'close',
                    args: { fd: this._fd },
                    retval: retval.toInt32(),
                    timestamp: ts()
                });
            }
        });
    }

    // ---------------------------------------------------------------
    // connect()
    // ---------------------------------------------------------------
    var connectAddr = resolveExport('connect');
    if (connectAddr) {
        Interceptor.attach(connectAddr, {
            onEnter: function (args) {
                this._fd = args[0].toInt32();
                try {
                    var sa = args[1];
                    var family = sa.readU16();
                    if (family === 2) {
                        // AF_INET
                        var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                        var ip = sa.add(4).readU8() + '.' +
                                 sa.add(5).readU8() + '.' +
                                 sa.add(6).readU8() + '.' +
                                 sa.add(7).readU8();
                        this._info = { family: 'AF_INET', ip: ip, port: port };
                    } else if (family === 30) {
                        // AF_INET6 (macOS)
                        this._info = { family: 'AF_INET6' };
                    } else if (family === 1) {
                        // AF_UNIX
                        var path = safeReadString(sa.add(2));
                        this._info = { family: 'AF_UNIX', path: path };
                    } else {
                        this._info = { family: family };
                    }
                } catch (e) {
                    this._info = { error: 'parse_failed' };
                }
            },
            onLeave: function (retval) {
                send({
                    type: 'syscall',
                    name: 'connect',
                    args: { fd: this._fd, addr: this._info },
                    retval: retval.toInt32(),
                    timestamp: ts()
                });
            }
        });
    }

    // ---------------------------------------------------------------
    // send()
    // ---------------------------------------------------------------
    var sendAddr = resolveExport('send');
    if (sendAddr) {
        Interceptor.attach(sendAddr, {
            onEnter: function (args) {
                this._fd = args[0].toInt32();
                this._len = args[2].toInt32();
            },
            onLeave: function (retval) {
                var n = retval.toInt32();
                if (n > 0) {
                    send({
                        type: 'syscall',
                        name: 'send',
                        args: { fd: this._fd, requested: this._len },
                        retval: n,
                        timestamp: ts()
                    });
                }
            }
        });
    }

    // ---------------------------------------------------------------
    // recv()
    // ---------------------------------------------------------------
    var recvAddr = resolveExport('recv');
    if (recvAddr) {
        Interceptor.attach(recvAddr, {
            onEnter: function (args) {
                this._fd = args[0].toInt32();
                this._len = args[2].toInt32();
            },
            onLeave: function (retval) {
                var n = retval.toInt32();
                if (n > 0) {
                    send({
                        type: 'syscall',
                        name: 'recv',
                        args: { fd: this._fd, requested: this._len },
                        retval: n,
                        timestamp: ts()
                    });
                }
            }
        });
    }

    // ---------------------------------------------------------------
    // mmap()
    // ---------------------------------------------------------------
    var mmapAddr = resolveExport('mmap');
    if (mmapAddr) {
        Interceptor.attach(mmapAddr, {
            onEnter: function (args) {
                this._len = args[1].toInt32();
                this._prot = args[2].toInt32();
                this._flags = args[3].toInt32();
                this._fd = args[4].toInt32();
            },
            onLeave: function (retval) {
                // Sadece buyuk mmap'leri raporla (>64KB)
                if (this._len > 65536) {
                    send({
                        type: 'syscall',
                        name: 'mmap',
                        args: {
                            length: this._len,
                            prot: this._prot,
                            flags: this._flags,
                            fd: this._fd
                        },
                        retval: retval.toString(),
                        timestamp: ts()
                    });
                }
            }
        });
    }

    // ---------------------------------------------------------------
    // dlopen()
    // ---------------------------------------------------------------
    var dlopenAddr = resolveExport('dlopen');
    if (dlopenAddr) {
        Interceptor.attach(dlopenAddr, {
            onEnter: function (args) {
                this._path = safeReadString(args[0]);
            },
            onLeave: function (retval) {
                if (this._path) {
                    send({
                        type: 'syscall',
                        name: 'dlopen',
                        args: { path: this._path },
                        retval: retval.toString(),
                        timestamp: ts()
                    });
                }
            }
        });
    }

    // ---------------------------------------------------------------
    // stat()
    // ---------------------------------------------------------------
    var statAddr = resolveExport('stat');
    if (statAddr) {
        Interceptor.attach(statAddr, {
            onEnter: function (args) {
                this._path = safeReadString(args[0]);
            },
            onLeave: function (retval) {
                if (this._path) {
                    send({
                        type: 'syscall',
                        name: 'stat',
                        args: { path: this._path },
                        retval: retval.toInt32(),
                        timestamp: ts()
                    });
                }
            }
        });
    }

    // ---------------------------------------------------------------
    // access()
    // ---------------------------------------------------------------
    var accessAddr = resolveExport('access');
    if (accessAddr) {
        Interceptor.attach(accessAddr, {
            onEnter: function (args) {
                this._path = safeReadString(args[0]);
                this._mode = args[1].toInt32();
            },
            onLeave: function (retval) {
                if (this._path) {
                    send({
                        type: 'syscall',
                        name: 'access',
                        args: { path: this._path, mode: this._mode },
                        retval: retval.toInt32(),
                        timestamp: ts()
                    });
                }
            }
        });
    }

    // ---------------------------------------------------------------
    // unlink() -- dosya silme
    // ---------------------------------------------------------------
    var unlinkAddr = resolveExport('unlink');
    if (unlinkAddr) {
        Interceptor.attach(unlinkAddr, {
            onEnter: function (args) {
                this._path = safeReadString(args[0]);
            },
            onLeave: function (retval) {
                if (this._path) {
                    send({
                        type: 'syscall',
                        name: 'unlink',
                        args: { path: this._path },
                        retval: retval.toInt32(),
                        timestamp: ts()
                    });
                }
            }
        });
    }

    // ---------------------------------------------------------------
    // Baslangic mesaji
    // ---------------------------------------------------------------
    send({
        type: 'hook_loaded',
        hook_name: 'generic_hooks',
        platform: Process.platform,
        arch: Process.arch,
        pid: Process.id,
        timestamp: ts()
    });

})();
