/**
 * Black Widow -- Node.js Runtime Hooks
 * Frida ile Node.js process'e inject edilir.
 *
 * Hook edilen alanlar:
 *   - require() -- modul yuklemeleri
 *   - fs (readFileSync, writeFileSync, readFile, writeFile, openSync, statSync)
 *   - http/https.request -- API cagrilari
 *   - child_process (execSync, spawn, fork, exec)
 *   - crypto (createHash, createCipheriv, createDecipheriv)
 *   - process.env erisimleri
 *
 * Tum mesajlar send() ile gonderilir (console.log degil).
 * Her mesaj: { type, ..., timestamp }
 */

(function () {
    'use strict';

    // ---------------------------------------------------------------
    // Yardimci: Zaman damgasi
    // ---------------------------------------------------------------
    function ts() {
        return Date.now();
    }

    // ---------------------------------------------------------------
    // require() hooklari -- hangi moduller yukleniyor?
    // ---------------------------------------------------------------

    // Node.js 'Module._load' uzerinden require'i yakala
    var Module = null;
    try {
        Module = Process.getModuleByName('node');
    } catch (e) {
        // node modulu bulunamadi -- bazi ortamlarda farkli isim olabilir
    }

    // require() icin native hook -- Module._resolveFilename uzerinden
    // Bu basit bir yaklasim: open() syscall'ini izleyerek .js/.json dosyalarini yakala
    // (Node.js internals'a girmeye gerek yok)

    // ---------------------------------------------------------------
    // File System Hooks
    // ---------------------------------------------------------------

    // open() -- dosya acma syscall'i
    var openPtr = Module ? Module.findExportByName('open') : null;
    if (!openPtr) {
        try { openPtr = Module ? null : null; } catch(e) {}
    }
    // Fallback: libc'den open
    if (!openPtr) {
        try { openPtr = Module ? Module.findExportByName(null, 'open') : null; } catch(e) {}
    }

    var nativeOpen = new NativeFunction(
        Module ? Module.findExportByName(null, 'open') || ptr(0) : ptr(0),
        'int', ['pointer', 'int', 'int']
    );

    Interceptor.attach(Module ? Module.findExportByName(null, 'open') || ptr(0) : ptr(0), {
        onEnter: function (args) {
            try {
                this._path = args[0].readUtf8String();
            } catch (e) {
                this._path = null;
            }
        },
        onLeave: function (retval) {
            if (this._path) {
                var p = this._path;
                // Sadece ilgili dosyalari raporla (noise azaltma)
                if (p.indexOf('.js') !== -1 || p.indexOf('.json') !== -1 ||
                    p.indexOf('.ts') !== -1 || p.indexOf('.env') !== -1 ||
                    p.indexOf('node_modules') !== -1 || p.indexOf('.pem') !== -1 ||
                    p.indexOf('.key') !== -1 || p.indexOf('.cert') !== -1) {
                    send({
                        type: 'fs_open',
                        path: p,
                        fd: retval.toInt32(),
                        timestamp: ts()
                    });
                }
            }
        }
    });

    // read() syscall
    Interceptor.attach(Module ? Module.findExportByName(null, 'read') || ptr(0) : ptr(0), {
        onEnter: function (args) {
            this._fd = args[0].toInt32();
            this._buf = args[1];
            this._size = args[2].toInt32();
        },
        onLeave: function (retval) {
            var bytesRead = retval.toInt32();
            if (bytesRead > 0 && this._size > 64) {
                send({
                    type: 'fs_read',
                    fd: this._fd,
                    bytes_read: bytesRead,
                    timestamp: ts()
                });
            }
        }
    });

    // write() syscall
    Interceptor.attach(Module ? Module.findExportByName(null, 'write') || ptr(0) : ptr(0), {
        onEnter: function (args) {
            this._fd = args[0].toInt32();
            this._size = args[2].toInt32();
        },
        onLeave: function (retval) {
            var bytesWritten = retval.toInt32();
            // stdout(1) ve stderr(2) haric
            if (bytesWritten > 0 && this._fd > 2) {
                send({
                    type: 'fs_write',
                    fd: this._fd,
                    bytes_written: bytesWritten,
                    timestamp: ts()
                });
            }
        }
    });

    // stat() -- dosya bilgi sorgulama
    Interceptor.attach(Module ? Module.findExportByName(null, 'stat') || ptr(0) : ptr(0), {
        onEnter: function (args) {
            try {
                this._path = args[0].readUtf8String();
            } catch (e) {
                this._path = null;
            }
        },
        onLeave: function (retval) {
            if (this._path && retval.toInt32() === 0) {
                send({
                    type: 'fs_stat',
                    path: this._path,
                    timestamp: ts()
                });
            }
        }
    });

    // ---------------------------------------------------------------
    // Network Hooks
    // ---------------------------------------------------------------

    // connect() -- TCP/UDP baglanti
    Interceptor.attach(Module ? Module.findExportByName(null, 'connect') || ptr(0) : ptr(0), {
        onEnter: function (args) {
            this._sockfd = args[0].toInt32();
            try {
                var sockaddr = args[1];
                var family = sockaddr.readU16();
                if (family === 2) {
                    // AF_INET
                    var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                    var ip = sockaddr.add(4).readU8() + '.' +
                             sockaddr.add(5).readU8() + '.' +
                             sockaddr.add(6).readU8() + '.' +
                             sockaddr.add(7).readU8();
                    this._host = ip;
                    this._port = port;
                } else {
                    this._host = 'unknown';
                    this._port = 0;
                }
            } catch (e) {
                this._host = 'parse_error';
                this._port = 0;
            }
        },
        onLeave: function (retval) {
            if (this._host && this._host !== 'unknown') {
                send({
                    type: 'net_connect',
                    host: this._host,
                    port: this._port,
                    fd: this._sockfd,
                    result: retval.toInt32(),
                    timestamp: ts()
                });
            }
        }
    });

    // send() -- veri gonderme
    Interceptor.attach(Module ? Module.findExportByName(null, 'send') || ptr(0) : ptr(0), {
        onEnter: function (args) {
            this._fd = args[0].toInt32();
            this._size = args[2].toInt32();
        },
        onLeave: function (retval) {
            var sent = retval.toInt32();
            if (sent > 0) {
                send({
                    type: 'net_send',
                    fd: this._fd,
                    bytes_sent: sent,
                    timestamp: ts()
                });
            }
        }
    });

    // recv() -- veri alma
    Interceptor.attach(Module ? Module.findExportByName(null, 'recv') || ptr(0) : ptr(0), {
        onEnter: function (args) {
            this._fd = args[0].toInt32();
        },
        onLeave: function (retval) {
            var received = retval.toInt32();
            if (received > 0) {
                send({
                    type: 'net_recv',
                    fd: this._fd,
                    bytes_received: received,
                    timestamp: ts()
                });
            }
        }
    });

    // ---------------------------------------------------------------
    // Process Hooks
    // ---------------------------------------------------------------

    // execve() -- program calistirma
    var execvePtr = Module ? Module.findExportByName(null, 'execve') : null;
    if (execvePtr) {
        Interceptor.attach(execvePtr, {
            onEnter: function (args) {
                try {
                    var cmd = args[0].readUtf8String();
                    send({
                        type: 'process_exec',
                        command: cmd,
                        timestamp: ts()
                    });
                } catch (e) {}
            }
        });
    }

    // posix_spawn() -- process olusturma (macOS)
    var posixSpawnPtr = Module ? Module.findExportByName(null, 'posix_spawn') : null;
    if (posixSpawnPtr) {
        Interceptor.attach(posixSpawnPtr, {
            onEnter: function (args) {
                try {
                    var cmd = args[1].readUtf8String();
                    send({
                        type: 'process_spawn',
                        command: cmd,
                        timestamp: ts()
                    });
                } catch (e) {}
            }
        });
    }

    // fork()
    var forkPtr = Module ? Module.findExportByName(null, 'fork') : null;
    if (forkPtr) {
        Interceptor.attach(forkPtr, {
            onLeave: function (retval) {
                send({
                    type: 'process_fork',
                    child_pid: retval.toInt32(),
                    timestamp: ts()
                });
            }
        });
    }

    // ---------------------------------------------------------------
    // Crypto -- dlopen/dlsym ile CommonCrypto veya OpenSSL izleme
    // ---------------------------------------------------------------

    // dlopen() -- dinamik kutuphane yukleme (crypto library tespiti)
    var dlopenPtr = Module ? Module.findExportByName(null, 'dlopen') : null;
    if (dlopenPtr) {
        Interceptor.attach(dlopenPtr, {
            onEnter: function (args) {
                try {
                    this._lib = args[0].readUtf8String();
                } catch (e) {
                    this._lib = null;
                }
            },
            onLeave: function (retval) {
                if (this._lib) {
                    send({
                        type: 'crypto_dlopen',
                        library: this._lib,
                        handle: retval.toString(),
                        timestamp: ts()
                    });
                }
            }
        });
    }

    // CCCrypt (CommonCrypto) -- macOS sifreleme
    try {
        var ccCryptPtr = Module ? Module.findExportByName('libcommonCrypto.dylib', 'CCCrypt') : null;
        if (!ccCryptPtr) {
            ccCryptPtr = Module ? Module.findExportByName(null, 'CCCrypt') : null;
        }
        if (ccCryptPtr) {
            Interceptor.attach(ccCryptPtr, {
                onEnter: function (args) {
                    var op = args[0].toInt32();
                    var alg = args[1].toInt32();
                    var algNames = {0: 'AES', 1: 'DES', 2: '3DES', 3: 'CAST', 4: 'RC4', 5: 'RC2', 6: 'Blowfish'};
                    send({
                        type: op === 0 ? 'crypto_encrypt' : 'crypto_decrypt',
                        algorithm: algNames[alg] || 'unknown_' + alg,
                        key_length: args[4].toInt32(),
                        data_length: args[6].toInt32(),
                        timestamp: ts()
                    });
                }
            });
        }
    } catch (e) {
        // CommonCrypto mevcut degil
    }

    // CC_SHA256 -- hash
    try {
        var sha256Ptr = Module ? Module.findExportByName(null, 'CC_SHA256') : null;
        if (sha256Ptr) {
            Interceptor.attach(sha256Ptr, {
                onEnter: function (args) {
                    send({
                        type: 'crypto_hash',
                        algorithm: 'SHA256',
                        data_length: args[1].toInt32(),
                        timestamp: ts()
                    });
                }
            });
        }
    } catch (e) {}

    // ---------------------------------------------------------------
    // process.env erisimleri -- getenv()
    // ---------------------------------------------------------------
    var getenvPtr = Module ? Module.findExportByName(null, 'getenv') : null;
    if (getenvPtr) {
        Interceptor.attach(getenvPtr, {
            onEnter: function (args) {
                try {
                    this._name = args[0].readUtf8String();
                } catch (e) {
                    this._name = null;
                }
            },
            onLeave: function (retval) {
                if (this._name) {
                    var val = null;
                    try {
                        if (!retval.isNull()) {
                            val = retval.readUtf8String();
                            // Hassas degerleri maskele
                            if (this._name.toLowerCase().indexOf('key') !== -1 ||
                                this._name.toLowerCase().indexOf('secret') !== -1 ||
                                this._name.toLowerCase().indexOf('token') !== -1 ||
                                this._name.toLowerCase().indexOf('password') !== -1) {
                                val = val.substring(0, 4) + '***MASKED***';
                            }
                        }
                    } catch (e) {}
                    send({
                        type: 'env_access',
                        name: this._name,
                        value: val,
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
        hook_name: 'nodejs_hooks',
        platform: Process.platform,
        arch: Process.arch,
        pid: Process.id,
        timestamp: ts()
    });

})();
