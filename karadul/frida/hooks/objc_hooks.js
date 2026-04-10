/**
 * Black Widow -- Objective-C Method Hooks
 * macOS native uygulamalar icin ObjC runtime hooklari.
 *
 * Hook edilen siniflar/metodlar:
 *   - NSURLSession: dataTaskWithURL:, dataTaskWithRequest:
 *   - NSFileManager: contentsOfDirectoryAtPath:, fileExistsAtPath:,
 *                    contentsAtPath:, createFileAtPath:
 *   - NSUserDefaults: objectForKey:, setObject:forKey:,
 *                     stringForKey:, boolForKey:
 *   - SecKeyCreateSignature (Security framework)
 *   - NSBundle: pathForResource:ofType:
 *   - NSProcessInfo: environment
 *
 * Tum mesajlar send() ile gonderilir.
 */

(function () {
    'use strict';

    // ObjC runtime kontrolu
    if (!ObjC.available) {
        send({
            type: 'hook_error',
            hook_name: 'objc_hooks',
            error: 'Objective-C runtime mevcut degil',
            timestamp: Date.now()
        });
        return;
    }

    function ts() {
        return Date.now();
    }

    // ---------------------------------------------------------------
    // NSURLSession -- Network istekleri
    // ---------------------------------------------------------------

    // dataTaskWithURL:completionHandler:
    try {
        var NSURLSession = ObjC.classes.NSURLSession;
        if (NSURLSession) {
            // dataTaskWithRequest:completionHandler:
            var dataTaskWithRequest = NSURLSession['- dataTaskWithRequest:completionHandler:'];
            if (dataTaskWithRequest) {
                Interceptor.attach(dataTaskWithRequest.implementation, {
                    onEnter: function (args) {
                        var request = new ObjC.Object(args[2]);
                        try {
                            var url = request.URL().absoluteString().toString();
                            var method = request.HTTPMethod().toString();
                            var headers = {};
                            try {
                                var allHeaders = request.allHTTPHeaderFields();
                                if (allHeaders) {
                                    var keys = allHeaders.allKeys();
                                    for (var i = 0; i < keys.count(); i++) {
                                        var key = keys.objectAtIndex_(i).toString();
                                        // Hassas header'lari maskele
                                        var val = allHeaders.objectForKey_(keys.objectAtIndex_(i)).toString();
                                        if (key.toLowerCase().indexOf('auth') !== -1 ||
                                            key.toLowerCase().indexOf('token') !== -1 ||
                                            key.toLowerCase().indexOf('cookie') !== -1) {
                                            val = val.substring(0, 8) + '***MASKED***';
                                        }
                                        headers[key] = val;
                                    }
                                }
                            } catch (e) {}

                            send({
                                type: 'net_request',
                                url: url,
                                method: method,
                                headers: headers,
                                timestamp: ts()
                            });
                        } catch (e) {}
                    }
                });
            }

            // dataTaskWithURL:completionHandler:
            var dataTaskWithURL = NSURLSession['- dataTaskWithURL:completionHandler:'];
            if (dataTaskWithURL) {
                Interceptor.attach(dataTaskWithURL.implementation, {
                    onEnter: function (args) {
                        try {
                            var url = new ObjC.Object(args[2]);
                            send({
                                type: 'net_request',
                                url: url.absoluteString().toString(),
                                method: 'GET',
                                timestamp: ts()
                            });
                        } catch (e) {}
                    }
                });
            }
        }
    } catch (e) {}

    // ---------------------------------------------------------------
    // NSFileManager -- Dosya islemleri
    // ---------------------------------------------------------------

    try {
        var NSFileManager = ObjC.classes.NSFileManager;
        if (NSFileManager) {
            // contentsOfDirectoryAtPath:error:
            var contentsOfDir = NSFileManager['- contentsOfDirectoryAtPath:error:'];
            if (contentsOfDir) {
                Interceptor.attach(contentsOfDir.implementation, {
                    onEnter: function (args) {
                        try {
                            var path = new ObjC.Object(args[2]).toString();
                            send({
                                type: 'fs_listdir',
                                path: path,
                                timestamp: ts()
                            });
                        } catch (e) {}
                    }
                });
            }

            // fileExistsAtPath:
            var fileExists = NSFileManager['- fileExistsAtPath:'];
            if (fileExists) {
                Interceptor.attach(fileExists.implementation, {
                    onEnter: function (args) {
                        try {
                            this._path = new ObjC.Object(args[2]).toString();
                        } catch (e) {
                            this._path = null;
                        }
                    },
                    onLeave: function (retval) {
                        if (this._path) {
                            send({
                                type: 'fs_exists',
                                path: this._path,
                                exists: retval.toInt32() !== 0,
                                timestamp: ts()
                            });
                        }
                    }
                });
            }

            // contentsAtPath:
            var contentsAt = NSFileManager['- contentsAtPath:'];
            if (contentsAt) {
                Interceptor.attach(contentsAt.implementation, {
                    onEnter: function (args) {
                        try {
                            var path = new ObjC.Object(args[2]).toString();
                            send({
                                type: 'fs_read_file',
                                path: path,
                                timestamp: ts()
                            });
                        } catch (e) {}
                    }
                });
            }

            // createFileAtPath:contents:attributes:
            var createFile = NSFileManager['- createFileAtPath:contents:attributes:'];
            if (createFile) {
                Interceptor.attach(createFile.implementation, {
                    onEnter: function (args) {
                        try {
                            var path = new ObjC.Object(args[2]).toString();
                            send({
                                type: 'fs_create_file',
                                path: path,
                                timestamp: ts()
                            });
                        } catch (e) {}
                    }
                });
            }
        }
    } catch (e) {}

    // ---------------------------------------------------------------
    // NSUserDefaults -- Tercih/ayar erisimleri
    // ---------------------------------------------------------------

    try {
        var NSUserDefaults = ObjC.classes.NSUserDefaults;
        if (NSUserDefaults) {
            // objectForKey:
            var objectForKey = NSUserDefaults['- objectForKey:'];
            if (objectForKey) {
                Interceptor.attach(objectForKey.implementation, {
                    onEnter: function (args) {
                        try {
                            this._key = new ObjC.Object(args[2]).toString();
                        } catch (e) {
                            this._key = null;
                        }
                    },
                    onLeave: function (retval) {
                        if (this._key) {
                            var val = null;
                            try {
                                if (!retval.isNull()) {
                                    val = new ObjC.Object(retval).toString();
                                    // Uzun degerleri kes
                                    if (val.length > 200) {
                                        val = val.substring(0, 200) + '...[truncated]';
                                    }
                                }
                            } catch (e) {}
                            send({
                                type: 'defaults_read',
                                key: this._key,
                                value: val,
                                timestamp: ts()
                            });
                        }
                    }
                });
            }

            // setObject:forKey:
            var setObjectForKey = NSUserDefaults['- setObject:forKey:'];
            if (setObjectForKey) {
                Interceptor.attach(setObjectForKey.implementation, {
                    onEnter: function (args) {
                        try {
                            var value = new ObjC.Object(args[2]).toString();
                            var key = new ObjC.Object(args[3]).toString();
                            if (value.length > 200) {
                                value = value.substring(0, 200) + '...[truncated]';
                            }
                            send({
                                type: 'defaults_write',
                                key: key,
                                value: value,
                                timestamp: ts()
                            });
                        } catch (e) {}
                    }
                });
            }
        }
    } catch (e) {}

    // ---------------------------------------------------------------
    // Security Framework -- SecKeyCreateSignature
    // ---------------------------------------------------------------

    try {
        var secSignAddr = Module.findExportByName('Security', 'SecKeyCreateSignature');
        if (secSignAddr) {
            Interceptor.attach(secSignAddr, {
                onEnter: function (args) {
                    try {
                        // args[1] = SecKeyAlgorithm (CFString)
                        var algorithm = new ObjC.Object(args[1]).toString();
                        send({
                            type: 'crypto_sign',
                            algorithm: algorithm,
                            timestamp: ts()
                        });
                    } catch (e) {
                        send({
                            type: 'crypto_sign',
                            algorithm: 'unknown',
                            timestamp: ts()
                        });
                    }
                }
            });
        }
    } catch (e) {}

    // SecKeyCreateDecryptedData
    try {
        var secDecryptAddr = Module.findExportByName('Security', 'SecKeyCreateDecryptedData');
        if (secDecryptAddr) {
            Interceptor.attach(secDecryptAddr, {
                onEnter: function (args) {
                    try {
                        var algorithm = new ObjC.Object(args[1]).toString();
                        send({
                            type: 'crypto_decrypt',
                            algorithm: algorithm,
                            timestamp: ts()
                        });
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}

    // SecKeyCreateEncryptedData
    try {
        var secEncryptAddr = Module.findExportByName('Security', 'SecKeyCreateEncryptedData');
        if (secEncryptAddr) {
            Interceptor.attach(secEncryptAddr, {
                onEnter: function (args) {
                    try {
                        var algorithm = new ObjC.Object(args[1]).toString();
                        send({
                            type: 'crypto_encrypt',
                            algorithm: algorithm,
                            timestamp: ts()
                        });
                    } catch (e) {}
                }
            });
        }
    } catch (e) {}

    // ---------------------------------------------------------------
    // NSBundle -- kaynak dosya yuklemeleri
    // ---------------------------------------------------------------

    try {
        var NSBundle = ObjC.classes.NSBundle;
        if (NSBundle) {
            var pathForResource = NSBundle['- pathForResource:ofType:'];
            if (pathForResource) {
                Interceptor.attach(pathForResource.implementation, {
                    onEnter: function (args) {
                        try {
                            var name = new ObjC.Object(args[2]).toString();
                            var type = new ObjC.Object(args[3]).toString();
                            this._resource = name + '.' + type;
                        } catch (e) {
                            this._resource = null;
                        }
                    },
                    onLeave: function (retval) {
                        if (this._resource) {
                            var path = null;
                            try {
                                if (!retval.isNull()) {
                                    path = new ObjC.Object(retval).toString();
                                }
                            } catch (e) {}
                            send({
                                type: 'bundle_resource',
                                resource: this._resource,
                                path: path,
                                timestamp: ts()
                            });
                        }
                    }
                });
            }
        }
    } catch (e) {}

    // ---------------------------------------------------------------
    // NSProcessInfo -- ortam degiskenleri
    // ---------------------------------------------------------------

    try {
        var NSProcessInfo = ObjC.classes.NSProcessInfo;
        if (NSProcessInfo) {
            var envMethod = NSProcessInfo['- environment'];
            if (envMethod) {
                Interceptor.attach(envMethod.implementation, {
                    onEnter: function (args) {
                        send({
                            type: 'env_access_objc',
                            method: 'NSProcessInfo.environment',
                            timestamp: ts()
                        });
                    }
                });
            }
        }
    } catch (e) {}

    // ---------------------------------------------------------------
    // Baslangic mesaji
    // ---------------------------------------------------------------
    send({
        type: 'hook_loaded',
        hook_name: 'objc_hooks',
        platform: Process.platform,
        arch: Process.arch,
        pid: Process.id,
        objc_available: ObjC.available,
        timestamp: ts()
    });

})();
