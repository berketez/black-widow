/**
 * Webpack minified bundle — test fixture
 * Black Widow (Karadul) target detection test icin
 */
(function(e) {
    var t = {};
    function n(r) {
        if (t[r]) return t[r].exports;
        var o = t[r] = {
            i: r,
            l: !1,
            exports: {}
        };
        return e[r].call(o.exports, o, o.exports, n), o.l = !0, o.exports
    }
    n.m = e,
    n.c = t,
    n.d = function(e, t, r) {
        n.o(e, t) || Object.defineProperty(e, t, {
            enumerable: !0,
            get: r
        })
    },
    n.r = function(e) {
        "undefined" != typeof Symbol && Symbol.toStringTag && Object.defineProperty(e, Symbol.toStringTag, {
            value: "Module"
        }),
        Object.defineProperty(e, "__esModule", {
            value: !0
        })
    },
    n.o = function(e, t) {
        return Object.prototype.hasOwnProperty.call(e, t)
    },
    n.p = "",
    n(n.s = 0)
})({
    0: function(e, t, n) {
        "use strict";
        var r = n(1),
            o = n(2);
        console.log(r.greet(o.name))
    },
    1: function(e, t) {
        "use strict";
        t.greet = function(e) {
            return "Hello, " + e + "! Welcome to __webpack_require__ land."
        }
    },
    2: function(e, t) {
        "use strict";
        t.name = "Karadul",
        t.version = "3.0.0",
        t.config = {
            debug: !1,
            verbose: !1,
            maxRetries: 3
        }
    }
});
