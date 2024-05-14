"use strict";
(self["webpackChunkunipass_wallet"] =
    self["webpackChunkunipass_wallet"] || []).push([
    [7198],
    {
        53695: function (e, l, a) {
            a.d(l, {
                Z: function () {
                    return W;
                },
            });
            var n = a(44870),
                o = a(73396),
                t = a(22483),
                i = a(73513),
                s = a(18131),
                c = (a(62064), a(62790)),
                r = a(34257),
                u = a(47128),
                p = a(87139),
                g = a(49242),
                d = a(78791),
                v = a(14052),
                m = a(45358),
                k = a(56827);
            const _ = { class: "page-login" },
                h = (0, o._)("div", { class: "logo" }, null, -1),
                y = { key: 0, class: "to-continue-to" },
                w = { class: "oauth-box" },
                U = { key: 1, class: "or-box" },
                S = (0, o._)("div", { class: "line" }, null, -1),
                f = (0, o._)("div", { class: "line" }, null, -1),
                b = { class: "other" },
                C = { class: "login-sign-protocol" },
                T = {
                    target: "_blank",
                    href: "https://cdn.cassava.network/public/Cassava_TC_AC-220927-dark.html",
                },
                $ = {
                    target: "_blank",
                    href: "https://cdn.cassava.network/public/Cassava_Technologies_Limited_Privacy_Policy-dark.html",
                };
            var L = (0, o.aZ)({
                __name: "page-login",
                setup(e) {
                    const l = (0, n.iH)(),
                        a = (0, n.iH)(),
                        L = (0, t.yj)();
                    L.query.source &&
                    "ethdenver" === L.query.source &&
                    sessionStorage.setItem("up_login_source", "ethdenver");
                    const z = (0, v.Hs)(),
                        W = (0, d.T)(),
                        q = (0, o.Fl)(() => "/login" === L.path);
                    (0, o.wF)(() => {
                        const e = sessionStorage.connectType;
                        e && (W.connectType = e);
                    });
                    const Z = () => {
                            q.value ? F() : P();
                        },
                        D = () => {
                            q.value
                                ? (0, v.yC)("login_click_google")
                                : (0, v.yC)("register_click_google"),
                                W.loginWithGoogle();
                        },
                        E = () => {
                            q.value
                                ? (0, v.yC)("login_click_apple")
                                : (0, v.yC)("register_click_apple"),
                                W.auth0Login({ provider: m.O4.APPLE });
                        },
                        F = () => {
                            var e, n;
                            W.email
                                ? l.value &&
                                l.value.validate((e) => {
                                    e &&
                                    ((0, v.yC)("login_click_continue", { email: W.email }, 1),
                                        W.auth0Login({ provider: m.O4.AUTH0 }));
                                })
                                : null === (e = a.value) ||
                                void 0 === e ||
                                null === (n = e.element) ||
                                void 0 === n ||
                                n.focus();
                        },
                        P = () => {
                            var e, n;
                            W.email
                                ? l.value &&
                                l.value.validate((e) => {
                                    e &&
                                    ((0, v.yC)(
                                        "register_click_continue",
                                        { email: W.email },
                                        1
                                    ),
                                        W.auth0Login({ provider: m.O4.AUTH0 }));
                                })
                                : null === (e = a.value) ||
                                void 0 === e ||
                                null === (n = e.element) ||
                                void 0 === n ||
                                n.focus();
                        },
                        A = (0, o.Fl)(() => sessionStorage.appName),
                        B = (0, o.Fl)(
                            () =>
                                ("google" === W.connectType || "both" === W.connectType) &&
                                !(0, k.BX)()
                        ),
                        H = (0, o.Fl)(
                            () =>
                                ("apple" === W.connectType || "both" === W.connectType) &&
                                !(0, k.BX)()
                        ),
                        j = (0, o.Fl)(() => "both" === W.connectType && !(0, k.BX)()),
                        x = (0, o.Fl)(
                            () =>
                                "email" === W.connectType ||
                                "both" === W.connectType ||
                                (0, k.BX)()
                        );
                    return (e, t) => {
                        const d = u.Z,
                            m = r.Z,
                            k = c.Z,
                            L = s.ly,
                            P = i.Z,
                            O = (0, o.up)("router-link"),
                            V = (0, o.up)("i18n-t");
                        return (
                            (0, o.wg)(),
                                (0, o.iD)("div", _, [
                                    h,
                                    (0, o._)(
                                        "h1",
                                        null,
                                        (0, p.zw)(
                                            (0, n.SU)(q) ? e.$t("LoginTitle") : e.$t("RegisterTitle")
                                        ),
                                        1
                                    ),
                                    (0, n.SU)(A)
                                        ? ((0, o.wg)(),
                                            (0, o.iD)("div", y, [
                                                (0, o.Uk)((0, p.zw)(e.$t("ToContinueTo")) + " ", 1),
                                                (0, o._)("span", null, (0, p.zw)((0, n.SU)(A)), 1),
                                            ]))
                                        : (0, o.kq)("", !0),
                                    (0, o._)("div", w, [
                                        (0, n.SU)(B)
                                            ? ((0, o.wg)(),
                                                (0, o.iD)(
                                                    "div",
                                                    { key: 0, class: "one google", onClick: D },
                                                    [
                                                        (0, o.Wm)(d, { name: "google" }),
                                                        (0, o._)(
                                                            "span",
                                                            null,
                                                            (0, p.zw)(
                                                                (0, n.SU)(q)
                                                                    ? e.$t("LoginWithGoogle")
                                                                    : e.$t("SignUpWithGoogle")
                                                            ),
                                                            1
                                                        ),
                                                    ]
                                                ))
                                            : (0, o.kq)("", !0),
                                        (0, n.SU)(H)
                                            ? ((0, o.wg)(),
                                                (0, o.iD)(
                                                    "div",
                                                    { key: 1, class: "one apple", onClick: E },
                                                    [
                                                        (0, o.Wm)(d, { name: "apple" }),
                                                        (0, o._)(
                                                            "span",
                                                            null,
                                                            (0, p.zw)(
                                                                (0, n.SU)(q)
                                                                    ? e.$t("LoginWithApple")
                                                                    : e.$t("SignUpWithApple")
                                                            ),
                                                            1
                                                        ),
                                                    ]
                                                ))
                                            : (0, o.kq)("", !0),
                                    ]),
                                    (0, n.SU)(j)
                                        ? ((0, o.wg)(),
                                            (0, o.iD)("div", U, [
                                                S,
                                                (0, o._)(
                                                    "span",
                                                    null,
                                                    (0, p.zw)(
                                                        (0, n.SU)(q)
                                                            ? e.$t("OrEmailLogin")
                                                            : e.$t("OrEmailRegister")
                                                    ),
                                                    1
                                                ),
                                                f,
                                            ]))
                                        : (0, o.kq)("", !0),
                                    (0, n.SU)(x)
                                        ? ((0, o.wg)(),
                                            (0, o.j4)(
                                                L,
                                                {
                                                    key: 2,
                                                    onSubmit:
                                                        t[4] || (t[4] = (0, g.iM)(() => {}, ["prevent"])),
                                                    ref_key: "formElement",
                                                    ref: l,
                                                    model: (0, n.SU)(W),
                                                },
                                                {
                                                    default: (0, o.w5)(() => [
                                                        (0, o.Wm)(
                                                            k,
                                                            {
                                                                label: (0, n.SU)(W).email && e.$t("Email"),
                                                                prop: "email",
                                                                type: "email",
                                                                rules: [
                                                                    {
                                                                        validator: (0, n.SU)(z).checkEmailFormat,
                                                                        trigger: "blur",
                                                                    },
                                                                ],
                                                            },
                                                            {
                                                                default: (0, o.w5)(() => [
                                                                    (0, o.Wm)(
                                                                        m,
                                                                        {
                                                                            ref_key: "emailElement",
                                                                            ref: a,
                                                                            placeholder: e.$t("EmailEmpty"),
                                                                            onInput:
                                                                                t[0] ||
                                                                                (t[0] = (e) =>
                                                                                    ((0, n.SU)(W).email = (0, n.SU)(v.go)(
                                                                                        e
                                                                                    ))),
                                                                            onFocus:
                                                                                t[1] ||
                                                                                (t[1] = (e) => {
                                                                                    var a;
                                                                                    return null === (a = l.value) ||
                                                                                    void 0 === a
                                                                                        ? void 0
                                                                                        : a.clearValidate("email");
                                                                                }),
                                                                            modelValue: (0, n.SU)(W).email,
                                                                            "onUpdate:modelValue":
                                                                                t[2] ||
                                                                                (t[2] = (e) => ((0, n.SU)(W).email = e)),
                                                                            clearable: "",
                                                                            onKeydown:
                                                                                t[3] ||
                                                                                (t[3] = (0, g.D2)(
                                                                                    (e) => (0, n.SU)(W).email && F(),
                                                                                    ["enter"]
                                                                                )),
                                                                            autofocus: "",
                                                                        },
                                                                        null,
                                                                        8,
                                                                        ["placeholder", "modelValue"]
                                                                    ),
                                                                ]),
                                                                _: 1,
                                                            },
                                                            8,
                                                            ["label", "rules"]
                                                        ),
                                                    ]),
                                                    _: 1,
                                                },
                                                8,
                                                ["model"]
                                            ))
                                        : (0, o.kq)("", !0),
                                    (0, n.SU)(x)
                                        ? ((0, o.wg)(),
                                            (0, o.j4)(
                                                P,
                                                {
                                                    key: 3,
                                                    class: "submit",
                                                    type: "primary",
                                                    onClick: Z,
                                                    loading: (0, n.SU)(W).auth0EmailLoading,
                                                },
                                                {
                                                    default: (0, o.w5)(() => [
                                                        (0, o.Uk)(
                                                            (0, p.zw)(
                                                                (0, n.SU)(q) ? e.$t("Login") : e.$t("Continue")
                                                            ),
                                                            1
                                                        ),
                                                    ]),
                                                    _: 1,
                                                },
                                                8,
                                                ["loading"]
                                            ))
                                        : (0, o.kq)("", !0),
                                    (0, o._)("div", b, [
                                        (0, o.Uk)(
                                            (0, p.zw)(
                                                (0, n.SU)(q) ? e.$t("NoAccount") : e.$t("HaveAccount")
                                            ) + " ",
                                            1
                                        ),
                                        (0, o.Wm)(
                                            O,
                                            {
                                                replace: "",
                                                to: (0, n.SU)(q) ? "/register" : "/login",
                                                class: "underline",
                                            },
                                            {
                                                default: (0, o.w5)(() => [
                                                    (0, o.Uk)(
                                                        (0, p.zw)(
                                                            (0, n.SU)(q) ? e.$t("ToSignUp") : e.$t("Login")
                                                        ),
                                                        1
                                                    ),
                                                ]),
                                                _: 1,
                                            },
                                            8,
                                            ["to"]
                                        ),
                                    ]),
                                    (0, o._)("div", C, [
                                        (0, o.Wm)(
                                            V,
                                            { keypath: "Protocol", tag: !1 },
                                            {
                                                terms: (0, o.w5)(() => [
                                                    (0, o._)("a", T, (0, p.zw)(e.$t("Terms")), 1),
                                                ]),
                                                privacy: (0, o.w5)(() => [
                                                    (0, o._)("a", $, (0, p.zw)(e.$t("Privacy")), 1),
                                                ]),
                                                _: 1,
                                            }
                                        ),
                                    ]),
                                ])
                        );
                    };
                },
            });
            const z = L;
            var W = z;
        },
        76290: function (e, l, a) {
            a.d(l, {
                Z: function () {
                    return k;
                },
            });
            var n = a(22483),
                o = a(47128),
                t = a(73396),
                i = a(87139),
                s = a(44870),
                c = a(61481);
            const r = { class: "up-header" },
                u = { class: "left" },
                p = { key: 0, class: "logo" },
                g = { key: 4, class: "title" },
                d = { class: "right" };
            var v = (0, t.aZ)({
                __name: "up-header",
                props: {
                    hideBack: { type: Boolean, default: !1 },
                    back: null,
                    close: null,
                    title: null,
                },
                setup(e) {
                    const l = e,
                        a = (0, c.L)(),
                        v = (0, n.tv)(),
                        m = () => {
                            var e;
                            null === l ||
                            void 0 === l ||
                            null === (e = l.close) ||
                            void 0 === e ||
                            e.call(l);
                        },
                        k = () => {
                            l.back ? l.back() : v.back();
                        };
                    return (e, n) => {
                        const c = o.Z;
                        return (
                            (0, t.wg)(),
                                (0, t.iD)("div", r, [
                                    (0, t._)("div", u, [
                                        l.hideBack
                                            ? ((0, t.wg)(), (0, t.iD)("div", p))
                                            : (0, t.kq)("", !0),
                                        l.hideBack
                                            ? ((0, t.wg)(),
                                                (0, t.j4)(c, {
                                                    key: 1,
                                                    name: "UniPass",
                                                    width: "96px",
                                                    height: "16px",
                                                }))
                                            : l.close
                                                ? ((0, t.wg)(),
                                                    (0, t.j4)(c, {
                                                        key: 2,
                                                        name: "close",
                                                        width: "24px",
                                                        height: "24px",
                                                        onClick: m,
                                                    }))
                                                : ((0, t.wg)(),
                                                    (0, t.j4)(c, { key: 3, name: "back", onClick: k })),
                                        l.title
                                            ? ((0, t.wg)(), (0, t.iD)("div", g, (0, i.zw)(l.title), 1))
                                            : (0, t.kq)("", !0),
                                    ]),
                                    (0, t._)("div", d, [
                                        l.title
                                            ? (0, t.kq)("", !0)
                                            : ((0, t.wg)(),
                                                (0, t.j4)(c, {
                                                    key: 0,
                                                    name: "more",
                                                    onClick:
                                                        n[0] ||
                                                        (n[0] = (e) =>
                                                            ((0, s.SU)(a).showHeaderMore = !(0, s.SU)(a)
                                                                .showHeaderMore)),
                                                })),
                                        (0, t.WI)(e.$slots, "right"),
                                    ]),
                                ])
                        );
                    };
                },
            });
            const m = v;
            var k = m;
        },
        33432: function (e, l, a) {
            a.d(l, {
                Z: function () {
                    return v;
                },
            });
            var n = a(73396),
                o = a.p + "img/UniPass.cf59feb7.svg";
            const t = { class: "up-supported-by" },
                i = (0, n._)("span", null, "Supported by", -1),
                s = (0, n._)("img", { class: "unipass-logo", src: o }, null, -1),
                c = (0, n._)("span", { class: "text" }, "UniPass", -1),
                r = [i, s, c];
            function u(e, l) {
                return (0, n.wg)(), (0, n.iD)("div", t, r);
            }
            var p = a(40089);
            const g = {},
                d = (0, p.Z)(g, [["render", u]]);
            var v = d;
        },
    },
]);
