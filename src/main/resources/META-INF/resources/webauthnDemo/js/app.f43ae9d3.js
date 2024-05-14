(function () {
    var e = {
            3542: function (e, t, n) {
                "use strict";
                n.d(t, {
                    Z: function () {
                        return l;
                    },
                });
                var o = n(73396),
                    a = JSON.parse(
                        '{"LoginTitle":"LOGIN","EmailEmpty":"Please enter your email address","RegisterTitle":"SIGN UP","RegisterPasswordSubtitle":"Set Password"}'
                    ),
                    i = JSON.parse(
                        '{"LoginTitle":"Login","EmailEmpty":"Please enter email","RegisterTitle":"Register","RegisterPasswordSubtitle":"Set Password","OrEmailLogin":"Please enter email","OrEmailRegister":"Please enter email","Confirm":"Confirm"}'
                    ),
                    r = JSON.parse(
                        '{"LoginTitle":"Log In","EmailEmpty":"Enter your email","RegisterTitle":"Sign Up","RegisterPasswordSubtitle":"Set Password","OrEmailLogin":"or","OrEmailRegister":"or","Confirm":"Confirm","LoginWithGoogle":"Google","SignUpWithGoogle":"Google","LoginWithApple":"Apple","SignUpWithApple":"Apple","StartTrading":"Start Trading","SigninMufex":"Sign in Mufex","ConnectTitle":"Sign In Mufex","MufexConnectTips":"To build the most user-friendly exchange, you need to grant the secure access listed below for 24hrs. This will make it easier for you to use the DEX.","MufexDesc1":"Access to the Mufex Lightning Trading Network","MufexDesc2":"Performing a deposit operation on your trading account on your behalf","MufexDesc3":"Performing a transfer operation on your wallet account on your behalf","MufexProtocol":"I Agree to {text}","MufexTerms":"Terms & Conditions"}'
                    ),
                    s = JSON.parse(
                        '{"LoginTitle":"Log In","EmailEmpty":"Enter your email","RegisterTitle":"Sign Up","RegisterPasswordSubtitle":"Set Password","Confirm":"Confirm"}'
                    );
                const c = {
                    theme: {
                        darkList: ["cassava", "DAOLink", "mufex", "KCC"],
                        lightList: ["metacene"],
                    },
                    lang: { cassava: a, DAOLink: i, mufex: r, KCC: s },
                    components: {
                        default: () => (0, o.RC)(() => n.e(2801).then(n.bind(n, 42801))),
                        cassava: () => (0, o.RC)(() => n.e(4043).then(n.bind(n, 24043))),
                        DAOLink: () => (0, o.RC)(() => n.e(8912).then(n.bind(n, 58912))),
                        metacene: () => (0, o.RC)(() => n.e(1854).then(n.bind(n, 51854))),
                        mufex: () => (0, o.RC)(() => n.e(8918).then(n.bind(n, 98918))),
                        KCC: () => (0, o.RC)(() => n.e(789).then(n.bind(n, 40789))),
                    },
                };
                var l = c;
            },
            38054: function (e, t, n) {
                "use strict";
                var o = n(49242),
                    a = n(73396),
                    i = n(44870),
                    r = n.p + "img/guide.fac45d63.svg",
                    s = n.p + "img/more.d8d62d97.svg",
                    c = n.p + "img/browser.45bc8e8c.svg";
                const l = { key: 0, id: "up-open-in-browser" },
                    u = (0, a.uE)(
                        '<img src="' +
                        r +
                        '" alt="guide" class="guide"><div class="tip"><span>1. Click the top-right corner</span><img src="' +
                        s +
                        '" alt="more" class="more"></div><div class="tip"><span>2. Click “Open in Browser” in the menu</span><img src="' +
                        c +
                        '" alt="browser" class="browser"></div>',
                        3
                    ),
                    d = [u];
                var g = (0, a.aZ)({
                    __name: "up-open-in-browser",
                    setup(e) {
                        const t = navigator.userAgent.toLowerCase(),
                            n = /micromessenger/i.test(t),
                            o = (0, i.iH)(!1);
                        return (
                            (o.value = n),
                                (e, t) =>
                                    o.value
                                        ? ((0, a.wg)(), (0, a.iD)("div", l, d))
                                        : (0, a.kq)("", !0)
                        );
                    },
                });
                const p = g;
                var h = p,
                    m = n(5658),
                    f = n(50186),
                    y = n(73513),
                    w = n(68368),
                    v = (n(42250), n(17960), n(87139)),
                    S = n(45358),
                    A = n(42819),
                    T = n(61481);
                const _ = { class: "el-dialog__subtitle" },
                    C = { key: 0, class: "will" };
                var P = (0, a.aZ)({
                    __name: "dialog-oauth",
                    setup(e) {
                        const { t: t } = (0, m.QT)(),
                            n = (0, T.L)(),
                            o = () => {
                                n.showTimeSelect
                                    ? A.n.set(
                                        "UP_SIGN_TOKEN_DURATION",
                                        (60 * n.showOAuthHours).toString()
                                    )
                                    : A.n.set("UP_SIGN_TOKEN_DURATION", "60"),
                                    (n.showOAuthConfirmLoading = !0),
                                    n.showOAuthCallback(),
                                n.accountInfo.oauth_provider === S.O4.CUSTODIAL &&
                                ((n.showOAuth = !1), (n.showOAuthConfirmLoading = !1));
                            },
                            r = (0, a.Fl)(() => [
                                { value: 0, label: t("ExpireZero") },
                                { value: 1, label: t("ExpireOneHour") },
                                { value: 4, label: t("ExpireFourHours") },
                                { value: 12, label: t("ExpireTwelve") },
                            ]);
                        return (e, s) => {
                            const c = w.BT,
                                l = w.km,
                                u = y.Z,
                                d = f.Z;
                            return (
                                (0, a.wg)(),
                                    (0, a.j4)(
                                        d,
                                        {
                                            modelValue: (0, i.SU)(n).showOAuth,
                                            "onUpdate:modelValue":
                                                s[1] || (s[1] = (e) => ((0, i.SU)(n).showOAuth = e)),
                                            title: (0, i.SU)(t)("SecurityVerification"),
                                            "destroy-on-close": "",
                                            class: "dialog-show-oauth",
                                        },
                                        {
                                            footer: (0, a.w5)(() => [
                                                (0, a.Wm)(
                                                    u,
                                                    {
                                                        type: "primary",
                                                        onClick: o,
                                                        loading: (0, i.SU)(n).showOAuthConfirmLoading,
                                                    },
                                                    {
                                                        default: (0, a.w5)(() => [
                                                            (0, a.Uk)((0, v.zw)((0, i.SU)(t)("Confirm")), 1),
                                                        ]),
                                                        _: 1,
                                                    },
                                                    8,
                                                    ["loading"]
                                                ),
                                            ]),
                                            default: (0, a.w5)(() => [
                                                (0, a._)(
                                                    "div",
                                                    _,
                                                    (0, v.zw)((0, i.SU)(t)("SecurityVerify")),
                                                    1
                                                ),
                                                (0, i.SU)(n).showTimeSelect
                                                    ? ((0, a.wg)(),
                                                        (0, a.iD)(
                                                            "div",
                                                            C,
                                                            (0, v.zw)((0, i.SU)(t)("SecurityExpire")) + ":",
                                                            1
                                                        ))
                                                    : (0, a.kq)("", !0),
                                                (0, i.SU)(n).showTimeSelect
                                                    ? ((0, a.wg)(),
                                                        (0, a.j4)(
                                                            l,
                                                            {
                                                                key: 1,
                                                                modelValue: (0, i.SU)(n).showOAuthHours,
                                                                "onUpdate:modelValue":
                                                                    s[0] ||
                                                                    (s[0] = (e) =>
                                                                        ((0, i.SU)(n).showOAuthHours = e)),
                                                                class: "oauth-validity-period",
                                                                "popper-class": "oauth-validity-period-popper",
                                                                placement: "top-start",
                                                            },
                                                            {
                                                                default: (0, a.w5)(() => [
                                                                    ((0, a.wg)(!0),
                                                                        (0, a.iD)(
                                                                            a.HY,
                                                                            null,
                                                                            (0, a.Ko)(
                                                                                (0, i.SU)(r),
                                                                                (e) => (
                                                                                    (0, a.wg)(),
                                                                                        (0, a.j4)(
                                                                                            c,
                                                                                            {
                                                                                                key: e.value,
                                                                                                label: e.label,
                                                                                                value: e.value,
                                                                                            },
                                                                                            null,
                                                                                            8,
                                                                                            ["label", "value"]
                                                                                        )
                                                                                )
                                                                            ),
                                                                            128
                                                                        )),
                                                                ]),
                                                                _: 1,
                                                            },
                                                            8,
                                                            ["modelValue"]
                                                        ))
                                                    : (0, a.kq)("", !0),
                                            ]),
                                            _: 1,
                                        },
                                        8,
                                        ["modelValue", "title"]
                                    )
                            );
                        };
                    },
                });
                const E = P;
                var k = E,
                    b = n(86367),
                    I = n(54419),
                    U = n(64150),
                    O = (n(93759), n(47128));
                const R = { class: "left" },
                    L = { class: "right" },
                    N = { class: "left" },
                    x = { class: "right" },
                    D = { class: "now" };
                var W = (0, a.aZ)({
                    __name: "dialog-header-more",
                    setup(e) {
                        const t = (0, T.L)(),
                            n = (0, m.QT)(),
                            o = (0, b.e7M)(),
                            { t: r } = (0, m.QT)(),
                            s = () => {
                                (n.locale.value = "en" === n.locale.value ? "zh" : "en"),
                                    localStorage.setItem("language", n.locale.value);
                            },
                            c = (0, I.OT)(o);
                        return (e, n) => {
                            const l = O.Z,
                                u = U.zd;
                            return (
                                (0, a.wg)(),
                                    (0, a.j4)(
                                        u,
                                        {
                                            modelValue: (0, i.SU)(t).showHeaderMore,
                                            "onUpdate:modelValue":
                                                n[1] || (n[1] = (e) => ((0, i.SU)(t).showHeaderMore = e)),
                                            direction: "rtl",
                                            "custom-class": "up-header-more",
                                            size: "290px",
                                        },
                                        {
                                            default: (0, a.w5)(() => [
                                                (0, a._)(
                                                    "div",
                                                    {
                                                        class: "one theme",
                                                        onClick: n[0] || (n[0] = (e) => (0, i.SU)(c)()),
                                                    },
                                                    [
                                                        (0, a._)("div", R, [
                                                            (0, a.Wm)(
                                                                l,
                                                                {
                                                                    name: (0, i.SU)(o)
                                                                        ? "setting-theme-dark"
                                                                        : "setting-theme-light",
                                                                },
                                                                null,
                                                                8,
                                                                ["name"]
                                                            ),
                                                            (0, a._)(
                                                                "div",
                                                                null,
                                                                (0, v.zw)(
                                                                    (0, i.SU)(o)
                                                                        ? (0, i.SU)(r)("ThemeLight")
                                                                        : (0, i.SU)(r)("ThemeDark")
                                                                ),
                                                                1
                                                            ),
                                                        ]),
                                                        (0, a._)("div", L, [
                                                            (0, a.Wm)(l, { name: "cutover" }),
                                                        ]),
                                                    ]
                                                ),
                                                (0, a._)("div", { class: "one language", onClick: s }, [
                                                    (0, a._)("div", N, [
                                                        (0, a.Wm)(
                                                            l,
                                                            {
                                                                name: (0, i.SU)(o)
                                                                    ? "setting-english-dark"
                                                                    : "setting-english-light",
                                                            },
                                                            null,
                                                            8,
                                                            ["name"]
                                                        ),
                                                        (0, a._)(
                                                            "div",
                                                            null,
                                                            (0, v.zw)((0, i.SU)(r)("Language")),
                                                            1
                                                        ),
                                                    ]),
                                                    (0, a._)("div", x, [
                                                        (0, a._)(
                                                            "div",
                                                            D,
                                                            (0, v.zw)((0, i.SU)(r)("LanguageNow")),
                                                            1
                                                        ),
                                                        (0, a.Wm)(l, { name: "jump" }),
                                                    ]),
                                                ]),
                                            ]),
                                            _: 1,
                                        },
                                        8,
                                        ["modelValue"]
                                    )
                            );
                        };
                    },
                });
                const F = W;
                var G = F,
                    K = n(51610);
                const M = { class: "title" },
                    B = { class: "support" },
                    H = { class: "tip" },
                    Z = { class: "mail" },
                    V = (0, a._)("div", null, "gmail.com", -1),
                    $ = (0, a._)("span", null, "/", -1),
                    z = (0, a._)("div", null, "googlemail.com", -1),
                    j = { class: "mail" },
                    q = (0, a._)("div", null, "outlook.com", -1),
                    J = (0, a._)("span", null, "/", -1),
                    Y = (0, a._)("div", null, "hotmail.com", -1),
                    Q = { class: "mail" },
                    X = (0, a._)("div", null, "yahoo.com", -1),
                    ee = { class: "mail" },
                    te = (0, a._)("div", null, "protonmail.com", -1),
                    ne = (0, a._)("span", null, "/", -1),
                    oe = (0, a._)("div", null, "pm.me", -1),
                    ae = { class: "mail" },
                    ie = (0, a._)("div", null, "icloud.com", -1),
                    re = { class: "mail" },
                    se = (0, a._)("div", null, "mail.com", -1),
                    ce = { class: "content" };
                var le = (0, a.aZ)({
                    __name: "dialog-support-email",
                    setup(e) {
                        const t = (0, T.L)(),
                            n = (0, b.e7M)();
                        return (e, o) => {
                            const r = O.Z,
                                s = y.Z,
                                c = K.Z;
                            return (
                                (0, a.wg)(),
                                    (0, a.j4)(
                                        c,
                                        {
                                            modelValue: (0, i.SU)(t).showSupportEmail,
                                            "onUpdate:modelValue":
                                                o[1] ||
                                                (o[1] = (e) => ((0, i.SU)(t).showSupportEmail = e)),
                                            class: "dialog-support-email",
                                        },
                                        {
                                            default: (0, a.w5)(() => [
                                                (0, a._)(
                                                    "div",
                                                    M,
                                                    (0, v.zw)(e.$t("SupportMailTitle")),
                                                    1
                                                ),
                                                (0, a._)("div", B, [
                                                    (0, a._)("div", H, (0, v.zw)(e.$t("SupportMail")), 1),
                                                    (0, a._)("div", Z, [
                                                        (0, a.Wm)(r, { class: "logo", name: "gmail" }),
                                                        V,
                                                        $,
                                                        z,
                                                    ]),
                                                    (0, a._)("div", j, [
                                                        (0, a.Wm)(r, { class: "logo", name: "outlook" }),
                                                        q,
                                                        J,
                                                        Y,
                                                    ]),
                                                    (0, a._)("div", Q, [
                                                        (0, a.Wm)(
                                                            r,
                                                            {
                                                                class: "logo",
                                                                name: "yahoo",
                                                                style: (0, v.j5)({
                                                                    color: (0, i.SU)(n) ? "#AD94FF" : "#2d1078",
                                                                }),
                                                            },
                                                            null,
                                                            8,
                                                            ["style"]
                                                        ),
                                                        X,
                                                    ]),
                                                    (0, a._)("div", ee, [
                                                        (0, a.Wm)(
                                                            r,
                                                            {
                                                                class: "logo",
                                                                name: "protonmail",
                                                                style: (0, v.j5)({
                                                                    color: (0, i.SU)(n) ? "#858BC1" : "#474A5f",
                                                                }),
                                                            },
                                                            null,
                                                            8,
                                                            ["style"]
                                                        ),
                                                        te,
                                                        ne,
                                                        oe,
                                                    ]),
                                                    (0, a._)("div", ae, [
                                                        (0, a.Wm)(r, { class: "logo", name: "icloud" }),
                                                        ie,
                                                    ]),
                                                    (0, a._)("div", re, [
                                                        (0, a.Wm)(
                                                            r,
                                                            {
                                                                class: "logo",
                                                                name: "mail-com",
                                                                style: (0, v.j5)({
                                                                    color: (0, i.SU)(n) ? "#fff" : "#000",
                                                                }),
                                                            },
                                                            null,
                                                            8,
                                                            ["style"]
                                                        ),
                                                        se,
                                                    ]),
                                                ]),
                                                (0, a._)("div", ce, (0, v.zw)(e.$t("UniPassDKIM")), 1),
                                                (0, a.Wm)(
                                                    s,
                                                    {
                                                        type: "primary",
                                                        onClick:
                                                            o[0] ||
                                                            (o[0] = (e) =>
                                                                ((0, i.SU)(t).showSupportEmail = !1)),
                                                    },
                                                    {
                                                        default: (0, a.w5)(() => [
                                                            (0, a.Uk)((0, v.zw)(e.$t("Confirm")), 1),
                                                        ]),
                                                        _: 1,
                                                    }
                                                ),
                                            ]),
                                            _: 1,
                                        },
                                        8,
                                        ["modelValue"]
                                    )
                            );
                        };
                    },
                });
                const ue = le;
                var de = ue,
                    ge = n(61072),
                    pe = n(44775),
                    he = n(14052),
                    me = n(7832),
                    fe = n(22483),
                    ye = n(3542);
                const we = { key: 0, class: "up-banner" },
                    ve = { class: "up-app" },
                    Se = { class: "up-loading" },
                    Ae = (0, a.uE)(
                        '<div class="loader"><div class="orbe" style="--index:0;"></div><div class="orbe" style="--index:1;"></div><div class="orbe" style="--index:2;"></div><div class="orbe" style="--index:3;"></div><div class="orbe" style="--index:4;"></div></div>',
                        1
                    ),
                    Te = { class: "tx-tip" };
                var _e = (0, a.aZ)({
                    __name: "app",
                    setup(e) {
                        const t = (0, T.L)();
                        let n;
                        const r = (0, a.Fl)(() => !1);
                        ge.Z.beforeEach(() => {
                            n = pe.kN.service({ lock: !1 });
                        }),
                            ge.Z.afterEach(() => {
                                var e;
                                null === (e = n) || void 0 === e || e.close();
                            });
                        const s = () => {
                                var e;
                                const t =
                                    null !== (e = localStorage.getItem("language")) &&
                                    void 0 !== e
                                        ? e
                                        : "en";
                                (0, he.m0)(t);
                            },
                            c = () => {
                                s(), (0, me.X)();
                            };
                        c();
                        const l = (0, a.Fl)(() => t.theme || sessionStorage.theme),
                            u = (0, a.Fl)(() =>
                                ye.Z.components[l.value]
                                    ? ye.Z.components[l.value]()
                                    : ye.Z.components["default"]()
                            );
                        return (e, n) => {
                            const s = de,
                                c = G,
                                d = k,
                                g = h;
                            return (
                                (0, a.wg)(),
                                    (0, a.iD)(
                                        a.HY,
                                        null,
                                        [
                                            (0, i.SU)(r)
                                                ? ((0, a.wg)(),
                                                    (0, a.iD)("div", we, (0, v.zw)(e.$t("UpBanner")), 1))
                                                : (0, a.kq)("", !0),
                                            (0, a._)("div", ve, [
                                                (0, a.wy)(
                                                    (0, a._)(
                                                        "div",
                                                        Se,
                                                        [
                                                            Ae,
                                                            (0, a._)("div", Te, (0, v.zw)(e.$t("TxTip")), 1),
                                                        ],
                                                        512
                                                    ),
                                                    [[o.F8, (0, i.SU)(t).upLoading]]
                                                ),
                                                (0, a.Wm)((0, i.SU)(fe.MA), { class: "page" }),
                                                (0, a.Wm)(s),
                                                (0, a.Wm)(c),
                                                (0, a.Wm)(d),
                                                (0, i.SU)(l)
                                                    ? ((0, a.wg)(), (0, a.j4)((0, i.SU)(u), { key: 0 }))
                                                    : (0, a.kq)("", !0),
                                            ]),
                                            (0, a.Wm)(g),
                                        ],
                                        64
                                    )
                            );
                        };
                    },
                });
                const Ce = _e;
                var Pe = Ce,
                    Ee = n(24702),
                    ke = n(58650);
                const be = (0, ke.WB)();
                var Ie = be,
                    Ue = n(60990),
                    Oe = n(48865),
                    Re = n.n(Oe),
                    Le = n(83268),
                    Ne = n(55254),
                    xe = n(56763),
                    De = n(49117),
                    We = n(48969);
                const Fe = (0, o.ri)(Pe);
                Fe.use(Ue.ZP, {
                    property: { id: "G-HNDL91TELQ", params: { send_page_view: !1 } },
                }),
                    Ne.S({
                        app: Fe,
                        dsn: "https://646c1ae7726342c9a2d3a8b91d8b2b8b@sentry.unipass.id/2",
                        integrations: [
                            new We.gE({ routingInstrumentation: xe.x(ge.Z) }),
                            new De.K({ levels: ["error"] }),
                        ],
                        tracesSampleRate: 1,
                    }),
                    Fe.use(Le.VueReCaptcha, {
                        siteKey: "6LfGwdckAAAAAGHImpxNZ0AJ_QyPCMyVPZmzFClY",
                    }),
                    Fe.use(Re()),
                    Fe.use(Ie),
                    Fe.use(ge.Z),
                    Fe.use(Ee.Z),
                    Fe.mount("#app");
            },
            24702: function (e, t, n) {
                "use strict";
                n.d(t, {
                    Z: function () {
                        return c;
                    },
                });
                var o = n(5658),
                    a = JSON.parse(
                        '{"AccountPending":"钱包正在恢复中...","AccountStatus":"钱包状态：","ActionNotCommitted":"有操作未提交，您确定要退出吗？","Add":"添加","AddGuardian":"添加守护者邮箱","AddGuardianFailed":"添加守护者邮箱失败","AddSuccess":"添加成功","AmountOutOfRange":"您的余额不足，转账金额将会更新","ApprovalTo":"授权至","BackToHome":"回到首页","Balance":"余额","Cancel":"取消","CastingSuccess":"验证成功！","ChangeGoogleVerify":"修改谷歌验证","ChangePassword":"修改密码","ChangePasswordTitle":"为了保护您的钱包安全，建议至少开启一个身份验证。","ChangePhoneVerify":"修改短信验证","ClosePage":"关闭页面","codeNotification":"请输入您在邮箱","codeNotification2":"收到的验证码","SecurityVerification":"安全验证","CodeWillBeSentTo":"验证码将发送至","Confirm":"确认","ConfirmNewPassword":"请确认新密码","ConfirmPassword":"确认密码","Connect":"连接","ConnectSubtitle":"请求连接至您的 UniPass 账户","ConnectTip1":"此应用程序将能够查看您的账户地址","ConnectTip1Email":"此应用程序将能够查看您的账户地址和邮箱","ConnectTip2":"此应用程序不归 UniPass 所有或运营","ConnectTip3":"此应用程序不能在未经您授权的情况下转移您的资产","ConnectTipJump":"连接后您将离开 UniPass，跳转至：","ConnectTitle":"授权连接","Continue":"继续","ContractAddress":"合约地址","ContractCall":"合约调用","CopyAddress":"复制地址","CopySuccess":"复制成功","CurrentProgress":"恢复模式","Delete":"删除","DeleteSuccess":"删除成功","Deployed":"部署钱包","DeployedWalletConfiguration":"将钱包部署至最新状态","Details":"明细","DualAuthentication":"双重身份验证","Email":"邮箱","EmailCode":"邮箱验证码","EmailCodeEmpty":"请输入邮箱验证码","EmailEmpty":"请输入邮箱","EmailVerify":"邮箱验证","EmailVerifyTitle":"邮箱验证始终保护您的钱包","EmailWrongFormat":"邮箱格式错误","EnterAmount":"请输入转账金额","EnterEthAddress":"请输入转账地址 (0x) 或域名","EnterGoogleCode":"请输入谷歌验证码","EnterNewPassword":"请输入新密码","EnterOldPassword":"请输入旧密码","EnterPassword":"输入密码","WelcomeBack":"欢迎回来！","WelcomeMessage":"输入密码解锁你的 Web3 钱包","EnterPhone":"请输入手机号","EnterPhoneCode":"请输入短信验证码","EnterWallet":"进入钱包","EthAddress":"地址 (0x) 或域名","Exit":"登出","FetchEmailCode":"获取验证码","Finish":"成功","ForgotPassword":"忘记密码？","FromWeb":"网址：","GasFee":"手续费","GasFeeLoadingFailed":"Gas fee 加载失败","GoogleCode":"谷歌验证码","GoogleVerify":"谷歌验证","GoogleVerifyTitle":"Google 验证将为您的钱包增加一重保障","Guardian":"守护者","SetGuardians":"设置守护者","HaveAccount":"已有账户？","HaveAdded":"已添加","HaveWaitingGuardian":"您有一个待确认的守护者，请继续等待或删除此守护者","IncorrectAccountOrPassword":"账户或密码错误","IncorrectCode":"验证码错误","IncorrectMailOrPassword":"邮箱或密码不正确","IncorrectPassword":"密码错误","InsufficientFunds":"余额不足","InvalidAddress":"无效地址","InvalidInput":"无效输入","InvitedSuccess":"邀请成功","Language":"语言","LanguageNow":"中文","LogOut":"登出","LogOutAccount":"登出钱包","Login":"登录","LoginTitle":"登录 UniPass","Maximum":"最大","Message":"消息：","CreateAccountButton":"创建钱包","Network":"网络","NetworkError":"网络错误或超时，请稍后重试","Newest":"最新的","NextStep":"下一步","NoAccount":"没有账户？","NoRisk":"无风险","NormalSpeed":"正常速度","NotDeployed":"未部署","NotSupport":"暂不支持此邮箱域名，请查看支持邮箱列表","Notification":"提示","OpenEmailVerify":"开启邮箱验证","OpenGoogleVerify":"开启谷歌验证","OpenPhoneVerify":"开启短信验证","OwnEmail":"注册邮箱","Password":"密码","PasswordEmpty":"请输入密码","PasswordRule1":"密码长度为 8-32 位","PasswordRule2":"至少1个大写字母","PasswordRule3":"至少1个小写字母","PasswordRule4":"至少1个数字","PasswordsNotMatch":"两次密码不一致，请重新输入","PendingUpgrade":"待同步","Phone":"手机号","PhoneCode":"短信验证码","PhoneVerify":"短信验证","PleaseConfirmPassword":"请再次输入密码","PleaseLoginNewPassword":"请使用最新的密码进行登录","RawData":"原始数据","Receive":"接收","Recovering":"恢复中...","RecoveringNotPending":"账户恢复已完成","RecoveringSubtitle":"账户正在社交恢复中，新密码将在倒计时结束后生效","RecoveringTip":"恢复期间，您依然可以使用旧密码登录账号","RecoveringTitle":"账户恢复中","Recovery48Hours":"锁定 48 小时","RecoveryEmailSame":"已添加此邮箱为守护者，请重新输入","RecoveryGuardianSubtitle":"请进行以下安全验证流程，以完成账户恢复","RecoveryGuardianTitle":"选择守护者，请求账户恢复邮件","RecoveryPasswordSubtitle":"请创建您的新密码","RecoveryPasswordTitle":"重置密码","RecoveryRestart":"网络错误或超时，请稍后重试","RecoveryTimeout":"恢复超时","RegisterAccount":"注册账户","RegisterPasswordSubtitle":"请创建一个复杂的密码来保护您的 Web3 钱包","RegisterTitle":"创建 UniPass 钱包","Registering":"钱包正在创建中...","RequestSignature":"请求签名","RequestsTooFrequent":"请求过于频繁，请稍后重试","RequestsExceeded":"当日请求超过最高限制，请24小时后重试","Resend":"重新发送","ResetPasswordTip":"本次恢复将在 48 小时后生效，您确定要继续，还是邀请更多的守护者来帮助您进行本次恢复？","RestoreNow":"立即恢复","SafetyVerification":"安全验证","SameCase":"请确认大小写与实际邮箱地址一致","SameCaseDot":"请确认大小写与“.”与实际邮箱地址一致","SameDot":"请确认”.”的位置与实际邮箱地址一致","Send":"发送","SendInvitationLink":"发送邀请链接","SendSuccess":"发送成功","SendTitle":"发送资产","SendNFTTitle":"发送NFT","SendTo":"发送至","SendToken":"发送代币","Setting":"账户设置","Setting2faPhoneTitle":"短信验证将为您的钱包增加一重保障","SettingGuardianSubtitle":"守护者能在您忘记密码时，通过邮件社交恢复帮助您找回账户","Sign":"签名","SignTransaction":"签名交易","Signatory":"签署人：","Submit":"提交","SupportMail":"支持邮箱列表","SupportMailTitle":"抱歉，您输入的邮箱域名暂不支持","SureLogOut":"是否确认登出？","Swap":"兑换","SystemBusy":"系统繁忙，请稍后重试","ThemeDark":"暗色","ThemeLight":"亮色","To2faVerification":"请进行二次验证","ToBind":"立即绑定","ToLogin":"去登录","ToSignUp":"立即注册","Token":"资产","SendNFT":"发送 NFT","TotalAmount":"资产净值","Transfer":"发送","UniPassDKIM":"因为 UniPass 通过智能合约验证邮件的 DKIM 签名来实现安全、去中心化的账户恢复，所以目前 UniPass 只支持具有高可信度的大型邮件服务商。","UpBanner":"当前为测试网，请不要转入任何主网资产","Update":"同步钱包","UpdateWalletConfiguration":"将钱包同步至最新状态","VerifyGoogleTip":"查看如何安装谷歌验证器","VerifyGoogleTitle1":"请下载并安装谷歌验证器。并通过添加密钥，完成绑定。","VerifyGoogleTitle2":"请妥善保管此密钥","VerifyPhoneTip":"请按照步骤验证您的手机","VerifySubtitle":"为了您的账户安全，请完成以下验证之一","VerifyYourEmail":"验证您的邮箱","Verifying":"验证中","ViewInExplorer":"在区块浏览器中查看","Waiting":"等待","WaitingRecoveryEmail":"等待发送恢复邮件","SignRequestRejected":"您的签名请求被拒绝","SignRequestConfirming":"请在您的邮件中完成确认","Warning":"注意","isTrading":"交易正在处理中...","recoveryGuardianTip":"请提醒你的守护者去转发社交恢复邮件来协助你恢复账号，当转发邮件的守护者足够多时，你的新密码将会立即生效","Verify":"验证","CancelRecovery":"取消恢复","InputYourPassword":"请输入您的密码","Insufficient":"余额不足","ToContinueTo":"继续使用","OrEmailLogin":"或通过电子邮件登录","OrEmailRegister":"或通过电子邮件注册","LoginWithGoogle":"使用 Google 登录","SignUpWithGoogle":"使用 Google 注册","LoginWithApple":"使用 Apple 登录","SignUpWithApple":"使用 Apple 注册","ByCreating":"创建 UniPass 钱包，您将同意我们的","TermsService":"服务条款","PrivacyPolicy":"隐私政策","And":"和","EnterPasswordConfirmAdd":"如果要继续添加，请输入密码确认","EnterPasswordConfirmDel":"如果要继续删除，请输入密码确认","SyncNotification":"您需要验证您的账户以继续本次交易","IsRecovering":"通知，账户恢复中…","GoogleTip":"您验证的 Google 账户与当前账户不符，请选择以下账户进行授权：<br />“{data}”","GoogleTitle":"Google 账户不正确","TryAgain":"重新选择","AuditError":"安全验证已过期，请回到首页后重试","SecurityVerify":"请在进行操作之前，完成对账户的安全验证","SecurityExpire":"本次验证的有效期是","ExpireZero":"1次","ExpireOneHour":"1 小时","ExpireFourHours":"4 小时","ExpireTwelve":"12 小时","ImportantNotification":"重要提醒","EmailTip1":"请确认您没有在使用 “","EmailTip2":"隐藏邮件地址","EmailTip3":"” 服务，此类邮箱","EmailTip4":"将无法进行社交恢复，建议更换邮箱","EmailTip5":"。","Buy":"购买","BuyCoins":"买币","BuyCoinsTips":"使用我们的合作伙伴之一直接将信用卡存入您的帐户","Payment":"支付方式","Fee":"手续费","Open":"打开","Scan":"扫码","PaidBy":"UniPass 赞助","YouAreSigning":"您正在签名：","SyncTip":"您的钱包需要在该链上进行同步操作以继续签名","DeployTip":"您的钱包需要在该链上进行部署操作以继续签名","WCWrongLink":"连接失败，请扫描 WalletConnect 的二维码","WCWrongChain":"切换链失败，暂不支持该链","NoClipboardPermission":"操作失败，请开启剪切板权限后重试","NoCameraPermission":"操作失败，请开启相机权限后重试","WCConnectionError":"连接异常，请检查网络后重试","WCConnectTimeout":"连接超时，请刷新 WalletConnect 页面后，使用新二维码重试","UseGoogleOauth":"检测到您正在使用谷歌帐号，请前往谷歌进行验证","UseAuth0Oauth":"<strong>{email}</strong> 已经注册过钱包，请直接使用 Email 进行登录","SignWithGoogle":"前往谷歌验证","SignWithEmail":"前往邮箱验证","WCSwitchChain":"切链成功，请重新请求操作","SignErrorTip":"手续费异常波动，请重试","Connecting":"连接中","ConnectTip4":"钱包将根据 Sign-In with Ethereum 格式执行登录验证签名","SeeSignDetail":"查看签名内容","ConnectAuth":"授权登录","SignIn":"登录","More":"加载更多","Quantity":"数量","Collection":"收藏","PasteWalletConnectCode":"粘贴 WalletConnect 二维码","NotCollections":"您还没有收藏","Protocol":"创建帐户即表示您同意我们的{terms}并已阅读并确认{privacy}","Terms":"条款和条件","Privacy":"隐私政策","AppleIdWithPhoneNumber":"暂不支持与手机号关联的 Apple ID 注册 UniPass，请使用其他方式进行注册","TradingSortTips":"请确保收款地址不是交易所的充值地址","TradingFullTips":"交易所暂不支持来自合约钱包的原生代币充值，您有可能因此丢失充值的资产","TxTip":"发送交易中，请耐心等待…","EnvCheckFailed":"UniPass 可能不支持当前浏览器环境，请使用 Chrome 或 Safari 或其他浏览器打开","SupportedNetworks":"支持的网络","Set4337":"设置 4337","NormalMod":"Normal Mod","4337Mod":"4337 Mod","4337PageTips":"启用 4337 模块后，交易时可以选择 4337 模块","Bundler":"Bundler","Paymaster":"Paymaster","Edit":"编辑","Done":"完成","SwitchEIP4337Tip":"本次修改生效之前需要您进行一笔授权交易，这将会消耗一些手续费，是否继续？","SwitchEIP4337TipAfterSync":"钱包同步已经完成，是否继续进行 4337 模块的激活交易？","AddressInconsistentTip":"地址不匹配，请在应用内重新连接 UniPass 进行验证。","SendEmailCode":"请输入发送至 {email} 的验证码","EmailCode6Digit":"请输入6位邮箱验证码","DisableInIframeEnv":"无法在当前环境下使用，需要在系统浏览器中使用","APDescription":"Action Points（简称 AP）可用于支付和抵扣交易中的 gas 费用"}'
                    ),
                    i = JSON.parse(
                        '{"AccountPending":"Wallet is recovering...","AccountStatus":"Wallet Status:","ActionNotCommitted":"There is a pending action, are you sure you want to exit?","Add":"Add guardians","AddGuardian":"Add Guardian Email","AddGuardianFailed":"Add Guardian Email Failed","AddSuccess":"Add success","AmountOutOfRange":"Your balance is insufficient, the transfer amount will be changed","ApprovalTo":"Approval to","BackToHome":"Return to homepage","Balance":"Balance","Cancel":"Cancel","CastingSuccess":"Verification successful!","ChangeGoogleVerify":"Change google authentication","ChangePassword":"Change Password","ChangePasswordTitle":"To protect your wallet security, it is recommended to enable at least one authentication.","ChangePhoneVerify":"Change SMS authentication","ClosePage":"Close page","codeNotification":"Please enter the verification code that was sent to","codeNotification2":"","SecurityVerification":"Security Verification","CodeWillBeSentTo":"Send verification code to","Confirm":"Confirm","ConfirmNewPassword":"Please confirm the new password","ConfirmPassword":"Repeat password","Connect":"Connect","ConnectSubtitle":"Request to connect to your UniPass wallet","ConnectTip1":"This application will be able to view your address","ConnectTip1Email":"This application will be able to view your address and email","ConnectTip2":"This application is not owned or operated by UniPass","ConnectTip3":"This application cannot transfer your assets without your authorization","ConnectTipJump":"After connecting you will leave UniPass and jump to:","ConnectTitle":"Authorize to Connect","Continue":"Continue","ContractAddress":"Contract address","ContractCall":"Contract call","CopyAddress":"Copy address","CopySuccess":"Copy success","CurrentProgress":"Recovery mode","Delete":"Delete","DeleteSuccess":"Delete success","Deployed":"Deploy wallet","DeployedWalletConfiguration":"Deploy your wallet to the latest status","Details":"Details","DualAuthentication":"Two-Factor Authentication","Email":"Email","EmailCode":"Email verification code","EmailCodeEmpty":"Enter email verification code","EmailEmpty":"Please enter email","EmailVerify":"Email authentication","EmailVerifyTitle":"Email authentication protects your wallet","EmailWrongFormat":"Invalid email format","EnterAmount":"Please enter the amount","EnterEthAddress":"Please enter address (0x) or domain","EnterGoogleCode":"Please enter google code","EnterNewPassword":"Please enter a new password","EnterOldPassword":"Please enter the old password","EnterPassword":"Please enter password","WelcomeBack":"Welcome Back!","WelcomeMessage":"Enter password to unlock your Web3 wallet","EnterPhone":"Please enter phone","EnterPhoneCode":"Please enter SMS code","EnterWallet":"Enter wallet","EthAddress":"Address (0x) or domain","Exit":"Log out","FetchEmailCode":"Get code","Finish":"Success","ForgotPassword":"Forgot password？","FromWeb":"Website:","GasFee":"Gas Fee","GasFeeLoadingFailed":"Gas fee loading failed","GoogleCode":"Google code","GoogleVerify":"Google authentication","GoogleVerifyTitle":"Google authenticator adds another layer of security to your wallet","Guardian":"Guardian","SetGuardians":"Set Guardians","HaveAccount":"Already have an account?","HaveAdded":"Added","HaveWaitingGuardian":"There is a guardian waiting to be confirmed, please wait or delete it","IncorrectAccountOrPassword":"Incorrect account or password","IncorrectCode":"Incorrect verification code","IncorrectMailOrPassword":"Incorrect email or password","IncorrectPassword":"Incorrect password","InsufficientFunds":"Insufficient funds","InvalidAddress":"Invalid address","InvalidInput":"Invalid input","InvitedSuccess":"Invited successfully","Language":"Language","LanguageNow":"English","LogOut":"Log out","LogOutAccount":"Log Out Wallet","Login":"Log in","LoginTitle":"Login UniPass","Maximum":"Max","Message":"Message:","CreateAccountButton":"Create wallet","Network":"Network","NetworkError":"Network error or timeout, please try again later","Newest":"Latest","NextStep":"Next","NoAccount":"Don’t have an account yet?","NoRisk":"No risk","NormalSpeed":"Normal speed","NotDeployed":"Undeployed","NotSupport":"Invalid domain, please check the supported emails","Notification":"Notification","OpenEmailVerify":"Open email authentication","OpenGoogleVerify":"Open google authentication","OpenPhoneVerify":"Open SMS authentication","OwnEmail":"Register email","Password":"Password","PasswordEmpty":"Please enter password","PasswordRule1":"Needs 8-32 characters","PasswordRule2":"At least 1 upper-case letter","PasswordRule3":"At least 1 lower-case letter","PasswordRule4":"At least 1 number","PasswordsNotMatch":"Passwords do not match, please re-enter","PendingUpgrade":"To be synced","Phone":"Phone","PhoneCode":"SMS verification code","PhoneVerify":"SMS authentication","PleaseConfirmPassword":"Please repeat password","PleaseLoginNewPassword":"Please log in with the latest password","RawData":"Raw data","Receive":"Receive","Recovering":"Recovering...","RecoveringNotPending":"Account recovery is complete","RecoveringSubtitle":"Account is undergoing social recovery, the new password will take effect after the countdown","RecoveringTip":"The original password remains valid during recovery","RecoveringTitle":"Account is recovering","Recovery48Hours":"Locked for 48h","RecoveryEmailSame":"This email has been the guardian, please re-enter","RecoveryGuardianSubtitle":"Please go through the security verification process below to complete the account recovery","RecoveryGuardianTitle":"Recovery Security Verification","RecoveryPasswordSubtitle":"Please create your new password","RecoveryPasswordTitle":"Reset Password","RecoveryRestart":"Network error or timeout, please try again later","RecoveryTimeout":"Recovery timeout","RegisterAccount":"Register account","RegisterPasswordSubtitle":"Please create a strong and unique password to protect your Web3 wallet","RegisterTitle":"Create UniPass Wallet","Registering":"Wallet is creating...","RequestSignature":"Request signature","RequestsTooFrequent":"Requests too frequent, please try again later","RequestsExceeded":"The daily request limit has been exceeded, please try again in 24 hours","Resend":"Resend","ResetPasswordTip":"This recovery will take effect after 48 hours, are you sure you want to continue, or invite more guardians to help you with this recovery?","RestoreNow":"Recover immediately","SafetyVerification":"Security verification","SameCase":"Please make sure the case is the same as the actual email","SameCaseDot":"Please make sure the case and the “.” is the same as the actual email","SameDot":"Please make sure the case and the “.” is the same as the actual email","Send":"Send","SendInvitationLink":"Send invitation link","SendSuccess":"Send successfully","SendTitle":"Send assets","SendNFTTitle":"Send NFT","SendTo":"Send to","SendToken":"Send token","Setting":"Account Settings","Setting2faPhoneTitle":"SMS authentication adds another layer of security to your wallet","SettingGuardianSubtitle":"Guardians can help you retrieve your account through email-based social recovery when you forget your password","Sign":"Sign","SignTransaction":"Sign Transaction","Signatory":"Signer:","Submit":"Submit","SupportMail":"Supported Emails:","SupportMailTitle":"Sorry, the email domain you entered is not supported currently","SureLogOut":"Are you sure you want to log out?","Swap":"Swap","SystemBusy":"System is busy, please try again later","ThemeDark":"Dark","ThemeLight":"Light","To2faVerification":"Please complete the 2FA","ToBind":"Bind now","ToLogin":"Log in","ToSignUp":"Sign up","Token":"Tokens","SendNFT":"Send NFT","TotalAmount":"Net Worth","Transfer":"Send","UniPassDKIM":"Because UniPass implements secure, decentralized account recovery by verifying your email provider’s DKIM signature on-chain, we only support email service providers with high credibility.","UpBanner":"You are in testnet, do not deposit any real assets","Update":"Sync wallet","UpdateWalletConfiguration":"Sync your wallet to the latest status","VerifyGoogleTip":"See how to install Google authenticator","VerifyGoogleTitle1":"Please download and install Google authenticator first. And complete the binding through adding a key","VerifyGoogleTitle2":"Please keep this key safe","VerifyPhoneTip":"Please follow the steps to verify your phone.","VerifySubtitle":"To protect your wallet, please complete one of the verifications below","VerifyYourEmail":"Get code to verify your email","Verifying":"Verifying","ViewInExplorer":"View in explorer","Waiting":"Waiting","WaitingRecoveryEmail":"Waiting for recovery email to be sent","SignRequestRejected":"Your sign request has been rejected","SignRequestConfirming":"Please confirm the sign request in your email","Warning":"Attention","isTrading":"Transaction is being processed...","recoveryGuardianTip":"You should notify guardians to send recovery email to assist you in completing the recovery process. Recovery will take effect immediately if enough guardians finished the forwarding.","Verify":"Verify","CancelRecovery":"Cancel recovery","InputYourPassword":"Please input your password.","Insufficient":"Insufficient fund","ToContinueTo":"to continue to","OrEmailLogin":"OR LOG IN THROUGH EMAIL","OrEmailRegister":"OR SIGN UP THROUGH EMAIL","LoginWithGoogle":"Login with Google","SignUpWithGoogle":"Sign up with Google","LoginWithApple":"Login with Apple","SignUpWithApple":"Sign up with Apple","ByCreating":"By creating a UniPass wallet, you agree to our","TermsService":"Terms of Service","PrivacyPolicy":"Privacy Policy","And":"and","EnterPasswordConfirmAdd":"If you want to continue adding, please enter your password to confirm","EnterPasswordConfirmDel":"If you want to continue deleting, please enter your password to confirm","SyncNotification":"Please verify your account before completing this transaction","IsRecovering":"Account is recovering…","GoogleTip":"Google account you verified does not match the account being logged in, please select the following account to authorize<br />“{data}”","GoogleTitle":"Wrong account","TryAgain":"Try again","AuditError":"Verification is expire, please try again","SecurityVerify":"Please verify your account before completing this process","SecurityExpire":"This verification will","ExpireZero":"Expire after one time","ExpireFourHours":"Expire in 4 hours","ExpireTwelve":"Expire in 12 hours","ExpireOneHour":"Expire in 1 hour","ImportantNotification":"Notification","EmailTip1":"Please ensure that you are not using the \\"","EmailTip2":"Hide My Email","EmailTip3":"\\" service. Since","EmailTip4":" this type of email cannot be used for social recovery","EmailTip5":", changing email is advised.","Buy":"Buy","BuyCoins":"Buy coins","BuyCoinsTips":"Deposit with credit card to your account directly using one of our partners","Payment":"Payment","Fee":"Fee","Open":"Open","Scan":"Scan","PaidBy":"Sponsored by UniPass","YouAreSigning":"You are signing:","SyncTip":"Your wallet needs to be synced on this chain to continue signing","DeployTip":"Your wallet needs to be deployed on this chain to continue signing","WCWrongLink":"Connection failed, please scan WalletConnect  QR code","WCWrongChain":"Switch chain failed, this chain is not supported yet","NoClipboardPermission":"Paste failed, please enable clipboard permission and try again","NoCameraPermission":"Open camera failed, please enable the camera permission and try again","WCConnectionError":"Connection error, please check the network and try again","WCConnectTimeout":"Timed out, please refresh WalletConnect page and try again with new QR code","UseGoogleOauth":"You are using Google account, please verify your account to continue","UseAuth0Oauth":"You have already used <strong>{email}</strong>. Please sign in with Email to continue","SignWithGoogle":"Continue with Google","SignWithEmail":"Continue with Email","WCSwitchChain":"Switching chain successfully, please request the operation again","SignErrorTip":"Gas fee abnormal fluctuation, please try again","Connecting":"Connecting","ConnectTip4":"The wallet will execute a Sign-In with Ethereum signature to verify identity","SeeSignDetail":"See signature detail","ConnectAuth":"Authorize to Sign-in","SignIn":"Sign in","More":"More...","Quantity":"Quantity","Collection":"Collection","PasteWalletConnectCode":"Paste WalletConnect code","NotCollections":"You do not own collections yet","Protocol":"By creating an account, you agree to our {terms} and have read and acknowledge {privacy}","Terms":"Terms & Conditions","Privacy":"Privacy Policy","AppleIdWithPhoneNumber":"The Apple ID associated with the phone number is not currently supported for UniPass registration, please use other methods to register","TradingSortTips":"Ensure recipient is not an Exchange address","TradingFullTips":"Exchanges do not automatically detect native token deposits, so there is a risk of losing your assets","TxTip":"Sending transaction, it will take few seconds…","EnvCheckFailed":"UniPass not supported in current browser environment. Please switch to using UniPass in Chrome or Safari","SupportedNetworks":"Supported Networks","Set4337":"Set 4337 Module","NormalMod":"Normal Mode","4337Mod":"4337 Mode","4337PageTips":"After enabling 4337 module, you will be able to select 4337 Mod during transactions","Bundler":"Bundler","Paymaster":"Paymaster","Edit":"Edit","Done":"Done","SwitchEIP4337Tip":"Before activating 4337 module, you need to execute transaction.","SwitchEIP4337TipAfterSync":"The wallet sync is complete. Proceed with 4337 module activation?","AddressInconsistentTip":"Address mismatch. Please reconnect to UniPass in the app for authentication.","SendEmailCode":"Please enter the verification code that was sent to {email}","EmailCode6Digit":"Please enter the 6-digit email verification code","DisableInIframeEnv":"Cannot be used in the current environment, it needs to be used in the system browser","APDescription":"Action Points (AP) are utilized to pay transaction gas fee"}'
                    ),
                    r = n(3542);
                const s = (0, o.o)({
                    globalInjection: !0,
                    legacy: !1,
                    locale: "en",
                    fallbackLocale: "en",
                    messages: { zh: a, en: i, ...r.Z.lang },
                });
                var c = s;
            },
            61072: function (e, t, n) {
                "use strict";
                n.d(t, {
                    Z: function () {
                        return w;
                    },
                });
                var o = n(22483),
                    a = n(60990),
                    i = n(47116),
                    r = n(61481),
                    s = n(41397),
                    c = n(56827),
                    l = n(14052);
                let u = !1;
                const d = async (e) => {
                        if (u) return;
                        const t = (0, r.L)();
                        u = !0;
                        try {
                            if (
                                -1 !==
                                ["/loading", "/wc", "/logout", "/send-code"].indexOf(e.path)
                            )
                                return;
                            return -1 !==
                            ["/register", "/recovery", "/recovery/result", "/404"].indexOf(
                                e.path
                            )
                                ? void (await t.exit())
                                : -1 !== ["/connect"].indexOf(e.path)
                                    ? ((sessionStorage.path = e.path),
                                        (sessionStorage.referrer = window.document.referrer),
                                        void (
                                            (0, c.JN)() && (sessionStorage.redirectUrl = location.href)
                                        ))
                                    : (-1 !==
                                    ["/sign-message", "/send-transaction"].indexOf(e.path) &&
                                    ((sessionStorage.path = e.path),
                                        (sessionStorage.referrer = window.document.referrer),
                                    (0, c.JN)() &&
                                    (sessionStorage.redirectUrl = location.href)),
                                        await t.init("/login" !== e.path),
                                        void (0, s.U1)());
                        } catch (n) {}
                        return { path: "/404" };
                    },
                    g = async () => {
                        const e = (0, r.L)();
                        if (e.isLogin) return { path: "/" };
                    },
                    p = (e, t) => {
                        (0, l.yC)("router_change", { from: t.path, to: e.path });
                    },
                    h = (e, t) => {
                        const n = (0, i.K)();
                        "/" === t.path && n.stop(), "/" === e.path && n.start();
                    },
                    m = n(32814),
                    f = m.keys().map((e) => {
                        const t = e.slice(2);
                        let o = e.slice(1).replace(".vue", "");
                        o.endsWith("/index")
                            ? (o = o.slice(0, -6))
                            : o.endsWith("/_") && (o = `${o.slice(0, -2)}/:pathMatch(.*)*`);
                        const a = () => n(70717)(`./${t}`);
                        return {
                            path: o,
                            component: a,
                            beforeEnter: "/login" === o ? g : void 0,
                        };
                    }),
                    y = (0, o.p7)({ history: (0, o.PO)("/"), routes: f });
                y.afterEach(p), (0, a.iq)(y), y.beforeEach(d), y.beforeEach(h);
                var w = y;
            },
            35351: function (e, t, n) {
                "use strict";
                n.d(t, {
                    Z: function () {
                        return T;
                    },
                });
                var o = n(14052),
                    a = n(61072),
                    i = n(42819),
                    r = n(56265),
                    s = n.n(r),
                    c = n(61481),
                    l = n(24702),
                    u = n(15941);
                const { t: d } = l.Z.global,
                    g = {
                        200: !1,
                        1e3: "RequestsTooFrequent",
                        1001: "IncorrectCode",
                        1002: "IncorrectCode",
                        1006: "RequestsExceeded",
                        1008: !1,
                        1009: "IncorrectCode",
                        2e3: "",
                        3e3: !1,
                        3001: "IncorrectAccountOrPassword",
                        3003: "",
                        3005: !1,
                        3006: !1,
                        3007: "SystemBusy",
                        3008: "",
                        3009: "IncorrectPassword",
                        5e3: !1,
                        5001: !1,
                        5002: !1,
                        5004: !1,
                        5005: "AccountPending",
                        5006: !1,
                        5007: !1,
                        5008: !1,
                        5009: !1,
                        5010: !1,
                        5011: !1,
                        5012: !1,
                        5014: !1,
                        5015: !1,
                        5030: "RequestsTooFrequent",
                        422: !1,
                    },
                    p = (e) => {
                        const t = e.statusCode;
                        if (401 === t || 403 === t) {
                            const e = (0, c.L)();
                            e.exit();
                        }
                        g[t] ? (0, o.E3)(d(g[t])) : u.error("backend error: ", e);
                    },
                    h = (e) => {
                        var t;
                        return (
                            (null !== (t = e.data) && void 0 !== t && t.statusCode) ||
                            (e.data = { ok: !1, statusCode: 404 }),
                                200 === e.data.statusCode
                                    ? (e.data.ok = !0)
                                    : ((e.data.ok = !1), p(e.data)),
                                e.data
                        );
                    };
                var m = n(23269),
                    f = n(26156);
                const { t: y } = l.Z.global,
                    w = s().create({ baseURL: m.e8.urlConfig.backend }),
                    v = "https://indexer.wallet.unipass.id";
                w.interceptors.request.use(
                    function (e) {
                        try {
                            const t = (0, i.Y)();
                            null !== t &&
                            void 0 !== t &&
                            t.authorization &&
                            (e.headers = {
                                ...(null === e || void 0 === e ? void 0 : e.headers),
                                Authorization: `Bearer ${
                                    null === t || void 0 === t ? void 0 : t.authorization
                                }`,
                            });
                        } catch (t) {}
                        return e;
                    },
                    function (e) {
                        return Promise.reject(e);
                    }
                ),
                    w.interceptors.response.use(
                        function (e) {
                            return h(e);
                        },
                        function (e) {
                            return h(e.response);
                        }
                    );
                const S = (e, t = !1) => {
                        if (!1 === t) {
                            const { data: t } = e,
                                n = (t && (t.registerEmail || t.email)) || "";
                            (0, o.yC)("backend_request", { url: e.url || "", email: n });
                        }
                        return w(e);
                    },
                    A = {
                        getConfig() {
                            return S({ method: "get", url: "/api/v1/config" });
                        },
                        sendOtpCode(e) {
                            return S({ method: "post", url: "/api/v1/otp/send", data: e });
                        },
                        verifyOtpCode(e) {
                            return S({ method: "post", url: "/api/v1/otp/verify", data: e });
                        },
                        authToken(e) {
                            return S({ method: "post", url: "/api/v1/token/auth", data: e });
                        },
                        signUpAccount(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/signup",
                                data: e,
                            });
                        },
                        getPasswordToken(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/password.token",
                                data: e,
                            });
                        },
                        login(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/signIn",
                                data: e,
                            });
                        },
                        queryAccountKeyset(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/keyset",
                                data: e,
                            });
                        },
                        queryAccountKeystore(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/keystore",
                                data: e,
                            });
                        },
                        checkProvider(e, t) {
                            return S({
                                method: "get",
                                url: "/api/v1/email/provider.check",
                                params: { email: e, source: t },
                            });
                        },
                        sendCode(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/oauth/send",
                                data: { email: e, sendType: "email" },
                            });
                        },
                        verifyCode(e, t) {
                            return S({
                                method: "post",
                                url: "/api/v1/oauth/login",
                                data: { email: e, code: t },
                            });
                        },
                        uploadRecoveryMasterKey(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/recovery/upload.key",
                                data: e,
                            });
                        },
                        sendRecoveryEmail(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/recovery/guardian.send.email",
                                data: e,
                            });
                        },
                        startRecovery(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/recovery/start",
                                data: e,
                            });
                        },
                        sendRecoveryStatus(e) {
                            return S(
                                {
                                    method: "post",
                                    url: "/api/v1/account/recovery/guardian.email.status",
                                    data: { email: e },
                                },
                                !0
                            );
                        },
                        cancelRecovery(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/recovery/cancel",
                                data: e,
                            });
                        },
                        onRampUrl(e) {
                            return S({
                                method: "get",
                                url: "/api/v1/account/on.ramp.url",
                                params: e,
                            });
                        },
                        startKeygen(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/tss/keygen/start",
                                data: e,
                            });
                        },
                        getKeygen(e) {
                            return S({ method: "post", url: "/api/v1/tss/keygen", data: e });
                        },
                        finishKeygen(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/tss/keygen/finish",
                                data: e,
                            });
                        },
                        startSign(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/tss/sign/start",
                                data: e,
                            });
                        },
                        sign(e) {
                            return S({ method: "post", url: "/api/v1/tss/sign", data: e });
                        },
                        async audit(e) {
                            const t = (0, f.$)() || "",
                                n = await S({
                                    method: "post",
                                    url: "/api/v1/tss/audit",
                                    data: e,
                                    headers: { "up-sign-token": t },
                                });
                            return (
                                200 !== n.statusCode &&
                                (a.Z.replace("/"), (0, o.E3)(y("AuditError"))),
                                    n
                            );
                        },
                        signToken(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/tss/sign.token",
                                data: e,
                            });
                        },
                        getGoogleAuthenticatorQRCode() {
                            return S({ method: "post", url: "/api/v1/2fa/ga/qrcode" });
                        },
                        addAuthenticator(e) {
                            return S({ method: "post", url: "/api/v1/2fa/add", data: e });
                        },
                        authenticatorStatus(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/2fa/open.status",
                                data: e,
                            });
                        },
                        authenticatorList(e) {
                            return S({ method: "post", url: "/api/v1/2fa/list", data: e });
                        },
                        upSignToken(e, t, n) {
                            return S({
                                method: "post",
                                url: "/api/v1/2fa/up-sign-token",
                                data: { code: e, authType: t, requestTokenDuration: n },
                            });
                        },
                        sendRecoveryOAuthSig(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/recovery/auth.oauth",
                                data: e,
                            });
                        },
                        sendSyncOAuthSig(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/sync/auth.oauth",
                                data: e,
                            });
                        },
                        sendGuardianLink(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/guardian.link",
                                data: e,
                            });
                        },
                        getGuardianToken(e) {
                            return S(
                                {
                                    method: "post",
                                    url: "/api/v1/account/guardian.status",
                                    data: { registerEmail: e },
                                },
                                !0
                            );
                        },
                        checkKeyset(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/keyset.check",
                                data: e,
                            });
                        },
                        updateGuardian(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/guardian.update",
                                data: e,
                            });
                        },
                        syncUpdate() {
                            return S({ method: "post", url: "/api/v1/account/sync.update" });
                        },
                        getSyncStatus(e) {
                            return S(
                                { method: "post", url: "/api/v1/sync/status", data: e },
                                !0
                            );
                        },
                        getTokenList(e, t = 1) {
                            return S(
                                {
                                    method: "get",
                                    url: "/api/v1/token/list",
                                    params: { chainId: e, includeNativeToken: t },
                                },
                                !0
                            );
                        },
                        getTokenBalances(e, t) {
                            return S(
                                {
                                    baseURL: v,
                                    method: "get",
                                    url: "/api/v1/token/balances",
                                    params: { chainId: e, address: t },
                                },
                                !0
                            );
                        },
                        getTokenPrices(e, t) {
                            return S(
                                {
                                    baseURL: v,
                                    method: "get",
                                    url: "/api/v1/token/prices",
                                    params: { chainId: e, contracts: t.join(",") },
                                },
                                !0
                            );
                        },
                        getPriceConversion(e) {
                            return S(
                                {
                                    method: "post",
                                    url: "/api/v1/account/token/price",
                                    data: { id: e },
                                },
                                !0
                            );
                        },
                        getAccountTokens(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/erc20/tokens",
                                data: e,
                            });
                        },
                        getAccountCollection(e) {
                            return S({
                                method: "get",
                                url: "/api/v1/account/nft/collection",
                                params: e,
                            });
                        },
                        getAccountNFT(e) {
                            return S({
                                method: "get",
                                url: "/api/v1/account/nft/tokens",
                                params: e,
                            });
                        },
                        getAccountNFTImage(e) {
                            return S({
                                method: "get",
                                url: "/api/v1/account/nft/images",
                                params: e,
                            });
                        },
                        policySign(e) {
                            return S({
                                method: "post",
                                url: "/api/v1/account/policy/sign",
                                data: e,
                            });
                        },
                        fetchApBalance() {
                            return S({ method: "get", url: "api/v1/ap/show/balance" });
                        },
                    };
                var T = A;
            },
            68466: function (e, t, n) {
                "use strict";
                n.d(t, {
                    OR: function () {
                        return m;
                    },
                    bD: function () {
                        return v;
                    },
                });
                var o = n(72043),
                    a = n(9635),
                    i = n(63013),
                    r = n(98074),
                    s = n(91856),
                    c = n(25490),
                    l = n(53380),
                    u = n(93130),
                    d = n(23269),
                    g = n(15941);
                let p, h;
                const m = () => {
                        const e = "mainnet";
                        return "mainnet" !== e && "preview" !== e
                            ? c.TESTNET_UNIPASS_WALLET_CONTEXT
                            : c.MAINNET_UNIPASS_WALLET_CONTEXT;
                    },
                    f = m().moduleMain,
                    y =
                        (m().dkimKeys,
                            () => {
                                p ||
                                ((p = new a.r(
                                    "https://node.wallet.unipass.id/polygon-mainnet"
                                )),
                                    (h = new i.CH(f, s.moduleMain.abi, p)));
                            }),
                    w = {
                        getProvider() {
                            return (
                                (p = new a.r("https://node.wallet.unipass.id/polygon-mainnet")),
                                    p
                            );
                        },
                        async isRegistered(e) {
                            y();
                            const t = await p.getCode(e);
                            return "0x" !== t;
                        },
                        async getMetaNonce(e) {
                            y();
                            const t = h.attach(e);
                            let n = 0;
                            try {
                                n = await t.getMetaNonce();
                            } catch (o) {}
                            return Number(n.toString()) + 1;
                        },
                        async getAccountInfo(e, t) {
                            y();
                            try {
                                const n = [
                                    {
                                        target: e,
                                        call: ["getKeysetHash()(bytes32)"],
                                        returns: [["KEYSET_HASH", (e) => e]],
                                    },
                                    {
                                        target: e,
                                        call: ["getLockInfo()(bytes32)"],
                                        type: [
                                            [
                                                {
                                                    internalType: "bool",
                                                    name: "isLockedRet",
                                                    type: "bool",
                                                },
                                                {
                                                    internalType: "uint32",
                                                    name: "lockDuringRet",
                                                    type: "uint32",
                                                },
                                                {
                                                    internalType: "bytes32",
                                                    name: "lockedKeysetHashRet",
                                                    type: "bytes32",
                                                },
                                                {
                                                    internalType: "uint256",
                                                    name: "unlockAfterRet",
                                                    type: "uint256",
                                                },
                                            ],
                                        ],
                                        returns: [["LOCK_INFO", (e) => e]],
                                    },
                                ];
                                t &&
                                n.push({
                                    target: e,
                                    call: ["isValidKeysetHash(bytes32)(bool)", t],
                                    returns: [["IS_VALID_KEYSET_HASH", (e) => e]],
                                });
                                const o = await (0, l.m)(n, {
                                    multicallAddress: u.bh,
                                    rpcUrl: "https://node.wallet.unipass.id/polygon-mainnet",
                                });
                                let a = o.results.transformed["KEYSET_HASH"];
                                const i = o.results.transformed["LOCK_INFO"],
                                    r = i.isLockedRet,
                                    s = i.lockedKeysetHashRet,
                                    c = Number(i.unlockAfterRet),
                                    d = i.lockDuringRet;
                                return (
                                    t &&
                                    !0 === o.results.transformed["IS_VALID_KEYSET_HASH"] &&
                                    (a = t),
                                        {
                                            isPending: r,
                                            pendingKeysetHash: s,
                                            keysetHash: a,
                                            unlockTime: c,
                                            lockDuration: d,
                                        }
                                );
                            } catch (n) {
                                throw (g.error("multicall getAccountInfo", n), n);
                            }
                        },
                        async getERC20TokenInfo(e, t) {
                            y();
                            try {
                                const n = [
                                        {
                                            target: e,
                                            call: ["symbol()(string)"],
                                            returns: [["SYMBOL", (e) => e]],
                                        },
                                        {
                                            target: e,
                                            call: ["decimals()(uint8)"],
                                            returns: [["DECIMALS", (e) => e]],
                                        },
                                        {
                                            target: e,
                                            call: ["totalSupply()(uint256)"],
                                            returns: [["TOTAL_SUPPLY", (e) => e]],
                                        },
                                    ],
                                    o = await (0, l.m)(n, {
                                        multicallAddress: u.bh,
                                        rpcUrl: (0, d.Z1)((0, d.BR)(t)),
                                    }),
                                    a = o.results.transformed["SYMBOL"],
                                    i = o.results.transformed["DECIMALS"],
                                    r = o.results.transformed["TOTAL_SUPPLY"];
                                return {
                                    symbol: a,
                                    decimals: i,
                                    contractAddress: e,
                                    totalSupply: r,
                                    isERC20: !!a && r.gt(0),
                                };
                            } catch (n) {
                                return (
                                    g.error("getERC20TokenInfo: ", n),
                                        {
                                            symbol: "",
                                            decimals: 18,
                                            contractAddress: e,
                                            totalSupply: o.O$.from(0),
                                            isERC20: !1,
                                        }
                                );
                            }
                        },
                        generateAccountAddress(e) {
                            return y(), (0, r.getWalletAddress)(f, e);
                        },
                    },
                    v = async (e, t) => {
                        if (!t) return;
                        let n;
                        await new Promise((o) => {
                            t.on("block", (a) => {
                                n ? a >= n + e && (o(a), t.off("block")) : (n = a);
                            });
                        });
                    };
                t["ZP"] = w;
            },
            23269: function (e, t, n) {
                "use strict";
                n.d(t, {
                    BR: function () {
                        return y;
                    },
                    IA: function () {
                        return l;
                    },
                    K1: function () {
                        return u;
                    },
                    Of: function () {
                        return p;
                    },
                    Z1: function () {
                        return w;
                    },
                    _M: function () {
                        return m;
                    },
                    a2: function () {
                        return S;
                    },
                    c: function () {
                        return d;
                    },
                    e8: function () {
                        return s;
                    },
                    hZ: function () {
                        return h;
                    },
                    qz: function () {
                        return c;
                    },
                    tA: function () {
                        return g;
                    },
                    tJ: function () {
                        return A;
                    },
                    uV: function () {
                        return v;
                    },
                    z5: function () {
                        return f;
                    },
                });
                n(21703);
                var o = n(4369),
                    a = n(93130),
                    i = n(54419);
                const r = () => {
                        const e = "mainnet";
                        let t,
                            n = "testnet";
                        return (
                            "dev" === e
                                ? (t = o.dev_api_config)
                                : "test" === e
                                    ? (t = o.test_api_config)
                                    : "testnet" === e
                                        ? (t = o.testnet_api_config)
                                        : "preview" === e
                                            ? ((n = "mainnet"), (t = o.mainnet_preview_api_config))
                                            : "mainnet" === e
                                                ? ((n = "mainnet"), (t = o.mainnet_api_config))
                                                : (t = o.testnet_api_config),
                                { net: n, urlConfig: t }
                        );
                    },
                    s = r(),
                    c = (e) => {
                        if (!e) return "";
                        const t = {
                            bsc: "BSC",
                            polygon: "Polygon",
                            rangers: "Rangers",
                            eth: "ETH",
                            scroll: "Scroll",
                            arbitrum: "Arbitrum",
                            avalanche: "Avalanche",
                            kcc: "KCC",
                            platon: "PlatOn",
                        };
                        return t[e];
                    },
                    l = () => {
                        const e = "mainnet";
                        let t = "testnet";
                        return (
                            "dev" === e || "test" === e || "testnet" === e
                                ? (t = "testnet")
                                : ("preview" === e || "mainnet" === e) && (t = "mainnet"),
                                t
                        );
                    },
                    u = (e) => {
                        const t = l();
                        if ("testnet" === t)
                            switch (e) {
                                case "eth":
                                    return "eth-goerli";
                                case "polygon":
                                    return "polygon-mumbai";
                                case "bsc":
                                    return "bsc-testnet";
                                case "rangers":
                                    return "rangers-robin";
                                case "scroll":
                                    return "scroll-testnet";
                                case "arbitrum":
                                    return "arbitrum-testnet";
                                case "avalanche":
                                    return "avalanche-testnet";
                                case "kcc":
                                    return "kcc-testnet";
                                case "platon":
                                    return "platon-testnet";
                                default:
                                    return "polygon-mumbai";
                            }
                        else if ("mainnet" === t)
                            switch (e) {
                                case "eth":
                                    return "eth-mainnet";
                                case "polygon":
                                    return "polygon-mainnet";
                                case "bsc":
                                    return "bsc-mainnet";
                                case "rangers":
                                    return "rangers-mainnet";
                                case "arbitrum":
                                    return "arbitrum-mainnet";
                                case "avalanche":
                                    return "avalanche-mainnet";
                                case "kcc":
                                    return "kcc-mainnet";
                                case "platon":
                                    return "platon-mainnet";
                                default:
                                    return "polygon-mainnet";
                            }
                        return "polygon-mumbai";
                    },
                    d = () => {
                        const e = l();
                        return "testnet" === e ? a.oR : "mainnet" === e ? a.Ow : [];
                    },
                    g = () => {
                        const e = l();
                        return "testnet" === e ? a.RI : "mainnet" === e ? a.eF : a.RI;
                    },
                    p = () => {
                        const e = sessionStorage.getItem("chainId");
                        return e && (0, i.hj)(parseInt(e)) ? Number(e) : g();
                    },
                    h = (e) => {
                        switch (Number(e)) {
                            case a.BT:
                            case a.Uw:
                                return "eth";
                            case a.eF:
                            case a.RI:
                                return "polygon";
                            case a.WG:
                            case a.nU:
                                return "bsc";
                            case a.ik:
                            case a.sw:
                                return "rangers";
                            case a.yd:
                                return "scroll";
                            case a.qF:
                            case a.Gh:
                                return "arbitrum";
                            case a.t1:
                            case a.et:
                                return "avalanche";
                            case a.$W:
                            case a.Dz:
                                return "kcc";
                            case a.R2:
                                return "platon";
                            default:
                                return "polygon";
                        }
                    },
                    m = (e) => {
                        switch (Number(e)) {
                            case a.BT:
                            case a.Uw:
                                return "Etherscan";
                            case a.eF:
                            case a.RI:
                                return "Polygonscan";
                            case a.WG:
                            case a.nU:
                                return "Bscscan";
                            case a.qF:
                            case a.Gh:
                                return "Arbiscan";
                            case a.t1:
                            case a.et:
                                return "Snowtrace";
                            case a.$W:
                            case a.Dz:
                                return "KCC";
                            default:
                                return "Polygonscan";
                        }
                    },
                    f = (e) => {
                        const t = l();
                        return "mainnet" === t ? a.W5[e] || [] : a.es[e] || [];
                    },
                    y = (e) => {
                        const t = l();
                        switch (e) {
                            case "polygon":
                                return "mainnet" === t ? a.eF : a.RI;
                            case "eth":
                                return "mainnet" === t ? a.BT : a.Uw;
                            case "bsc":
                                return "mainnet" === t ? a.WG : a.nU;
                            case "rangers":
                                return "mainnet" === t ? a.ik : a.sw;
                            case "arbitrum":
                                return "mainnet" === t ? a.Gh : a.qF;
                            case "scroll":
                                return "mainnet" === t ? -1 : a.yd;
                            case "avalanche":
                                return "mainnet" === t ? a.et : a.t1;
                            case "kcc":
                                return "mainnet" === t ? a.Dz : a.$W;
                            case "platon":
                                return "mainnet" === t ? -1 : a.R2;
                            default:
                                throw new Error(`Not Support Chain: ${e}`);
                        }
                    },
                    w = (e) => {
                        switch (e) {
                            case a.BT:
                            case a.Uw:
                                return "https://node.wallet.unipass.id/eth-mainnet";
                            case a.eF:
                            case a.RI:
                                return "https://node.wallet.unipass.id/polygon-mainnet";
                            case a.WG:
                            case a.nU:
                                return "https://node.wallet.unipass.id/bsc-mainnet";
                            case a.ik:
                            case a.sw:
                                return "https://node.wallet.unipass.id/rangers-mainnet";
                            case a.yd:
                                return {
                                    NODE_ENV: "production",
                                    VUE_APP_Net: "mainnet",
                                    VUE_APP_UniPass_GA: "G-HNDL91TELQ",
                                    VUE_APP_UniPass_Sentry:
                                        "https://646c1ae7726342c9a2d3a8b91d8b2b8b@sentry.unipass.id/2",
                                    VUE_APP_UniPass_reCAPTCHA:
                                        "6LfGwdckAAAAAGHImpxNZ0AJ_QyPCMyVPZmzFClY",
                                    VUE_APP_UniPass_Paymaster:
                                        "https://wallet.unipass.id/paymaster/",
                                    VUE_APP_Permit_Weight: "100",
                                    VUE_APP_Polygon_RPC:
                                        "https://node.wallet.unipass.id/polygon-mainnet",
                                    VUE_APP_Polygon_Explorer: "https://polygonscan.com",
                                    VUE_APP_Polygon_USDC: "",
                                    VUE_APP_Polygon_USDT: "",
                                    VUE_APP_BSC_RPC: "https://node.wallet.unipass.id/bsc-mainnet",
                                    VUE_APP_BSC_Explorer: "https://bscscan.com",
                                    VUE_APP_BSC_USDC: "",
                                    VUE_APP_BSC_USDT: "",
                                    VUE_APP_Rangers_RPC:
                                        "https://node.wallet.unipass.id/rangers-mainnet",
                                    VUE_APP_Rangers_Explorer: "https://scan.rangersprotocol.com",
                                    VUE_APP_Rangers_USDT:
                                        "0x8e8816a1747fddc5f8b45d2e140a425d3788f659",
                                    VUE_APP_ETH_RPC: "https://node.wallet.unipass.id/eth-mainnet",
                                    VUE_APP_ETH_Explorer: "https://etherscan.io",
                                    VUE_APP_ETH_USDC: "",
                                    VUE_APP_ARBITRUM_RPC:
                                        "https://node.wallet.unipass.id/arbitrum-mainnet",
                                    VUE_APP_ARBITRUM_Explorer: "https://arbiscan.io",
                                    VUE_APP_AVALANCHE_RPC:
                                        "https://node.wallet.unipass.id/avalanche-mainnet",
                                    VUE_APP_AVALANCHE_Explorer: "https://snowtrace.io",
                                    VUE_APP_KCC_RPC: "https://node.wallet.unipass.id/kcc-mainnet",
                                    VUE_APP_KCC_Explorer: "https://explorer.kcc.io",
                                    VUE_APP_OKC_RPC: "https://node.wallet.unipass.id/okc-mainnet",
                                    VUE_APP_OKC_Explorer: "https://www.oklink.com/okc",
                                    VUE_APP_PLATON_RPC:
                                        "https://node.wallet.unipass.id/platon-mainnet",
                                    VUE_APP_PLATON_Explorer: "https://scan.platon.network",
                                    BASE_URL: "/",
                                }.VUE_APP_SCROLL_RPC;
                            case a.Gh:
                            case a.qF:
                                return "https://node.wallet.unipass.id/arbitrum-mainnet";
                            case a.et:
                            case a.t1:
                                return "https://node.wallet.unipass.id/avalanche-mainnet";
                            case a.Dz:
                            case a.$W:
                                return "https://node.wallet.unipass.id/kcc-mainnet";
                            case a.R2:
                                return "https://node.wallet.unipass.id/platon-mainnet";
                        }
                    },
                    v = (e) => {
                        switch (e) {
                            case a.BT:
                            case a.Uw:
                            case a.yd:
                            case a.Gh:
                            case a.qF:
                                return "ETH";
                            case a.eF:
                            case a.RI:
                                return "MATIC";
                            case a.WG:
                            case a.nU:
                                return "BNB";
                            case a.ik:
                            case a.sw:
                                return "RPG";
                            case a.et:
                            case a.t1:
                                return "AVAX";
                            case a.Dz:
                            case a.$W:
                                return "KCS";
                            case a.R2:
                                return "LAT";
                            default:
                                return "MATIC";
                        }
                    },
                    S = d().map((e) => ({ label: c(h(e)), value: e.toString() })),
                    A = (e) => {
                        const t = l();
                        if ("testnet" === t)
                            switch (e) {
                                case "eth":
                                    return "https://bundler.wallet.unipass.id/eth-goerli/";
                                case "polygon":
                                    return "https://bundler.wallet.unipass.id/polygon-mumbai/";
                            }
                        else if ("mainnet" === t)
                            switch (e) {
                                case "eth":
                                    return "https://bundler.wallet.unipass.id/eth-mainnet/";
                                case "polygon":
                                    return "https://bundler.wallet.unipass.id/polygon-mainnet/";
                            }
                        return "https://bundler.wallet.unipass.id/eth-goerli/";
                    };
            },
            56827: function (e, t, n) {
                "use strict";
                n.d(t, {
                    BX: function () {
                        return l;
                    },
                    F_: function () {
                        return c;
                    },
                    JN: function () {
                        return s;
                    },
                    Sr: function () {
                        return a;
                    },
                    Zh: function () {
                        return o;
                    },
                    cr: function () {
                        return r;
                    },
                    fl: function () {
                        return i;
                    },
                });
                const o = () => {
                        var e, t;
                        return !(
                            null === (e = window) ||
                            void 0 === e ||
                            null === (t = e.flutter_inappwebview) ||
                            void 0 === t ||
                            !t.callHandler
                        );
                    },
                    a = () => !!window.opener || "UNIPASS_IFRAME" === window.name,
                    i = () => !!window.vuplex,
                    r = () => {
                        var e, t;
                        return !(
                            null === (e = window) ||
                            void 0 === e ||
                            null === (t = e.ue) ||
                            void 0 === t ||
                            !t.unipass
                        );
                    },
                    s = () => {
                        const e = new URL(
                                sessionStorage.redirectUrl || window.location.href
                            ),
                            t = e.searchParams.get("redirectUrl");
                        return t && "string" === typeof t;
                    },
                    c = () => {
                        var e;
                        return a()
                            ? "popup"
                            : o()
                                ? "flutter"
                                : i()
                                    ? "unity"
                                    : r() || (null !== (e = window) && void 0 !== e && e.ue)
                                        ? "unreal"
                                        : s()
                                            ? "redirect"
                                            : "origin";
                    },
                    l = () => "UNIPASS_IFRAME" === window.name;
            },
            93130: function (e, t, n) {
                "use strict";
                n.d(t, {
                    $W: function () {
                        return A;
                    },
                    BT: function () {
                        return c;
                    },
                    Dz: function () {
                        return T;
                    },
                    Gh: function () {
                        return w;
                    },
                    Ow: function () {
                        return k;
                    },
                    R2: function () {
                        return _;
                    },
                    RI: function () {
                        return d;
                    },
                    RZ: function () {
                        return s;
                    },
                    Uw: function () {
                        return l;
                    },
                    W5: function () {
                        return P;
                    },
                    WG: function () {
                        return g;
                    },
                    bh: function () {
                        return a;
                    },
                    eF: function () {
                        return u;
                    },
                    es: function () {
                        return C;
                    },
                    et: function () {
                        return S;
                    },
                    fi: function () {
                        return i;
                    },
                    ik: function () {
                        return h;
                    },
                    je: function () {
                        return o;
                    },
                    nU: function () {
                        return p;
                    },
                    oR: function () {
                        return E;
                    },
                    qF: function () {
                        return y;
                    },
                    sw: function () {
                        return m;
                    },
                    t1: function () {
                        return v;
                    },
                    uh: function () {
                        return r;
                    },
                    yd: function () {
                        return f;
                    },
                });
                const o = "0x0000000000000000000000000000000000000000",
                    a = "0x175d02d277eac0838af14D09bf59f11B365BAB42",
                    i = "0xD46c1a3D33ab419F58a524a880f6BAc0E17553e5",
                    r = "0x0576a174D229E3cFA37253523E645A78A0C91B57",
                    s = "https://wallet.unipass.id/paymaster/",
                    c = 1,
                    l = 5,
                    u = 137,
                    d = 80001,
                    g = 56,
                    p = 97,
                    h = 2025,
                    m = 9527,
                    f = 534353,
                    y = 421613,
                    w = 42161,
                    v = 43113,
                    S = 43114,
                    A = 322,
                    T = 321,
                    _ = 2206132,
                    C = {
                        [l]: ["alchemyPay", "fatPay", "binanceConnect"],
                        [d]: ["alchemyPay", "fatPay", "binanceConnect"],
                        [p]: ["alchemyPay", "fatPay", "binanceConnect"],
                        [m]: ["alchemyPay"],
                        [y]: ["alchemyPay", "binanceConnect"],
                        [f]: [],
                        [v]: [],
                        [A]: [],
                        [_]: [],
                    },
                    P = {
                        [c]: ["alchemyPay", "fatPay", "binanceConnect"],
                        [u]: ["alchemyPay", "fatPay", "binanceConnect"],
                        [g]: ["alchemyPay", "fatPay", "binanceConnect"],
                        [h]: ["alchemyPay"],
                        [w]: ["alchemyPay", "binanceConnect"],
                        [S]: [],
                        [T]: [],
                    },
                    E = [l, p, d, f, y, v, A, m, _],
                    k = [c, g, u, w, S, T, h];
            },
            45358: function (e, t, n) {
                "use strict";
                var o, a, i, r, s, c;
                n.d(t, {
                    Av: function () {
                        return r;
                    },
                    D2: function () {
                        return s;
                    },
                    O4: function () {
                        return o;
                    },
                    S: function () {
                        return i;
                    },
                    Uo: function () {
                        return c;
                    },
                    Ws: function () {
                        return a;
                    },
                }),
                    (function (e) {
                        (e[(e["GOOGLE"] = 0)] = "GOOGLE"),
                            (e[(e["AUTH0"] = 1)] = "AUTH0"),
                            (e[(e["APPLE"] = 2)] = "APPLE"),
                            (e[(e["UNIPASS"] = 3)] = "UNIPASS"),
                            (e[(e["CUSTODIAL"] = 4)] = "CUSTODIAL");
                    })(o || (o = {})),
                    (function (e) {
                        (e[(e["MPC"] = 0)] = "MPC"),
                            (e[(e["SNAP"] = 1)] = "SNAP"),
                            (e[(e["METAMASK"] = 2)] = "METAMASK"),
                            (e[(e["AWS_KMS"] = 3)] = "AWS_KMS");
                    })(a || (a = {})),
                    (function (e) {
                        (e[(e["Synced"] = 0)] = "Synced"),
                            (e[(e["ServerSynced"] = 1)] = "ServerSynced"),
                            (e[(e["NotReceived"] = 2)] = "NotReceived"),
                            (e[(e["NotSynced"] = 3)] = "NotSynced");
                    })(i || (i = {})),
                    (function (e) {
                        (e[(e["PersonalSign"] = 0)] = "PersonalSign"),
                            (e[(e["EIP712Sign"] = 1)] = "EIP712Sign"),
                            (e[(e["Transaction"] = 2)] = "Transaction");
                    })(r || (r = {})),
                    (function (e) {
                        (e[(e["Approved"] = 0)] = "Approved"),
                            (e[(e["Rejected"] = 1)] = "Rejected"),
                            (e[(e["Confirming"] = 2)] = "Confirming");
                    })(s || (s = {})),
                    (function (e) {
                        (e["v1"] = "V1"), (e["v4"] = "V4");
                    })(c || (c = {}));
            },
            99040: function (e, t, n) {
                "use strict";
                n.d(t, {
                    L: function () {
                        return i;
                    },
                    o: function () {
                        return a;
                    },
                });
                var o = n(26639);
                const a = (e, t = 18) => o.formatUnits(e, t),
                    i = (e, t = 18) => o.parseUnits(e, t);
            },
            16775: function (e, t, n) {
                "use strict";
                n.d(t, {
                    RJ: function () {
                        return P;
                    },
                    Xm: function () {
                        return E;
                    },
                    _U: function () {
                        return b;
                    },
                    y4: function () {
                        return k;
                    },
                });
                var o = n(86550),
                    a = n(72043),
                    i = n(41152),
                    r = n(70498),
                    s = n(47116),
                    c = n(61481),
                    l = n(14052),
                    u = n(93130),
                    d = n(14041),
                    g = n(56265),
                    p = n.n(g),
                    h = n(63013),
                    m = n(4369);
                const f = [
                        {
                            constant: !0,
                            inputs: [{ name: "", type: "bytes4" }],
                            name: "entries",
                            outputs: [{ name: "", type: "string" }],
                            payable: !1,
                            type: "function",
                        },
                    ],
                    y = { a22cb465: "setApprovalForAll" },
                    w = async (e) => {
                        if (!e.startsWith("0x") || e.length < 10) return "unknown";
                        try {
                            var t;
                            const n = e.slice(2, 10);
                            if (y[n]) return y[n];
                            const o = m.chain_config["eth-mainnet"].rpc_url,
                                a = p().create({ baseURL: o }),
                                i = await a.post("", {
                                    jsonrpc: "2.0",
                                    id: 3,
                                    method: "eth_call",
                                    params: [
                                        {
                                            from: "0x0000000000000000000000000000000000000000",
                                            data: `0xb46bcdaa${n}00000000000000000000000000000000000000000000000000000000`,
                                            to: "0x44691b39d1a75dc4e0a0346cbb15e310e6ed1e86",
                                        },
                                        "latest",
                                    ],
                                }),
                                r = new h.CH("0x44691b39d1a75dc4e0a0346cbb15e310e6ed1e86", f),
                                s = r.interface.decodeFunctionResult("entries", i.data.result);
                            if (!s || "" === s.toString()) return "unknown";
                            const c =
                                null !== (t = s.toString().split("(")[0]) && void 0 !== t
                                    ? t
                                    : "unknown";
                            return c;
                        } catch (n) {
                            return "unknown";
                        }
                    };
                var v = n(99040),
                    S = n(68466),
                    A = n(43395);
                const { Interface: T, formatEther: _, parseEther: C } = o,
                    P = async (e, t) => {
                        const n = (0, c.L)(),
                            o = (0, s.K)(),
                            i = (0, r.Y)();
                        if (!t) return void (0, l.E3)("chain not found");
                        const g = o.coins.find(
                            (e) => e.chain === t && e.contractAddress === u.je
                        );
                        if (g) {
                            if (
                                (i.updateSymbolAndChain(g.chain),
                                    (0, d.W)(e.from, n.accountInfo.address))
                            ) {
                                if (e.data && "0x" !== e.data) {
                                    const n = await w(e.data),
                                        i = [
                                            "function transfer(address _to, uint256 _value)",
                                            "function safeTransferFrom(address _from, address _to, uint256 _tokenId)",
                                            "function safeTransferFrom(address _from, address _to, uint256 _id, uint256 _amount, bytes _data)",
                                        ],
                                        r = new T(i);
                                    try {
                                        const i = r.parseTransaction({ data: e.data });
                                        if ("transfer" === i.name) {
                                            const a = o.coins.find(
                                                (n) =>
                                                    n.chain === t && (0, d.W)(n.contractAddress, e.to)
                                            );
                                            if (a) {
                                                const e = (0, v.o)(i.args[1], a.decimals),
                                                    t = i.args[0];
                                                return [
                                                    {
                                                        show: !0,
                                                        type: "send-token",
                                                        tokenType: "erc20",
                                                        data: {
                                                            amount: e,
                                                            address: t,
                                                            symbol: a.symbol,
                                                            chain: a.chain,
                                                            decimals: a.decimals,
                                                        },
                                                        actionName: n,
                                                    },
                                                ];
                                            }
                                            {
                                                const o = await S.ZP.getERC20TokenInfo(e.to, t);
                                                if (o.isERC20) {
                                                    const e = (0, v.o)(i.args[1], o.decimals),
                                                        a = i.args[0];
                                                    return [
                                                        {
                                                            show: !0,
                                                            type: "send-token",
                                                            tokenType: "erc20",
                                                            data: {
                                                                amount: e,
                                                                address: a,
                                                                symbol: o.symbol,
                                                                chain: t,
                                                                decimals: o.decimals,
                                                            },
                                                            actionName: n,
                                                        },
                                                    ];
                                                }
                                            }
                                        } else if ("safeTransferFrom" === i.name) {
                                            if (3 === i.functionFragment.inputs.length)
                                                return [
                                                    {
                                                        show: !0,
                                                        type: "send-nft",
                                                        tokenType: "erc721",
                                                        data: {
                                                            chain: t,
                                                            symbol: g.symbol,
                                                            address: i.args[1],
                                                            contractAddress: e.to,
                                                            tokenId: a.O$.from(i.args[2]),
                                                            amount: a.O$.from(1),
                                                        },
                                                        actionName: n,
                                                    },
                                                ];
                                            if (5 === i.functionFragment.inputs.length)
                                                return [
                                                    {
                                                        show: !0,
                                                        type: "send-nft",
                                                        tokenType: "erc1155",
                                                        data: {
                                                            chain: t,
                                                            symbol: g.symbol,
                                                            address: i.args[1],
                                                            contractAddress: e.to,
                                                            tokenId: a.O$.from(i.args[2]),
                                                            amount: a.O$.from(i.args[3]),
                                                        },
                                                        actionName: n,
                                                    },
                                                ];
                                        }
                                    } catch (p) {}
                                    return [
                                        {
                                            show: !0,
                                            type: "contract-call",
                                            tokenType: "contract",
                                            data: {
                                                data: e.data,
                                                to: e.to,
                                                symbol: g.symbol,
                                                chain: g.chain,
                                                value: e.value,
                                            },
                                            actionName: n,
                                        },
                                    ];
                                }
                                return [
                                    {
                                        show: !0,
                                        type: "send-token",
                                        tokenType: "native",
                                        data: {
                                            amount: _(e.value && "0x" !== e.value ? e.value : 0),
                                            address: e.to,
                                            symbol: g.symbol,
                                            chain: g.chain,
                                            decimals: 18,
                                        },
                                    },
                                ];
                            }
                            (0, A.DR)({ type: "UP_SIGN_TRANSACTION" });
                        } else (0, l.E3)("coin not found");
                    },
                    E = (e) => {
                        const t = (0, s.K)(),
                            n = (0, c.L)(),
                            {
                                chain: o,
                                symbol: a,
                                address: r,
                                amount: l,
                                nftType: d,
                                nftTokenId: g,
                                contractAddress: p,
                            } = e;
                        if ("ERC1155" === d) {
                            if (!p) return;
                            const e = new i.vU([
                                    "function safeTransferFrom(address _from, address _to, uint256 _id, uint256 _amount, bytes _data)",
                                ]),
                                t = e.encodeFunctionData("safeTransferFrom", [
                                    n.accountInfo.address,
                                    r,
                                    g,
                                    l,
                                    "0x",
                                ]);
                            return {
                                from: n.accountInfo.address,
                                to: p,
                                value: "0x",
                                data: t,
                            };
                        }
                        if ("ERC721" === d) {
                            if (!p) return;
                            const e = new i.vU([
                                    "function safeTransferFrom(address _from, address _to, uint256 tokenId)",
                                ]),
                                t = e.encodeFunctionData("safeTransferFrom", [
                                    n.accountInfo.address,
                                    r,
                                    g,
                                ]);
                            return {
                                from: n.accountInfo.address,
                                to: p,
                                value: "0x",
                                data: t,
                            };
                        }
                        {
                            const e = t.coins.find((e) => e.symbol === a && e.chain === o);
                            if (!e) return;
                            if (e.contractAddress === u.je)
                                return {
                                    from: n.accountInfo.address,
                                    to: r,
                                    value: C(l.toString()).toHexString(),
                                    data: "0x",
                                };
                            {
                                const t = new i.vU([
                                        "function transfer(address _to, uint256 _value)",
                                    ]),
                                    o = t.encodeFunctionData("transfer", [
                                        r,
                                        (0, v.L)(l.toString(), e.decimals),
                                    ]);
                                return {
                                    from: n.accountInfo.address,
                                    to: e.contractAddress,
                                    value: "0x",
                                    data: o,
                                };
                            }
                        }
                    },
                    k = () => {
                        const e = (0, r.Y)(),
                            {
                                transaction: t,
                                feeOptions: n,
                                feeSymbol: o,
                                chain: i,
                                isEIP4337HookTx: s,
                            } = e,
                            { data: c, to: l, value: d } = t;
                        if (!c) return;
                        const g = n.find((e) => e.token.symbol === o);
                        let p;
                        return (
                            g &&
                            "rangers" !== i &&
                            (p = {
                                token: g.token.contractAddress || u.je,
                                value: a.O$.from(g.amount),
                                receiver: g.to,
                            }),
                                {
                                    tx: {
                                        target: l,
                                        value: d && "0x" !== d ? a.O$.from(d) : a.O$.from(0),
                                        revertOnError: !0,
                                        data: c,
                                    },
                                    fee: p,
                                    chain: i,
                                    isAddHook: s,
                                }
                        );
                    },
                    b = () => {
                        const e = (0, r.Y)(),
                            {
                                transaction: t,
                                feeOptions: n,
                                feeSymbol: o,
                                chain: s,
                                cards: c,
                                isEIP4337HookTx: l,
                            } = e,
                            { data: d, to: g, value: p } = t;
                        if (!d) return;
                        const h = n.find((e) => e.token.symbol === o);
                        let m;
                        if (
                            (h &&
                            "rangers" !== s &&
                            (m = {
                                token: h.token.contractAddress || u.je,
                                value: a.O$.from(h.amount),
                                receiver: h.to,
                            }),
                            "native" === c[0].tokenType)
                        )
                            return {
                                tx: {
                                    target: g,
                                    value: a.O$.from(1),
                                    revertOnError: !0,
                                    data: d,
                                },
                                fee: m,
                                chain: s,
                            };
                        if ("erc20" === c[0].tokenType) {
                            const e = new i.vU([
                                    "function transfer(address _to, uint256 _value)",
                                ]),
                                t = e.encodeFunctionData("transfer", [
                                    c[0].data.address,
                                    a.O$.from(1),
                                ]);
                            return {
                                tx: {
                                    target: g,
                                    value: a.O$.from(0),
                                    revertOnError: !0,
                                    data: t,
                                },
                                fee: m,
                                chain: s,
                            };
                        }
                        return {
                            tx: {
                                target: g,
                                value: p && "0x" !== p ? a.O$.from(p) : a.O$.from(0),
                                revertOnError: !0,
                                data: d,
                            },
                            fee: m,
                            chain: s,
                            isAddHook: l,
                        };
                    };
            },
            78661: function (e, t, n) {
                "use strict";
                n.d(t, {
                    j: function () {
                        return c;
                    },
                });
                var o = n(58650),
                    a = n(68466),
                    i = n(93130),
                    r = n(55743),
                    s = n.n(r);
                const c = (0, o.Q_)({
                    id: "chainAccountStore",
                    state: () => ({
                        initialized: !1,
                        isPending: !1,
                        pendingKeysetHash: "0x",
                        keysetHash: "0x",
                        unlockTime: 0,
                        lockDuration: 0,
                        progress: "0",
                    }),
                    getters: {},
                    actions: {
                        async fetchAccountInfo(e, t = !1, n) {
                            if (this.initialized && !t) return;
                            const o = await a.ZP.getAccountInfo(e, n);
                            let i = "0";
                            o.isPending &&
                            (i = this.updatePercentage(o.lockDuration, o.unlockTime)),
                                (this.$state = { ...o, initialized: !0, progress: i });
                        },
                        isRecoveryStarted(e) {
                            return (
                                (!0 === this.isPending && e === this.pendingKeysetHash) ||
                                (!1 === this.isPending &&
                                    e === this.keysetHash &&
                                    this.keysetHash !== i.je)
                            );
                        },
                        updatePercentage(e, t) {
                            if (0 === e) return "0.00";
                            const n = (100 * (e - (t - s()().unix()))) / e;
                            return Math.min(n, 100).toFixed(2);
                        },
                        isKeysetHashUpdated(e, t) {
                            return this.keysetHash !== e || this.keysetHash === t;
                        },
                    },
                });
            },
            47116: function (e, t, n) {
                "use strict";
                n.d(t, {
                    K: function () {
                        return p;
                    },
                });
                var o = n(58650),
                    a = n(23269),
                    i = n(61481),
                    r = n(82482);
                class s {
                    constructor(e, t = 1e3) {
                        (0, r.Z)(this, "_timer", void 0),
                            (0, r.Z)(this, "_task", void 0),
                            (0, r.Z)(this, "_interval", void 0),
                            (this._task = e),
                            (this._interval = t);
                    }
                    start() {
                        this._timer ||
                        (this._task(),
                            (this._timer = setInterval(this._task, this._interval)));
                    }
                    stop() {
                        this._timer && clearInterval(this._timer), (this._timer = null);
                    }
                    once() {
                        this._task();
                    }
                }
                var c = n(9984),
                    l = n(79829),
                    u = n(91926),
                    d = n(35351),
                    g = n(15941);
                const p = (0, o.Q_)({
                    id: "coinStore",
                    state: () => ({
                        coins: (0, l.$_)((0, a.Of)()),
                        pollingTask: void 0,
                        active: -1,
                        showLumpSum: !0,
                        netWorth: "-",
                        apBalance: 0,
                        tokenLists: {
                            eth: [],
                            polygon: [],
                            bsc: [],
                            rangers: [],
                            scroll: [],
                            arbitrum: [],
                            avalanche: [],
                            kcc: [],
                            platon: [],
                            okc: [],
                        },
                    }),
                    actions: {
                        start() {
                            if (this.pollingTask) this.pollingTask.start();
                            else {
                                const e = new s(this._netWorthTask, 2e4);
                                e.start(), (this.pollingTask = e);
                            }
                        },
                        stop() {
                            this.pollingTask && this.pollingTask.stop();
                        },
                        async _netWorthTask() {
                            const e = (0, i.L)();
                            if (e.accountInfo.address) {
                                const t = await e.checkKeysetHash();
                                t && (await this.fetchBalances());
                            }
                        },
                        async fetchBalances() {
                            const e = (0, i.L)(),
                                t = (0, c.J)(),
                                n = e.accountInfo.address;
                            n &&
                            (this.getAccountAssets(n),
                                t.loadCollection(n),
                                this.fetchApBalance());
                        },
                        async fetchApBalance() {
                            try {
                                const { data: e } = await d.Z.fetchApBalance();
                                this.apBalance = e.availActionPoint;
                            } catch (e) {
                                g.error("fetch AP balance failed", e);
                            }
                        },
                        async getAccountAssets(e) {
                            const t = (0, i.L)().chainId,
                                n = sessionStorage.getItem("mockAddress") || e,
                                {
                                    sortedTokens: o,
                                    netWorth: a,
                                    prevChainId: r,
                                } = await (0, l.qR)(t, n);
                            r === (0, i.L)().chainId &&
                            ((this.coins = o), (this.netWorth = (0, u.Ik)(a)));
                        },
                    },
                });
            },
            93832: function (e, t, n) {
                "use strict";
                var o = n(77603),
                    a = n(42819),
                    i = n(61481),
                    r = n(15941);
                const s = "UniPassWalletIndexDB_v2",
                    c = new o["default"](s);
                c.version(1).stores({ users: "email_provider" });
                const l = () => {
                        const e = (0, a.Y)();
                        if (e) {
                            const { email: t, oauth_provider: n } = e;
                            return `${t}_${n}`;
                        }
                        return "";
                    },
                    u = {
                        async getAccountInfo(e = !0) {
                            const t = (0, i.L)();
                            try {
                                const n = await c.table("users").get(l()).timeout(500);
                                return n || void (e && t.exit());
                            } catch (n) {
                                r.error("DB getAccountInfo error:", n), e && t.exit();
                            }
                        },
                        async setAccountInfo(e) {
                            try {
                                await c
                                    .table("users")
                                    .put({ ...e, email_provider: l() })
                                    .timeout(500);
                            } catch (t) {
                                return void r.error("DB setAccountInfo error:", t);
                            }
                        },
                        async clearAccountInfo() {
                            try {
                                const e = await c.table("users").delete(l()).timeout(500);
                                return e;
                            } catch (e) {
                                return void r.error("DB clearAccountInfo error:", e);
                            }
                        },
                    };
                t["Z"] = u;
            },
            62029: function (e, t, n) {
                "use strict";
                n.d(t, {
                    _: function () {
                        return U;
                    },
                });
                var o = n(58650),
                    a = (n(38862), n(21703), n(56827)),
                    i = n(39992),
                    r = n(24702),
                    s = n(61072),
                    c = n(59878),
                    l = n(35351),
                    u = n(86550),
                    d = n(24840),
                    g = n.n(d);
                const { toUtf8Bytes: p, toUtf8String: h, base64: m } = u,
                    f = async (e) => {
                        var t, n, o;
                        const {
                            region: a,
                            idToken: i,
                            identityPoolId: r,
                            userPoolId: s,
                        } = e;
                        g().config.region = a;
                        const c = new (g().CognitoIdentity)(),
                            l = {
                                IdentityPoolId: r,
                                Logins: { [`cognito-idp.${a}.amazonaws.com/${s}`]: i },
                            },
                            u = await c.getId(l).promise();
                        if (!u.IdentityId) throw new Error("aws credential get id failed");
                        const d = {
                                IdentityId: u.IdentityId,
                                Logins: { [`cognito-idp.${a}.amazonaws.com/${s}`]: i },
                            },
                            p = await c.getCredentialsForIdentity(d).promise();
                        if (!p.Credentials) throw new Error("get aws credential failed");
                        return new (g().KMS)({
                            region: a,
                            accessKeyId:
                                null !== (t = p.Credentials.AccessKeyId) && void 0 !== t
                                    ? t
                                    : "",
                            secretAccessKey:
                                null !== (n = p.Credentials.SecretKey) && void 0 !== n ? n : "",
                            sessionToken:
                                null !== (o = p.Credentials.SessionToken) && void 0 !== o
                                    ? o
                                    : "",
                        });
                    };
                async function y(e, t) {
                    const { kmsKeyId: n } = t,
                        o = await f(t),
                        a = { KeyId: n, Plaintext: p(e) },
                        i = await o.encrypt(a).promise();
                    if (!i.CiphertextBlob) throw new Error("encrypted origin key failed");
                    return m.encode(i.CiphertextBlob);
                }
                async function w(e, t) {
                    const { kmsKeyId: n } = t,
                        o = await f(t),
                        a = { KeyId: n, CiphertextBlob: m.decode(e) },
                        i = await o.decrypt(a).promise();
                    if (!i.Plaintext) throw new Error("decrypted keystore failed");
                    return h(i.Plaintext);
                }
                var v = n(10010),
                    S = n(65219),
                    A = n(12434),
                    T = n(14052),
                    _ = n(42819),
                    C = n(93832),
                    P = n(61481),
                    E = n(68466),
                    k = n(45358),
                    b = n(15941);
                const { t: I } = r.Z.global,
                    U = (0, o.Q_)({
                        id: "KMSLoginStore",
                        state: () => ({
                            email: "",
                            code: "",
                            submitLoading: !1,
                            sendLoading: !1,
                            countDown: 0,
                            countDownTimer: void 0,
                            isUpdateUpSignToken: !1,
                        }),
                        actions: {
                            verifyCodeForCustodial(e) {
                                (this.email = e),
                                    (this.code = ""),
                                    (this.isUpdateUpSignToken = !1),
                                    (this.submitLoading = !1),
                                    s.Z.push("/verify-code");
                            },
                            updateUpSignTokenCustodial(e) {
                                (this.email = e),
                                    (this.code = ""),
                                    (this.isUpdateUpSignToken = !0),
                                    (this.submitLoading = !1),
                                    s.Z.push("/verify-code");
                            },
                            async sendCode() {
                                if (this.email)
                                    try {
                                        (this.sendLoading = !0), this.stopCountDown();
                                        const e = this.isUpdateUpSignToken
                                            ? await l.Z.sendOtpCode({
                                                action: "auth2Fa",
                                                authType: 0,
                                            })
                                            : await l.Z.sendCode(this.email);
                                        e.ok
                                            ? ((0, T.b_)(I("SendSuccess")), this.startCountDown())
                                            : this.stopCountDown();
                                    } catch {
                                        (0, T.E3)("send code failed"), this.stopCountDown();
                                    } finally {
                                        this.sendLoading = !1;
                                    }
                            },
                            startCountDown() {
                                (this.countDown = 60),
                                    (this.countDownTimer = setInterval(() => {
                                        (this.countDown -= 1),
                                        this.countDown <= 0 && this.stopCountDown();
                                    }, 1e3));
                            },
                            stopCountDown() {
                                clearInterval(this.countDownTimer),
                                    (this.countDownTimer = void 0),
                                    (this.countDown = 0);
                            },
                            async verifyCode() {
                                (this.submitLoading = !0),
                                    this.isUpdateUpSignToken
                                        ? this.verifyCodeForUpSignToken()
                                        : this.verifyCodeForSign();
                            },
                            async verifyCodeForSign() {
                                try {
                                    this.submitLoading = !0;
                                    const t = await l.Z.verifyCode(this.email, this.code);
                                    if (t.ok) {
                                        var e;
                                        const {
                                                cognitoResult: n,
                                                provider: o,
                                                isRegistered: a,
                                                authorization: i,
                                                upSignToken: r,
                                                unipassInfo: s,
                                            } = t.data,
                                            c = {
                                                sub: "",
                                                oauth_provider: o,
                                                authorization: i,
                                                id_token:
                                                    null !==
                                                    (e =
                                                        null === n || void 0 === n
                                                            ? void 0
                                                            : n.idToken) && void 0 !== e
                                                        ? e
                                                        : "",
                                                email: this.email,
                                                expires_at: "",
                                                up_sign_token: r,
                                                unipass_info: s,
                                            };
                                        _.n.set("OAUTH_INFO", JSON.stringify(c)),
                                            a
                                                ? await this.encryptLogin(c, n)
                                                : await this.encryptSignUp(c, n),
                                            (this.code = ""),
                                            this.stopCountDown();
                                    }
                                } catch (t) {
                                    b.error("kms verify code error", t);
                                } finally {
                                    this.submitLoading = !1;
                                }
                            },
                            async verifyCodeForUpSignToken() {
                                try {
                                    this.submitLoading = !0;
                                    const e = parseInt(_.n.get("UP_SIGN_TOKEN_DURATION") || "60"),
                                        t = await l.Z.upSignToken(this.code, 0, e);
                                    if (t.ok) {
                                        const { authorization: e, upSignToken: n } = t.data,
                                            o = (0, _.Y)();
                                        _.n.set(
                                            "OAUTH_INFO",
                                            JSON.stringify({
                                                ...o,
                                                authorization: e,
                                                up_sign_token: n,
                                            })
                                        ),
                                            s.Z.back();
                                    }
                                } catch (e) {
                                    b.error("update sign token verify code error", e);
                                } finally {
                                    this.submitLoading = !1;
                                }
                            },
                            async encryptSignUp(e, t) {
                                try {
                                    if (!t) throw new Error("cognito result not find");
                                    const {
                                            email: n,
                                            id_token: o,
                                            expires_at: r,
                                            oauth_provider: c,
                                        } = e,
                                        u = await A.ZP.generateLocalKey({
                                            email: n,
                                            action: "signUp",
                                        });
                                    if (!u) return;
                                    const d = await y(u.keystore, t),
                                        { encrypted_key: g, aes_key: p } = await (0, S.i)(
                                            u.keystore
                                        ),
                                        h = i.Wallet.createRandom().privateKey,
                                        m = (0, v.oL)(u.localKeyAddress),
                                        f = await l.Z.signUpAccount({
                                            keysetJson: m.toJson(),
                                            masterKey: {
                                                masterKeyAddress: u.localKeyAddress,
                                                keyStore: d,
                                                keyType: k.Ws.AWS_KMS,
                                            },
                                            pepper: h,
                                            source:
                                                sessionStorage.getItem("up_login_source") ||
                                                sessionStorage.appName ||
                                                "unipass",
                                        }),
                                        w = E.ZP.generateAccountAddress(m.hash());
                                    if (f.ok) {
                                        sessionStorage.removeItem("up_login_source");
                                        const {
                                            address: t,
                                            authorization: i,
                                            upSignToken: l,
                                        } = f.data;
                                        if (t.toLowerCase() === w.toLowerCase()) {
                                            const t = {
                                                email: n,
                                                id_token: o,
                                                user_key: { encrypted_key: g, aes_key: p },
                                                address: w,
                                                oauth_provider: c,
                                                expires_at: r,
                                                keyset: {
                                                    hash: m.hash(),
                                                    masterKeyAddress: u.localKeyAddress,
                                                    keysetJson: m.obscure().toJson(),
                                                    keyType: k.Ws.AWS_KMS,
                                                },
                                                keystore: d,
                                            };
                                            if (
                                                (await C.Z.setAccountInfo(t),
                                                    await (0, P.L)().init(),
                                                    _.n.set(
                                                        "OAUTH_INFO",
                                                        JSON.stringify({
                                                            ...e,
                                                            authorization: i,
                                                            up_sign_token: l,
                                                        })
                                                    ),
                                                    (sessionStorage.newborn = !0),
                                                    (0, a.BX)())
                                            )
                                                return void (await s.Z.replace(
                                                    sessionStorage.path || "/"
                                                ));
                                            s.Z.replace("/register/loading");
                                        } else b.error("signUp account address inconsistent");
                                    }
                                } catch (n) {
                                    b.error("sign up failed", n), s.Z.replace("/login");
                                }
                            },
                            async encryptLogin(e, t) {
                                try {
                                    if (!t) throw new Error("cognito result not find");
                                    const {
                                        email: n,
                                        id_token: o,
                                        expires_at: a,
                                        unipass_info: i,
                                        oauth_provider: r,
                                    } = e;
                                    if (null === i || void 0 === i || !i.keystore)
                                        throw new Error("unipass_info not find when login");
                                    const l = await w(i.keystore, t),
                                        { encrypted_key: u, aes_key: d } = await (0, S.i)(l),
                                        g = c.Keyset.fromJson(i.keyset),
                                        p = {
                                            email: n,
                                            id_token: o,
                                            user_key: { encrypted_key: u, aes_key: d },
                                            address: i.address,
                                            oauth_provider: r,
                                            expires_at: a,
                                            keyset: {
                                                hash: g.hash(),
                                                masterKeyAddress: g.keys[0].address,
                                                keysetJson: g.obscure().toJson(),
                                                keyType:
                                                    (null === i || void 0 === i ? void 0 : i.keyType) ||
                                                    k.Ws.AWS_KMS,
                                            },
                                            keystore: i.keystore,
                                        };
                                    if (
                                        (await C.Z.setAccountInfo(p),
                                            await (0, P.L)().init(),
                                            sessionStorage.removeItem("newborn"),
                                            sessionStorage.redirectUrl)
                                    ) {
                                        const e = new URL(sessionStorage.redirectUrl);
                                        sessionStorage.removeItem("redirectUrl"),
                                            e.searchParams.delete("connectType"),
                                            (location.href = e.toString());
                                    } else await s.Z.replace(sessionStorage.path || "/");
                                    (0, T.yC)(
                                        "login_success",
                                        { account: i.address, email: n },
                                        r
                                    );
                                } catch (n) {
                                    if (
                                        "invalid password" ===
                                        (null === n || void 0 === n ? void 0 : n.message)
                                    )
                                        return void (0, T.E3)(I("IncorrectPassword"));
                                    b.error("login error", n), s.Z.replace("/login");
                                }
                            },
                        },
                    });
            },
            9984: function (e, t, n) {
                "use strict";
                n.d(t, {
                    J: function () {
                        return s;
                    },
                });
                var o = n(58650),
                    a = n(35351),
                    i = n(61481),
                    r = n(15941);
                const s = (0, o.Q_)({
                    id: "nftStore",
                    state: () => ({
                        nft: {
                            tokenId: "",
                            tokenType: "",
                            timeLastUpdated: "",
                            total: 0,
                            title: "",
                            description: "",
                            imageUrl: "",
                            imageOriginalUrl: "",
                        },
                        collection: {
                            contractAddress: "",
                            tokenType: "",
                            totalTokens: 0,
                            name: "",
                            symbol: "",
                            imageUrl: "",
                            chainId: "",
                            openseaUrl: "",
                            browserUrl: "",
                            timeLastUpdated: "",
                        },
                        activeTab: "token",
                        activeCollectionIndex: -1,
                        collectionList: [],
                        collectionCache: {},
                        currentCollection: [],
                        nftLoading: !1,
                        collectionLoading: !0,
                        currentChainIndex: 0,
                    }),
                    actions: {
                        clickCollection(e, t) {
                            var n;
                            (this.activeCollectionIndex =
                                this.activeCollectionIndex === t ? -1 : t),
                                null !== (n = this.collectionCache[e.contractAddress]) &&
                                void 0 !== n &&
                                n.length
                                    ? (this.currentCollection =
                                        this.collectionCache[e.contractAddress])
                                    : ((this.currentCollection = []), this.loadNFT(e, t));
                        },
                        async loadCollection(e) {
                            if (!e) return null;
                            const t = (0, i.L)().chainId;
                            try {
                                const n = await a.Z.getAccountCollection({
                                    address: e,
                                    chainId: t,
                                    page: 1,
                                    size: 100,
                                });
                                this.collectionList = n.data.list;
                            } catch (n) {
                                r.error("updateCollection", n);
                            }
                            this.collectionLoading = !1;
                        },
                        async loadNFT(e, t) {
                            const n = (0, i.L)().accountInfo.address;
                            if (!n) return null;
                            if (this.nftLoading) return null;
                            this.nftLoading = !0;
                            const { contractAddress: o, chainId: s } = e;
                            try {
                                const e = await a.Z.getAccountNFT({
                                    address: n,
                                    chainId: s,
                                    contractAddress: o,
                                    page: 1,
                                    size: 100,
                                });
                                (this.collectionCache[o] = e.data.list),
                                t === this.activeCollectionIndex &&
                                (this.currentCollection = this.collectionCache[o]);
                            } catch (c) {
                                r.error("loadNFT", c);
                            }
                            this.nftLoading = !1;
                        },
                    },
                });
            },
            78791: function (e, t, n) {
                "use strict";
                n.d(t, {
                    T: function () {
                        return b;
                    },
                });
                var o = n(58650),
                    a = (n(38862), n(56827)),
                    i = n(39992),
                    r = n(31463),
                    s = n(24702),
                    c = n(88363),
                    l = n(59878),
                    u = n(35351),
                    d = n(61072),
                    g = n(68466),
                    p = n(12434),
                    h = n(10010),
                    m = n(61481),
                    f = n(42819),
                    y = n(5941),
                    w = n(73712),
                    v = n(45358);
                const S = {
                        domain: "auth.wallet.unipass.id",
                        clientID: "vr6KIghxCqmElpAd4TND0nrMBiAR3X2m",
                        responseType: "token id_token",
                        redirectUri: window.location.origin + "/loading",
                    },
                    A = (e) => {
                        switch (e) {
                            case v.O4.GOOGLE:
                            case v.O4.AUTH0:
                                return;
                            case v.O4.APPLE:
                                return "apple";
                            case v.O4.UNIPASS:
                                return "unipass";
                            default:
                                return;
                        }
                    };
                var T = n(14052),
                    _ = n(65219),
                    C = n(93832),
                    P = n(62029),
                    E = n(15941);
                const { t: k } = s.Z.global,
                    b = (0, o.Q_)({
                        id: "OAuthLoginStore",
                        state: () => ({
                            auth0: new r.ZP.WebAuth(S),
                            connectType: "both",
                            email: "",
                            password: "",
                            confirmPassword: "",
                            isPending: !1,
                            auth0EmailLoading: !1,
                            passwordLoading: !1,
                        }),
                        actions: {
                            changeConnectType(e) {
                                (this.connectType = e), (sessionStorage.connectType = e);
                            },
                            loginWithGoogle() {
                                window.location.href = (0, w.U7)();
                            },
                            initAccountStatus(e) {
                                this.isPending = e;
                            },
                            async auth0Login(e) {
                                const t = (0, m.L)(),
                                    n = (0, P._)(),
                                    { prompt: o = "login", email: i, nonce: r, scope: l } = e;
                                let d = e.provider;
                                d !== v.O4.APPLE && (this.auth0EmailLoading = !0);
                                const g = this.email || i;
                                if (!g || r || l || d === v.O4.APPLE) {
                                    if (g && d === v.O4.CUSTODIAL)
                                        return (
                                            n.updateUpSignTokenCustodial(g),
                                                (this.auth0EmailLoading = !1),
                                                void (this.email = "")
                                        );
                                } else {
                                    var p;
                                    const e = await u.Z.checkProvider(g, sessionStorage.appName);
                                    if (!e.ok) return void (this.auth0EmailLoading = !1);
                                    if (
                                        ((d =
                                            null === (p = e.data) || void 0 === p
                                                ? void 0
                                                : p.provider),
                                        (0, a.BX)() && d !== v.O4.CUSTODIAL)
                                    )
                                        return (
                                            c.T.alert(k("DisableInIframeEnv"), k("Notification"), {
                                                confirmButtonText: k("Confirm"),
                                                center: !0,
                                                showClose: !1,
                                                showCancelButton: !1,
                                            }),
                                                (this.auth0EmailLoading = !1),
                                                void (this.email = "")
                                        );
                                    if (e.ok && d === v.O4.GOOGLE)
                                        return (
                                            c.T.alert(k("UseGoogleOauth"), k("Notification"), {
                                                confirmButtonText: k("SignWithGoogle"),
                                                center: !0,
                                            })
                                                .then(() => {
                                                    (0, T.yC)("login_click_change_to_google"),
                                                        (window.location.href = (0, w.U7)(g));
                                                })
                                                .catch(() => {}),
                                                void (this.auth0EmailLoading = !1)
                                        );
                                    if (e.ok && d === v.O4.CUSTODIAL)
                                        return (
                                            n.verifyCodeForCustodial(g),
                                                (this.auth0EmailLoading = !1),
                                                void (this.email = "")
                                        );
                                }
                                this.auth0.authorize({
                                    login_hint: g,
                                    connection: A(d),
                                    prompt: o,
                                    nonce: r,
                                    scope: l,
                                    language: JSON.stringify({
                                        theme: sessionStorage.theme || t.theme,
                                        language: s.Z.global.locale.value,
                                    }),
                                    ui_locales: JSON.stringify({
                                        theme: sessionStorage.theme || t.theme,
                                        language: s.Z.global.locale.value,
                                    }),
                                });
                            },
                            async encryptSignUp() {
                                try {
                                    const e = (0, f.Y)();
                                    if (!e) return;
                                    const {
                                        email: t,
                                        id_token: n,
                                        expires_at: o,
                                        oauth_provider: a,
                                    } = e;
                                    (0, T.yC)("register_click_signup", { email: t }, a);
                                    const r = await p.ZP.generateLocalKey({
                                        email: t,
                                        action: "signUp",
                                    });
                                    if (!r) return;
                                    const s = await (0, y.h)(r.keystore, this.password),
                                        { encrypted_key: c, aes_key: l } = await (0, _.i)(
                                            r.keystore
                                        ),
                                        { data: w } = await u.Z.getConfig(),
                                        S = i.Wallet.createRandom().privateKey,
                                        A = (0, h.uv)(
                                            [],
                                            { idToken: n },
                                            t,
                                            r.localKeyAddress,
                                            w.policyKeysetJson,
                                            S
                                        ),
                                        P = await u.Z.signUpAccount({
                                            keysetJson: A.toJson(),
                                            masterKey: {
                                                masterKeyAddress: r.localKeyAddress,
                                                keyStore: s,
                                                keyType: v.Ws.MPC,
                                            },
                                            pepper: S,
                                            source:
                                                sessionStorage.getItem("up_login_source") ||
                                                sessionStorage.appName ||
                                                "unipass",
                                        }),
                                        k = g.ZP.generateAccountAddress(A.hash());
                                    if (P.ok) {
                                        sessionStorage.removeItem("up_login_source");
                                        const {
                                            address: i,
                                            authorization: u,
                                            upSignToken: g,
                                        } = P.data;
                                        if (i.toLowerCase() === k.toLowerCase()) {
                                            const i = {
                                                email: t,
                                                id_token: n,
                                                user_key: { encrypted_key: c, aes_key: l },
                                                address: k,
                                                oauth_provider: a,
                                                expires_at: o,
                                                keyset: {
                                                    hash: A.hash(),
                                                    masterKeyAddress: r.localKeyAddress,
                                                    keysetJson: A.obscure().toJson(),
                                                    keyType: v.Ws.MPC,
                                                },
                                                keystore: s,
                                            };
                                            await C.Z.setAccountInfo(i),
                                                await (0, m.L)().init(),
                                                f.n.set(
                                                    "OAUTH_INFO",
                                                    JSON.stringify({
                                                        ...e,
                                                        authorization: u,
                                                        up_sign_token: g,
                                                    })
                                                ),
                                                (sessionStorage.newborn = !0),
                                                d.Z.replace("/register/loading");
                                        } else E.error("signUp account address inconsistent");
                                    }
                                } catch (e) {
                                    d.Z.replace("/login");
                                }
                            },
                            async encryptLogin() {
                                try {
                                    const e = (0, f.Y)();
                                    if (!e || !e.unipass_info) return;
                                    const {
                                        email: t,
                                        id_token: n,
                                        expires_at: o,
                                        unipass_info: a,
                                        oauth_provider: i,
                                    } = e;
                                    (0, T.yC)(
                                        "login_click_login",
                                        { account: a.address, email: t },
                                        i
                                    );
                                    const r = await (0, y.p)(a.keystore, this.password),
                                        { encrypted_key: s, aes_key: c } = await (0, _.i)(r),
                                        u = l.Keyset.fromJson(a.keyset),
                                        g = {
                                            email: t,
                                            id_token: n,
                                            user_key: { encrypted_key: s, aes_key: c },
                                            address: a.address,
                                            oauth_provider: i,
                                            expires_at: o,
                                            keyset: {
                                                hash: u.hash(),
                                                masterKeyAddress: u.keys[0].address,
                                                keysetJson: u.obscure().toJson(),
                                                keyType:
                                                    (null === a || void 0 === a ? void 0 : a.keyType) ||
                                                    v.Ws.MPC,
                                            },
                                            keystore: a.keystore,
                                        };
                                    if (
                                        (await C.Z.setAccountInfo(g),
                                            await (0, m.L)().init(),
                                            sessionStorage.removeItem("newborn"),
                                            sessionStorage.redirectUrl)
                                    ) {
                                        const e = new URL(sessionStorage.redirectUrl);
                                        e.searchParams.get("forceLogin") &&
                                        e.searchParams.set("forceLogin", "0"),
                                            sessionStorage.removeItem("redirectUrl"),
                                            e.searchParams.delete("connectType"),
                                            (location.href = e.toString());
                                    } else await d.Z.replace(sessionStorage.path || "/");
                                    (0, T.yC)(
                                        "login_success",
                                        { account: a.address, email: t },
                                        i
                                    );
                                } catch (e) {
                                    if (
                                        "invalid password" ===
                                        (null === e || void 0 === e ? void 0 : e.message)
                                    )
                                        return void (0, T.E3)(k("IncorrectPassword"));
                                    E.error("login error", e), d.Z.replace("/login");
                                } finally {
                                    this.passwordLoading = !1;
                                }
                            },
                        },
                    });
            },
            70498: function (e, t, n) {
                "use strict";
                n.d(t, {
                    Y: function () {
                        return k;
                    },
                });
                var o = n(58650),
                    a = n(44870),
                    i = (n(38862), n(21703), n(23269)),
                    r = n(61598),
                    s = n(14052),
                    c = n(61481),
                    l = n(72043),
                    u = n(26639),
                    d = n(63013),
                    g = n(26156),
                    p = n(7832),
                    h = n(47116),
                    m = n(16775),
                    f = n(35351),
                    y = n(19573),
                    w = n(98074),
                    v = n(93130),
                    S = n(66224),
                    A = n(86140),
                    T = n(46029),
                    _ = n(87079),
                    C = n(45358),
                    P = n(79829),
                    E = n(15941);
                const k = (0, o.Q_)({
                    id: "signStore",
                    state: () => ({
                        cards: [],
                        feeOptions: [],
                        eip4337FeeOptions: [],
                        eip4337UserOperationStruct: void 0,
                        gasMod: "normal",
                        isFeeRequired: !0,
                        isEIP4337FeeRequired: !0,
                        feeSymbol: "",
                        eip4337FeeSymbol: "",
                        loading: !1,
                        appIcon: "",
                        appName: "",
                        returnEmail: !1,
                        referrer: "",
                        starkKeyMessage: "",
                        sessionKeyAddress: "",
                        connectLoading: !1,
                        connectAndAuth: { message: "", showMessage: !1 },
                        chain: "polygon",
                        symbol: "MATIC",
                        isEIP4337HookTx: !1,
                        isAccountSynced: !0,
                        fromThirdParty: !1,
                        isOpenEIP4337Hook: !1,
                        transaction: { from: "", data: "", to: "", value: "" },
                        gasFeeLoading: !0,
                        redirectUrl: "",
                        signMassage: {
                            loading: !1,
                            type: C.Uo.v1,
                            typedData: {},
                            msg: "",
                            from: "",
                            referrer: "",
                        },
                        walletConnectId: void 0,
                        walletConnectTopic: "",
                        fromWalletConnectSign: !1,
                        fromEIP4337Sign: !1,
                        checkAccountStatusLoading: !1,
                        fromStandardProviderSign: !1,
                        nft: {
                            imageUrl: "",
                            chainId: "",
                            contractAddress: "",
                            name: "",
                            tokenId: "",
                            amount: "",
                        },
                    }),
                    getters: {
                        coin(e) {
                            const t = e.chain,
                                n = e.symbol;
                            return (0, h.K)().coins.find(
                                (e) => e.chain === t && e.symbol === n
                            );
                        },
                    },
                    actions: {
                        async restoreSignState(e, t, n) {
                            try {
                                const o = JSON.parse(e);
                                if (
                                    ((o.feeSymbol = ""), (this.$state = o), "signMessage" === n)
                                )
                                    await (0, g.Ab)(t, () => (0, g.Sb)(e));
                                else {
                                    const { nonce: n } = (0, r["default"])(t);
                                    n.startsWith("update-up-sign-token")
                                        ? await (0, g.Ab)(t, () => (0, g.i_)("upSignToken", e))
                                        : await (0, g.Ab)(t, () => (0, g.i_)("multiSync", e));
                                }
                            } catch (o) {
                                return;
                            }
                        },
                        async initTransactionData(e, t, n = !1, o = !1) {
                            (this.feeOptions = []),
                                (this.isFeeRequired = !0),
                                (this.isEIP4337HookTx = n),
                                (this.fromThirdParty = o),
                                this.initAppSetting(e);
                            const a = await (0, m.RJ)(t, e.chain);
                            a &&
                            ((this.transaction = t), (this.cards = a), this.updateGasFee());
                        },
                        initAppSetting(e) {
                            const t = (0, c.L)(),
                                n = (0, h.K)();
                            if (e) {
                                const { theme: o, chain: a, appName: r, appIcon: s } = e;
                                !sessionStorage.theme &&
                                o &&
                                ((sessionStorage.theme = o), (t.theme = o), (0, p.X)()),
                                a &&
                                ((this.chain = a),
                                (0 !== n.coins.length && (0, i.BR)(a) === t.chainId) ||
                                (n.coins = (0, P.$_)((0, i.BR)(a))),
                                    (t.chainId = (0, i.BR)(a))),
                                r && ((sessionStorage.appName = r), (this.appName = r)),
                                s && (this.appIcon = s);
                            }
                        },
                        updateSymbolAndChain(e, t) {
                            (this.symbol = t || this.symbol || ""), (this.chain = e);
                        },
                        async updateGasFee() {
                            try {
                                (this.feeOptions = []),
                                    (this.eip4337FeeOptions = []),
                                    (this.feeSymbol = ""),
                                    (this.eip4337FeeSymbol = ""),
                                    (this.gasMod = "normal"),
                                    (this.gasFeeLoading = !0),
                                    await this._updateGasFee();
                            } catch (e) {
                                (this.feeOptions = []),
                                    E.error("Loading Gas Failed:"),
                                    E.error(e),
                                    (0, s.x9)(
                                        `Transaction Error: ${e.message || "unknown error"}`,
                                        0,
                                        !0
                                    );
                            } finally {
                                this.gasFeeLoading = !1;
                            }
                        },
                        async _updateGasFee() {
                            const e = (0, h.K)(),
                                t = (0, c.L)();
                            if (
                                (await t.checkKeysetHash(),
                                    e.getAccountAssets(t.accountInfo.address),
                                    !this.isEIP4337HookTx)
                            ) {
                                const {
                                    data: { syncStatus: e },
                                } = await f.Z.getSyncStatus({
                                    email: t.accountInfo.email,
                                    authChainNode: (0, i.K1)(this.chain),
                                });
                                if (e === C.S.NotReceived || e === C.S.NotSynced)
                                    return void (0, g.iX)(
                                        "multiSync",
                                        JSON.stringify({ ...(0, a.IU)(this.$state), loading: !1 }),
                                        this.fromEIP4337Sign
                                    );
                                this.isAccountSynced = e === C.S.Synced;
                            }
                            await Promise.all([
                                this._simulateTransaction(),
                                this._simulateEIP4337Transaction(),
                            ]);
                        },
                        async isEIP4337HookAdded() {
                            if ("eth" === this.chain || "polygon" === this.chain) {
                                const e = (0, c.L)(),
                                    t = (await e.unipassWallet.wallet(this.chain)).provider;
                                return await (0, y.isAddEIP4337Hook)(
                                    e.accountInfo.address,
                                    t,
                                    v.fi
                                );
                            }
                            return !1;
                        },
                        async _simulateTransaction() {
                            const e = (0, c.L)(),
                                t = (0, h.K)(),
                                n = (0, m._U)();
                            if (!n)
                                throw new Error(
                                    "Expected Transaction For Simulating Transaction"
                                );
                            const o = await e.unipassWallet.simulateTransactions(n);
                            if (!o) return;
                            const {
                                isFeeRequired: a,
                                feeTokens: i,
                                feeReceiver: r,
                                discount: s,
                                gasPrice: d,
                            } = o;
                            if (((this.isFeeRequired = a), a)) {
                                const e = [];
                                i.forEach(
                                    ({
                                         token: n,
                                         gasUsed: o,
                                         nativeTokenPrice: a,
                                         tokenPrice: i,
                                     }) => {
                                        const c = t.coins.find(
                                            (e) =>
                                                e.chain === this.chain &&
                                                e.contractAddress.toLowerCase() === n.toLowerCase()
                                        );
                                        if (c) {
                                            let t, n;
                                            "rangers" === this.chain
                                                ? ((t = l.O$.from(1e6)), (n = u.parseEther("0.0001")))
                                                : ((t = l.O$.from(o)), (n = t.mul(d)));
                                            const g = n
                                                .mul(Math.ceil(a * 10 ** 8))
                                                .div(Math.ceil(i * 10 ** 8))
                                                .mul(s)
                                                .div(100)
                                                .div(10 ** (18 - c.decimals));
                                            e.push({
                                                to: r,
                                                gasLimit: t,
                                                token: c,
                                                amount: g.toHexString(),
                                            });
                                        }
                                    }
                                ),
                                    (this.feeOptions = e);
                            }
                        },
                        async _simulateEIP4337Transaction() {
                            if (
                                this.isEIP4337HookTx ||
                                !this.isAccountSynced ||
                                this.fromThirdParty
                            )
                                this.isOpenEIP4337Hook = !1;
                            else if (
                                "eth" === this.chain ||
                                ("mainnet" === (0, i.IA)() && "polygon" === this.chain)
                            ) {
                                const e = (0, c.L)(),
                                    t = (await e.unipassWallet.wallet(this.chain)).provider,
                                    n = await (0, y.isAddEIP4337Hook)(
                                        e.accountInfo.address,
                                        t,
                                        v.fi
                                    );
                                if (((this.isOpenEIP4337Hook = n), !n))
                                    return void (this.eip4337UserOperationStruct = void 0);
                                {
                                    const e = (0, h.K)(),
                                        n = (0, c.L)(),
                                        o = (0, m.y4)();
                                    if (null === o || void 0 === o || !o.tx)
                                        throw new Error(
                                            "Expected Transaction For Simulating EIP4337 Transaction"
                                        );
                                    const a = await n.unipassWallet.wallet(this.chain),
                                        r = new S.UnipassAccountAPI({
                                            provider: t,
                                            entryPointAddress: v.uh,
                                            accountAddress: n.accountInfo.address,
                                            wallet: a,
                                            paymasterAPI: new A.VerifyingPaymasterAPI(
                                                (0, i.BR)(this.chain),
                                                (0, y.getSigSize)(a.keyset, [0]),
                                                v.RZ,
                                                v.uh
                                            ),
                                            overheads: { sigSize: (0, y.getSigSize)(a.keyset, [0]) },
                                        }),
                                        s = await this._simulateEIP4337HookTransaction(r, {
                                            ...o.tx,
                                            _isUnipassWalletTransaction: !0,
                                            callType: T.CallType.Call,
                                            revertOnError: !0,
                                            gasLimit: o.tx.gasLimit || l.O$.from(0),
                                            data: o.tx.data || "0x",
                                        });
                                    (this.eip4337UserOperationStruct = s), (this.gasMod = "4337");
                                    const u =
                                        null == s.paymasterAndData || "0x" === s.paymasterAndData;
                                    if (u) {
                                        this.isEIP4337FeeRequired = !0;
                                        const o = e.coins.find(
                                                (e) =>
                                                    e.chain === this.chain &&
                                                    e.contractAddress.toLowerCase() === v.je
                                            ),
                                            a = await new d.CH(
                                                v.uh,
                                                new _.Interface([
                                                    "function balanceOf(address) returns (uint256)",
                                                ]),
                                                t
                                            ).callStatic.balanceOf(n.accountInfo.address);
                                        let i = (await s.callGasLimit)
                                            .add(await s.verificationGasLimit)
                                            .add(await s.preVerificationGas)
                                            .sub(a.div(await s.maxFeePerGas));
                                        i.lt(0) && (i = l.O$.from(0)),
                                            (this.eip4337FeeOptions = [
                                                {
                                                    to: v.uh,
                                                    gasLimit: i,
                                                    token: o,
                                                    amount: i.mul(s.maxFeePerGas).toHexString(),
                                                },
                                            ]);
                                    } else
                                        (this.eip4337FeeOptions = []),
                                            (this.isEIP4337FeeRequired = !1);
                                }
                            } else this.isOpenEIP4337Hook = !1;
                        },
                        async _simulateEIP4337HookTransaction(e, t) {
                            const n = w.ModuleHookEIP4337WalletInterface.encodeFunctionData(
                                "execFromEntryPoint",
                                [t]
                            );
                            return await e.createUnsignedUserOp({
                                target: await e.getAccountAddress(),
                                data: n,
                            });
                        },
                    },
                });
            },
            42819: function (e, t, n) {
                "use strict";
                n.d(t, {
                    Y: function () {
                        return s;
                    },
                    n: function () {
                        return r;
                    },
                });
                n(38862);
                var o = n(61481);
                const a = {
                        OAUTH_INFO: "__oauth_info",
                        UP_SIGN_TOKEN_DURATION: "__up_sign_token_duration",
                        RECOVERY_ORIGIN_STATE: "__recovery_origin_state",
                        SIGN_TX_ORIGIN_STATE: "__sign_tx_origin_state",
                        GUARDIAN_ORIGIN_STATE: "__guardian_origin_state",
                        EIP4337HOOK_ORIGIN_STATE: "__eip4337hook_origin_state",
                        CANCEL_RECOVERY_ORIGIN_STATE: "__cancel_recovery_origin_state",
                        SIGN_MESSAGE_ORIGIN_STATE: "__sign_message_origin_state",
                        SIGN_MESSAGE_APP_SETTING: "__sign_message_app_setting",
                        AUTHORIZATION_REQUIRE_STATE: "__authorization_require_state",
                        LEGACY_SIGN_WALLET_CONNECT_CLIENT:
                            "__legacy_sign_wallet_connect_client",
                        LEGACY_SIGN_WALLET_CONNECT_SESSIONS:
                            "__legacy_sign_wallet_connect_sessions",
                    },
                    i = (e) => {
                        const t = (t, n) => {
                                e.setItem(a[t], n || "");
                            },
                            n = (t, n) => {
                                e.setItem(t, JSON.stringify(n));
                            },
                            o = (t) => e.getItem(a[t]) || "",
                            i = (t) => e.getItem(t) || "",
                            r = (t) => e.removeItem(a[t]),
                            s = () => {
                                for (const t in e)
                                    t &&
                                    (["vueuse-color-scheme", "language", "assets"].find((e) =>
                                            t.startsWith(e)
                                        ) ||
                                        e.removeItem(t));
                            };
                        return {
                            get: o,
                            getDirectly: i,
                            set: t,
                            setDirectly: n,
                            remove: r,
                            clearAll: s,
                        };
                    },
                    r = i(window.localStorage || localStorage),
                    s = () => {
                        const e = (0, o.L)();
                        try {
                            const e = r.get("OAUTH_INFO");
                            if (!e) return;
                            return JSON.parse(e);
                        } catch (t) {
                            e.exit();
                        }
                    };
            },
            61481: function (e, t, n) {
                "use strict";
                n.d(t, {
                    L: function () {
                        return y;
                    },
                });
                var o = n(58650),
                    a = (n(38862), n(23104)),
                    i = n(23269),
                    r = n(4369),
                    s = n.n(r),
                    c = n(61072),
                    l = n(54663),
                    u = n(78661),
                    d = n(20881),
                    g = n(93832),
                    p = n(45358),
                    h = n(9984),
                    m = n(47116),
                    f = n(79829);
                const y = (0, o.Q_)({
                    id: "userStore",
                    state: () => ({
                        unipassWallet: s().getInstance({
                            env: i.e8.net,
                            url_config: i.e8.urlConfig,
                        }),
                        accountInfo: {
                            email: "",
                            id_token: "",
                            user_key: { encrypted_key: "" },
                            address: "",
                            oauth_provider: p.O4.GOOGLE,
                            keyset: {
                                hash: "",
                                masterKeyAddress: "",
                                keysetJson: "",
                                keyType: p.Ws.MPC,
                            },
                        },
                        appInited: !1,
                        showSupportEmail: !1,
                        showHeaderMore: !1,
                        showOAuth: !1,
                        showOAuthConfirmLoading: !1,
                        showTimeSelect: !0,
                        showOAuthHours: 1,
                        showOAuthCallback: async () => {},
                        upLoading: !1,
                        theme: "",
                        chainId: (0, i.Of)(),
                    }),
                    getters: {
                        isLogin(e) {
                            var t;
                            return !(
                                null === e ||
                                void 0 === e ||
                                null === (t = e.accountInfo) ||
                                void 0 === t ||
                                !t.address
                            );
                        },
                    },
                    actions: {
                        async init(e = !0) {
                            const t = await g.Z.getAccountInfo(e);
                            t && (this.accountInfo = t);
                        },
                        async update(e) {
                            (this.accountInfo = e), await g.Z.setAccountInfo(e);
                        },
                        async exit(e = !1, t) {
                            var n, o;
                            await (0, d.B)(),
                                (0, u.j)().$reset(),
                                sessionStorage.removeItem("chainId"),
                                this.$reset(),
                                (this.upLoading = !1),
                            window.opener &&
                            (0, l.oi)(
                                new a.cW(
                                    "UP_RESPONSE",
                                    JSON.stringify(new a.vq("DECLINE", "expired"))
                                )
                            ),
                            null !== (n = window) &&
                            void 0 !== n &&
                            null !== (o = n.flutter_inappwebview) &&
                            void 0 !== o &&
                            o.callHandler &&
                            window.flutter_inappwebview.callHandler(
                                "onUserInfoInvalid",
                                new a.cW(
                                    "UP_RESPONSE",
                                    JSON.stringify(new a.vq("DECLINE", "expired"))
                                )
                            ),
                                e
                                    ? window.location.replace("/login")
                                    : t
                                        ? (window.location.href = t)
                                        : c.Z.replace("/login");
                        },
                        async checkKeysetHash() {
                            const e = (0, u.j)();
                            return (
                                await e.fetchAccountInfo(
                                    this.accountInfo.address,
                                    !0,
                                    this.accountInfo.keyset.hash
                                ),
                                this.accountInfo.keyset.hash === e.keysetHash ||
                                (this.exit(), !1)
                            );
                        },
                        updateChainId(e) {
                            if (this.chainId === e) return;
                            (this.chainId = e),
                                sessionStorage.setItem("chainId", e.toString());
                            const t = this.accountInfo.address;
                            if (t) {
                                const t = (0, h.J)();
                                (t.collectionLoading = !0), (t.collectionList = []);
                                const n = (0, m.K)();
                                (n.netWorth = "-"), (n.coins = (0, f.$_)(e)), n.fetchBalances();
                            }
                        },
                    },
                });
            },
            79829: function (e, t, n) {
                "use strict";
                n.d(t, {
                    $_: function () {
                        return O;
                    },
                    qR: function () {
                        return L;
                    },
                });
                var o = n(28307),
                    a = n(91926),
                    i = n(23269);
                const r = [
                        {
                            chainId: 5,
                            contractAddress: "0x365E05Fd986245d14c740c139DF8712AD8807874",
                            name: "USDC",
                            symbol: "USDC",
                            decimals: 6,
                            logoURI: "",
                        },
                        {
                            chainId: 5,
                            contractAddress: "0xd44BB808bfE43095dBb94c83077766382D63952a",
                            name: "USDT",
                            symbol: "USDT",
                            decimals: 6,
                            logoURI:
                                "https://lay2-unipass-token-images.s3.ap-southeast-1.amazonaws.com/coins/images/325/large/Tether-logo.png?1598003707",
                        },
                    ],
                    s = [
                        {
                            chainId: 80001,
                            contractAddress: "0x87F0E95E11a49f56b329A1c143Fb22430C07332a",
                            name: "USDC",
                            symbol: "USDC",
                            decimals: 6,
                            logoURI: "",
                            default: !0,
                        },
                        {
                            chainId: 80001,
                            contractAddress: "0x569F5fF11E259c8e0639b4082a0dB91581a6b83e",
                            name: "USDT",
                            symbol: "USDT",
                            default: !0,
                            decimals: 6,
                            logoURI: "",
                        },
                    ],
                    c = [
                        {
                            chainId: 97,
                            contractAddress: "0x64544969ed7EBf5f083679233325356EbE738930",
                            name: "USDC",
                            symbol: "USDC",
                            decimals: 18,
                            logoURI: "",
                        },
                    ],
                    l = [
                        {
                            chainId: 9527,
                            contractAddress: "0xd6ed1c13914ff1b08737b29de4039f542162cae1",
                            name: "USDC",
                            symbol: "USDC",
                            decimals: 6,
                            logoURI: "",
                        },
                    ],
                    u = [
                        {
                            chainId: 534353,
                            contractAddress: "0xA0D71B9877f44C744546D649147E3F1e70a93760",
                            name: "USDC",
                            symbol: "USDC",
                            decimals: 18,
                            logoURI: "",
                        },
                    ],
                    d = [
                        {
                            chainId: 421613,
                            contractAddress: "0x8667Bfb67d4D9fd1e61168dc872e17f637964547",
                            name: "USDC",
                            symbol: "USDC",
                            decimals: 6,
                            logoURI: "",
                        },
                    ],
                    g = [
                        {
                            chainId: 43113,
                            contractAddress: "0x5425890298aed601595a70AB815c96711a31Bc65",
                            name: "USDC",
                            symbol: "USDC",
                            decimals: 6,
                            logoURI: "",
                        },
                    ],
                    p = [
                        {
                            chainId: 59,
                            contractAddress: "0xd6c7e27a598714c2226404eb054e0c074c906fc9",
                            name: "USDC",
                            symbol: "USDC",
                            decimals: 18,
                            logoURI: "",
                        },
                    ],
                    h = [
                        {
                            chainId: 2206132,
                            contractAddress: "0xEd5e318045D33611E877C25F7aFE6e98e2c2933C",
                            name: "USD Coin",
                            symbol: "USDC",
                            decimals: 6,
                            logoURI: "",
                        },
                    ];
                var m = {
                    eth: r,
                    polygon: s,
                    bsc: c,
                    rangers: l,
                    scroll: u,
                    arbitrum: d,
                    avalanche: g,
                    kcc: p,
                    platon: h,
                };
                const f = [
                        {
                            chainId: 1,
                            contractAddress: "0xdac17f958d2ee523a2206206994597c13d831ec7",
                            name: "Tether",
                            symbol: "USDT",
                            decimals: 6,
                            logoURI: "",
                        },
                        {
                            chainId: 1,
                            contractAddress: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                            name: "USDC",
                            symbol: "USDC",
                            decimals: 6,
                            logoURI: "",
                        },
                    ],
                    y = [
                        {
                            chainId: 137,
                            contractAddress: "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
                            name: "Tether",
                            symbol: "USDT",
                            decimals: 6,
                            logoURI: "",
                        },
                        {
                            chainId: 137,
                            contractAddress: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
                            name: "USDC",
                            symbol: "USDC",
                            decimals: 6,
                            logoURI: "",
                        },
                    ],
                    w = [
                        {
                            chainId: 56,
                            contractAddress: "0x55d398326f99059fF775485246999027B3197955",
                            name: "USDT",
                            symbol: "USDT",
                            decimals: 18,
                            logoURI: "",
                        },
                        {
                            chainId: 56,
                            contractAddress: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
                            name: "USDC",
                            symbol: "USDC",
                            decimals: 18,
                            logoURI: "",
                        },
                    ],
                    v = [
                        {
                            chainId: 2025,
                            contractAddress: "0x8e8816a1747fddc5f8b45d2e140a425d3788f659",
                            name: "USDT",
                            symbol: "USDT",
                            decimals: 18,
                            logoURI: "",
                        },
                    ],
                    S = [
                        {
                            chainId: 42161,
                            contractAddress: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
                            name: "USDT",
                            symbol: "USDT",
                            decimals: 6,
                            logoURI: "",
                        },
                        {
                            chainId: 42161,
                            contractAddress: "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8",
                            name: "USDC",
                            symbol: "USDC",
                            decimals: 6,
                            logoURI: "",
                        },
                    ],
                    A = [
                        {
                            chainId: 43114,
                            contractAddress: "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7",
                            name: "TetherToken",
                            symbol: "USDt",
                            decimals: 6,
                            logoURI: "",
                        },
                        {
                            chainId: 43114,
                            contractAddress: "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e",
                            name: "USD Coin",
                            symbol: "USDC",
                            decimals: 6,
                            logoURI: "",
                        },
                    ],
                    T = [
                        {
                            chainId: 321,
                            contractAddress: "0x980a5afef3d17ad98635f6c5aebcbaeded3c3430",
                            name: "KCC-Peg USD Coin",
                            symbol: "USDC",
                            decimals: 18,
                            logoURI: "",
                        },
                        {
                            chainId: 321,
                            contractAddress: "0x0039f574ee5cc39bdd162e9a88e3eb1f111baf48",
                            name: "KCC-Peg Tether USD",
                            symbol: "USDT",
                            decimals: 18,
                            logoURI: "",
                        },
                    ],
                    _ = [
                        {
                            chainId: 210425,
                            contractAddress: "0x81ECac0D6Be0550A00FF064a4f9dd2400585FE9c",
                            name: "USD Coin",
                            symbol: "USDC",
                            decimals: 6,
                            logoURI: "",
                        },
                        {
                            chainId: 210425,
                            contractAddress: "0x97003a080D320eA015BEDba30df25e65Dc32164f",
                            name: "PlatON-Peg Tether USD",
                            symbol: "USDT",
                            decimals: 6,
                            logoURI: "",
                        },
                    ];
                var C = {
                        eth: f,
                        polygon: y,
                        bsc: w,
                        rangers: v,
                        arbitrum: S,
                        avalanche: A,
                        kcc: T,
                        platon: _,
                    },
                    P = n(35351),
                    E = n(53380),
                    k = n(99040),
                    b = n(93130),
                    I = n(15941);
                const U = async (e, t, n) => {
                        try {
                            const o = n.map(({ contractAddress: t }) =>
                                    t === b.je
                                        ? {
                                            target: b.bh,
                                            call: ["getEthBalance(address)(uint256)", e],
                                            returns: [["TOKEN_BALANCE_NATIVE", (e) => e]],
                                        }
                                        : {
                                            target: t,
                                            call: ["balanceOf(address)(uint256)", e],
                                            returns: [[`TOKEN_BALANCE_${t}`, (e) => e]],
                                        }
                                ),
                                a = await (0, E.m)(o, {
                                    rpcUrl: (0, i.Z1)(t),
                                    multicallAddress: b.bh,
                                }),
                                { transformed: r } = a.results;
                            return n.map((e) =>
                                e.contractAddress === b.je
                                    ? {
                                        ...e,
                                        balance: (0, k.o)(r["TOKEN_BALANCE_NATIVE"], e.decimals),
                                    }
                                    : {
                                        ...e,
                                        balance: (0, k.o)(
                                            r[`TOKEN_BALANCE_${e.contractAddress}`],
                                            e.decimals
                                        ),
                                    }
                            );
                        } catch (o) {
                            return (
                                I.error("getBalancesByMulticall failed", o),
                                    n.map((e) => ({ ...e, balance: "0" }))
                            );
                        }
                    },
                    O = (e) => {
                        const t = (0, i.IA)(),
                            n = (0, i.hZ)(e),
                            o = {
                                chain: n,
                                chainId: e,
                                name: (0, i.uV)(e),
                                symbol: (0, i.uV)(e),
                                decimals: 18,
                                contractAddress: b.je,
                            };
                        let a = [];
                        var r, s;
                        "mainnet" === t
                            ? (a = null !== (r = C[n]) && void 0 !== r ? r : [])
                            : (a = null !== (s = m[n]) && void 0 !== s ? s : []);
                        return [o, ...a].map((e) => ({ ...e, chain: n, default: !0 }));
                    },
                    R = (e) =>
                        (0, o.Z)(
                            e,
                            (e) => -1 * ((null === e || void 0 === e ? void 0 : e.worth) || 0)
                        ),
                    L = async (e, t) => {
                        let n = O(e);
                        const o = await P.Z.getTokenBalances(e, t);
                        o.ok && (n = (0, a.Im)(o.data, n)), (n = await U(t, e, n));
                        const r = n.map((e) => e.contractAddress),
                            s = await P.Z.getTokenPrices(e, r);
                        s.ok && (n = (0, a.Im)(n, s.data.tokens));
                        const c = n.map((t) => {
                                const n = t.decimals || 18,
                                    o = (0, k.L)(t.balance || "0", n),
                                    a = (0, k.L)((t.price || 0).toFixed(18), 18),
                                    r = parseFloat((0, k.o)(o.mul(a), 18 + n));
                                return {
                                    ...t,
                                    inited: !0,
                                    chain: (0, i.hZ)(e),
                                    worth: r,
                                    logoURI: t.default ? "" : t.logoURI,
                                };
                            }),
                            l = R(c);
                        return { sortedTokens: l, netWorth: (0, a.jO)(l), prevChainId: e };
                    };
            },
            91926: function (e, t, n) {
                "use strict";
                n.d(t, {
                    Ik: function () {
                        return r;
                    },
                    Im: function () {
                        return a;
                    },
                    jO: function () {
                        return i;
                    },
                });
                n(85827);
                var o = n(87079);
                const a = (e, t) => {
                        if (0 === e.length || 0 === t.length) return [...e, ...t];
                        const n = [...e, ...t];
                        return n.reduce((e, t) => {
                            const n = e.find(
                                (e) =>
                                    e.contractAddress.toLowerCase() ===
                                    t.contractAddress.toLowerCase()
                            );
                            return (
                                n
                                    ? Object.assign(n, {
                                        ...t,
                                        symbol: n.default ? n.symbol : t.symbol,
                                        name: n.default ? n.name : t.name,
                                    })
                                    : e.push({
                                        ...t,
                                        contractAddress: (0, o.getAddress)(t.contractAddress),
                                    }),
                                    e
                            );
                        }, []);
                    },
                    i = (e) => {
                        let t = 0;
                        return (
                            e.forEach(({ worth: e }) => {
                                t += e || 0;
                            }),
                                t.toFixed(2)
                        );
                    },
                    r = (e) => {
                        const t = e.toString().split(".");
                        let n = t[0];
                        const o = t[1] || "";
                        let a = "";
                        while (n.length > 3)
                            (a = "," + n.slice(-3) + a), (n = n.slice(0, n.length - 3));
                        return n && (a = n + a), "" === o ? a : a + "." + o;
                    };
            },
            20881: function (e, t, n) {
                "use strict";
                n.d(t, {
                    B: function () {
                        return i;
                    },
                });
                var o = n(42819),
                    a = n(93832);
                const i = async () => {
                    await a.Z.clearAccountInfo(), o.n.clearAll();
                };
            },
            88041: function (e, t, n) {
                "use strict";
                n.d(t, {
                    T9: function () {
                        return g;
                    },
                    dY: function () {
                        return d;
                    },
                    rf: function () {
                        return p;
                    },
                });
                const o = ["gmail.com", "googlemail.com"],
                    a = ["yahoo.com"],
                    i = ["qq.com", "foxmail.com"],
                    r = ["icloud.com"],
                    s = ["protonmail.com", "pm.me"],
                    c = ["outlook.com", "hotmail.com"],
                    l = ["mail.com"],
                    u = [
                        "163.com",
                        "126.com",
                        "yeah.net",
                        "vip.163.com",
                        "vip.126.com",
                        "188.com",
                        "vip.188.com",
                    ],
                    d = [...o, ...a, ...i, ...u, ...r],
                    g = [...s, ...c, ...l],
                    p = [...s, ...o];
                t["ZP"] = {
                    google: o,
                    yahoo: a,
                    tencent: i,
                    apple: r,
                    protonmail: s,
                    microsoft: c,
                    mail: l,
                    netease: u,
                };
            },
            7832: function (e, t, n) {
                "use strict";
                n.d(t, {
                    X: function () {
                        return u;
                    },
                });
                var o = n(86367),
                    a = n(54419),
                    i = n(24702),
                    r = n(3542);
                const s = r.Z.theme.darkList,
                    c = r.Z.theme.lightList,
                    l = s.concat(c),
                    u = () => {
                        const e = sessionStorage.theme;
                        if (e) {
                            const t = (0, o.e7M)(),
                                n = (0, a.OT)(t);
                            if ("dark" === e) n(!0);
                            else if ("light" === e) n(!1);
                            else if (l.includes(e)) {
                                s.includes(e) && n(!0), c.includes(e) && n(!1);
                                const t = document.querySelector("html");
                                t && t.classList.add(e);
                                for (const n of i.Z.global.availableLocales)
                                    n === e &&
                                    ((i.Z.global.locale.value = e),
                                        localStorage.setItem("language", e));
                            }
                        }
                    };
            },
            41397: function (e, t, n) {
                "use strict";
                n.d(t, {
                    Pn: function () {
                        return y;
                    },
                    U1: function () {
                        return f;
                    },
                    qX: function () {
                        return w;
                    },
                });
                var o = n(26156),
                    a = n(55743),
                    i = n.n(a),
                    r = n(61598),
                    s = n(73712),
                    c = n(61481),
                    l = n(42819),
                    u = n(78791),
                    d = n(78661);
                const g = (e, t = !0) => {
                        const n = t ? p() : (0, o.y0)();
                        if (n) {
                            const t = (0, c.L)();
                            (t.showOAuthCallback = e),
                                (t.showTimeSelect = !1),
                                (t.showOAuth = !0);
                        }
                        return n;
                    },
                    p = () => {
                        const e = h();
                        let t = !1;
                        if (e) {
                            const n = (0, r["default"])(e);
                            i()(1e3 * n.exp).isBefore(i()()) && (t = !0);
                        } else t = !1;
                        return t;
                    },
                    h = () => {
                        const e = (0, l.Y)();
                        if (!e) return;
                        const { authorization: t } = e;
                        return t;
                    },
                    m = async () => {
                        l.n.set("AUTHORIZATION_REQUIRE_STATE", !0);
                        const { accountInfo: e } = (0, c.L)(),
                            { email: t, oauth_provider: n } = e;
                        if (0 === n) window.location.href = (0, s.U7)(t);
                        else {
                            const e = (0, u.T)();
                            await e.auth0Login({ prompt: "login", email: t, provider: n });
                        }
                    },
                    f = async () => g(m),
                    y = async () => g(m, !1),
                    w = async () => {
                        const e = (0, d.j)(),
                            t = (0, c.L)();
                        await t.init();
                        const { address: n, keyset: o } = t.accountInfo;
                        await e.fetchAccountInfo(n, !0, o.hash),
                        o.hash !== e.keysetHash && t.exit();
                    };
            },
            26156: function (e, t, n) {
                "use strict";
                n.d(t, {
                    iX: function () {
                        return O;
                    },
                    y0: function () {
                        return v;
                    },
                    zw: function () {
                        return k;
                    },
                    wJ: function () {
                        return L;
                    },
                    b3: function () {
                        return P;
                    },
                    WT: function () {
                        return I;
                    },
                    AB: function () {
                        return T;
                    },
                    $: function () {
                        return A;
                    },
                    xJ: function () {
                        return E;
                    },
                    i_: function () {
                        return U;
                    },
                    Bz: function () {
                        return R;
                    },
                    jm: function () {
                        return C;
                    },
                    Sb: function () {
                        return b;
                    },
                    Ab: function () {
                        return _;
                    },
                });
                n(38862);
                var o = n(61481),
                    a = n(35351),
                    i = n(61598),
                    r = n(55743),
                    s = n.n(r),
                    c = n(78791),
                    l = n(42819),
                    u = n(73712),
                    d = n(68466),
                    g = n(88363),
                    p = n(24702);
                const { t: h } = p.Z.global,
                    m = (e, t) => {
                        g.T.confirm(h("GoogleTip", { data: e }), h("GoogleTitle"), {
                            dangerouslyUseHTMLString: !0,
                            confirmButtonText: h("TryAgain"),
                            cancelButtonText: h("Cancel"),
                        })
                            .then(t)
                            .catch(() => {});
                    };
                var f = n(31030),
                    y = n(78661);
                const w = (e) => {
                        const t = v();
                        return t && S(e), t;
                    },
                    v = () => {
                        const e = A();
                        let t = !1;
                        if (e) {
                            const n = (0, i["default"])(e);
                            s()(1e3 * n.exp).isBefore(s()()) && (t = !0);
                        } else t = !0;
                        return t;
                    },
                    S = (e, t, n = !1) => {
                        const a = (0, o.L)();
                        (a.showOAuthCallback = e),
                            "multiSync" !== t || v() || ((a.showTimeSelect = !1), !n)
                                ? (a.showOAuth = !0)
                                : e();
                    },
                    A = () => {
                        const e = (0, l.Y)();
                        if (!e) return void (0, o.L)().exit();
                        const { up_sign_token: t } = e;
                        return t;
                    },
                    T = () => {
                        const e = (0, l.Y)();
                        if (!e) return void (0, o.L)().exit();
                        const { up_sign_token: t = "" } = e,
                            n = (0, i["default"])(t);
                        n &&
                        n.isDisposable &&
                        l.n.set(
                            "OAUTH_INFO",
                            JSON.stringify({ ...e, up_sign_token: void 0 })
                        );
                    },
                    _ = async (e, t) => {
                        if (!e) return;
                        const { sub: n, nonce: r } = (0, i["default"])(e),
                            c = (0, l.Y)();
                        var u;
                        if (n !== (null === c || void 0 === c ? void 0 : c.sub))
                            return void m(
                                null !== (u = null === c || void 0 === c ? void 0 : c.email) &&
                                void 0 !== u
                                    ? u
                                    : "",
                                t
                            );
                        let d;
                        const g = parseInt(l.n.get("UP_SIGN_TOKEN_DURATION") || "60");
                        d = r.startsWith("update-up-sign-token")
                            ? await a.Z.signToken({ idToken: e, duration: g })
                            : await a.Z.sendSyncOAuthSig({ idToken: e, duration: g });
                        const p = (0, l.Y)();
                        if (d.ok && p) {
                            const { authorization: e, upSignToken: t } = d.data;
                            let n = "";
                            const o = A();
                            if (o) {
                                const e = (0, i["default"])(o);
                                n = s()(1e3 * e.exp).diff(void 0, "h") > 0 ? o : t;
                            } else n = t;
                            l.n.set(
                                "OAUTH_INFO",
                                JSON.stringify({ ...p, authorization: e, up_sign_token: n })
                            );
                        } else (0, o.L)().exit();
                    },
                    C = async () => {
                        l.n.set("GUARDIAN_ORIGIN_STATE", !0);
                        const { accountInfo: e } = (0, o.L)(),
                            { email: t, oauth_provider: n } = e,
                            a = N();
                        if (0 === n) window.location.href = (0, u.kj)(a, t);
                        else {
                            const e = (0, c.T)();
                            await e.auth0Login({
                                prompt: void 0,
                                email: t,
                                nonce: a,
                                scope: "openid",
                                provider: n,
                            });
                        }
                    },
                    P = async () => w(C),
                    E = async () => {
                        l.n.set("CANCEL_RECOVERY_ORIGIN_STATE", !0);
                        const { accountInfo: e } = (0, o.L)(),
                            { email: t, oauth_provider: n } = e,
                            a = N();
                        if (0 === n) window.location.href = (0, u.kj)(a, t);
                        else {
                            const e = (0, c.T)();
                            await e.auth0Login({
                                prompt: void 0,
                                email: t,
                                nonce: a,
                                scope: "openid",
                                provider: n,
                            });
                        }
                    },
                    k = async () => w(E),
                    b = async (e) => {
                        l.n.set("SIGN_MESSAGE_ORIGIN_STATE", e);
                        const { accountInfo: t } = (0, o.L)(),
                            { email: n, oauth_provider: a } = t,
                            i = N();
                        if (0 === a) window.location.href = (0, u.kj)(i, n);
                        else {
                            const e = (0, c.T)();
                            await e.auth0Login({
                                prompt: void 0,
                                email: n,
                                nonce: i,
                                scope: "openid",
                                provider: a,
                            });
                        }
                    },
                    I = async (e) => w(() => b(e)),
                    U = async (e, t) => {
                        l.n.set("SIGN_TX_ORIGIN_STATE", t);
                        const { accountInfo: n } = (0, o.L)(),
                            { email: a, address: i, oauth_provider: r, keyset: s } = n;
                        let g = "";
                        if ("upSignToken" === e) g = N();
                        else {
                            const e = await d.ZP.getMetaNonce(i);
                            g = await x(s.hash, e, i);
                        }
                        if (0 === r) window.location.href = (0, u.kj)(g, a);
                        else {
                            const e = (0, c.T)();
                            await e.auth0Login({
                                prompt: void 0,
                                email: a,
                                nonce: g,
                                scope: "openid",
                                provider: r,
                            });
                        }
                    },
                    O = (e, t, n = !1) => {
                        S(() => U(e, t), e, n);
                    },
                    R = async () => {
                        l.n.set("EIP4337HOOK_ORIGIN_STATE", !0);
                        const { accountInfo: e } = (0, o.L)(),
                            { email: t, oauth_provider: n } = e,
                            a = N();
                        if (0 === n) window.location.href = (0, u.kj)(a, t);
                        else {
                            const e = (0, c.T)();
                            await e.auth0Login({
                                prompt: void 0,
                                email: t,
                                nonce: a,
                                scope: "openid",
                                provider: n,
                            });
                        }
                    },
                    L = async () => w(R),
                    N = () => `update-up-sign-token+${(0, u.O1)()}`,
                    x = async (e, t, n) => {
                        t -= 1;
                        const o = (0, y.j)(),
                            a = (0, d.OR)().moduleMainUpgradable,
                            i = new f.SyncAccountTxBuilder(n, t, e, o.lockDuration, a, !1);
                        return i.digestMessage();
                    };
            },
            73712: function (e, t, n) {
                "use strict";
                n.d(t, {
                    $h: function () {
                        return u;
                    },
                    O1: function () {
                        return r;
                    },
                    U7: function () {
                        return c;
                    },
                    kj: function () {
                        return l;
                    },
                });
                var o = n(59821),
                    a = n(31030);
                const i = encodeURIComponent(window.location.origin + "/loading"),
                    r = () => o.randomBytes(Math.ceil(4)).toString("hex").slice(0, 8),
                    s = {
                        clientID:
                            "1076249686642-g0d42524fhdirjeho0t6n3cjd7pulmns.apps.googleusercontent.com",
                    },
                    c = (e) => {
                        const t = r(),
                            n = r();
                        return e
                            ? `https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount?redirect_uri=${i}&prompt=consent&response_type=id_token%20token&client_id=${s.clientID}&scope=openid%20email&state=${t}&nonce=${n}&login_hint=${e}&flowName=GeneralOAuthFlow`
                            : `https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount?redirect_uri=${i}&prompt=consent&response_type=id_token%20token&client_id=${s.clientID}&scope=openid%20email&state=${t}&nonce=${n}&flowName=GeneralOAuthFlow`;
                    },
                    l = (e, t) => {
                        const n = r();
                        return t
                            ? `https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount?redirect_uri=${i}&prompt=consent&response_type=id_token%20token&client_id=${s.clientID}&scope=openid&state=${n}&nonce=${e}&login_hint=${t}&flowName=GeneralOAuthFlow`
                            : `https://accounts.google.com/o/oauth2/v2/auth/oauthchooseaccount?redirect_uri=${i}&prompt=consent&response_type=id_token%20token&client_id=${s.clientID}&scope=openid&state=${n}&nonce=${e}&flowName=GeneralOAuthFlow`;
                    };
                function u(e, t, n) {
                    const o = new a.UpdateKeysetHashTxBuilder(e, n, t, !1);
                    return o.digestMessage();
                }
            },
            5941: function (e, t, n) {
                "use strict";
                n.d(t, {
                    h: function () {
                        return i;
                    },
                    p: function () {
                        return r;
                    },
                });
                var o = n(87079),
                    a = n(98074);
                async function i(e, t) {
                    const n = await (0, a.encryptKeystore)((0, o.toUtf8Bytes)(e), t, {
                        scrypt: { N: 16 },
                    });
                    return n;
                }
                async function r(e, t) {
                    const n = await (0, a.decryptKeystore)(e, t);
                    return (0, o.toUtf8String)(n);
                }
            },
            10010: function (e, t, n) {
                "use strict";
                n.d(t, {
                    zO: function () {
                        return m;
                    },
                    zN: function () {
                        return h;
                    },
                    uv: function () {
                        return c;
                    },
                    oL: function () {
                        return l;
                    },
                    L: function () {
                        return g;
                    },
                    d$: function () {
                        return w;
                    },
                    G4: function () {
                        return u;
                    },
                    Bk: function () {
                        return f;
                    },
                    hz: function () {
                        return d;
                    },
                });
                var o = n(36482),
                    a = n(94469),
                    i = n(59878);
                class r {
                    static getMasterKeyWeight() {
                        return { ownerWeight: 60, guardianWeight: 0, assetsOpWeight: 100 };
                    }
                    static getCustodialMasterKeyWeight() {
                        return { ownerWeight: 100, guardianWeight: 0, assetsOpWeight: 100 };
                    }
                    static getPolicyWeight() {
                        return { ownerWeight: 40, guardianWeight: 0, assetsOpWeight: 0 };
                    }
                    static getRegisterEmailWeight() {
                        return { ownerWeight: 60, guardianWeight: 60, assetsOpWeight: 0 };
                    }
                    static getSelfGuardianWeight() {
                        return { ownerWeight: 50, guardianWeight: 50, assetsOpWeight: 0 };
                    }
                    static getOneGuardianWeight() {
                        return { ownerWeight: 0, guardianWeight: 50, assetsOpWeight: 0 };
                    }
                    static getMoreGuardianWeight() {
                        return { ownerWeight: 0, guardianWeight: 40, assetsOpWeight: 0 };
                    }
                }
                var s = n(59821);
                function c(e, t, n, o, a, s) {
                    const c = r.getMasterKeyWeight(),
                        l = new i.KeySecp256k1(
                            o,
                            new i.RoleWeight(
                                c.ownerWeight,
                                c.assetsOpWeight,
                                c.guardianWeight
                            ),
                            i.SignType.EthSign,
                            async () => Promise.resolve("")
                        ),
                        u = i.Keyset.fromJson(a).keys[0],
                        d = [];
                    for (const h of e) {
                        let t =
                            e.length < 2
                                ? r.getOneGuardianWeight()
                                : r.getMoreGuardianWeight();
                        !0 === h.isSelfGuardian && (t = r.getSelfGuardianWeight());
                        const n = new i.KeyEmailDkim(
                            h.email.includes("*") ? "Hash" : "Raw",
                            h.email,
                            h.pepper,
                            new i.RoleWeight(
                                t.ownerWeight,
                                t.assetsOpWeight,
                                t.guardianWeight
                            ),
                            void 0,
                            h.emailHash
                        );
                        d.push(n);
                    }
                    const g = r.getRegisterEmailWeight(),
                        p = i.Keyset.create(
                            n,
                            s,
                            t,
                            l,
                            d,
                            u,
                            new i.RoleWeight(
                                g.ownerWeight,
                                g.assetsOpWeight,
                                g.guardianWeight
                            )
                        );
                    return p;
                }
                function l(e) {
                    const t = r.getCustodialMasterKeyWeight(),
                        n = new i.KeySecp256k1(
                            e,
                            new i.RoleWeight(
                                t.ownerWeight,
                                t.assetsOpWeight,
                                t.guardianWeight
                            ),
                            i.SignType.EthSign,
                            async () => Promise.resolve("")
                        );
                    return new i.Keyset([n]);
                }
                function u(e, t) {
                    var n;
                    const o = e.keys,
                        a =
                            1 === t.length
                                ? r.getOneGuardianWeight()
                                : r.getMoreGuardianWeight(),
                        s = t.map(
                            (e) =>
                                new i.KeyEmailDkim(
                                    e.rawOrHash,
                                    e.email,
                                    e.pepper,
                                    new i.RoleWeight(
                                        a.ownerWeight,
                                        a.assetsOpWeight,
                                        a.guardianWeight
                                    ),
                                    void 0,
                                    e.emailHash
                                )
                        ),
                        c = o.slice(0, 2),
                        l = null !== (n = o.slice(-1)) && void 0 !== n ? n : [],
                        u = [...c, ...s, ...l];
                    return new i.Keyset(u);
                }
                function d(e, t) {
                    const n = i.Keyset.fromJson(e),
                        o = r.getMasterKeyWeight(),
                        a = new i.KeySecp256k1(
                            t,
                            new i.RoleWeight(
                                o.ownerWeight,
                                o.assetsOpWeight,
                                o.guardianWeight
                            ),
                            i.SignType.EthSign,
                            async () => Promise.resolve("")
                        );
                    return (n.keys[0] = a), n;
                }
                function g(e) {
                    const t = i.Keyset.fromJson(e),
                        n = [];
                    return (
                        t.keys.forEach((e) => {
                            if (i.KeyEmailDkim.isKeyEmailDkim(e))
                                n.push({
                                    email: e.emailFrom,
                                    emailHash: e.emailHash,
                                    weight: e.roleWeight.guardianWeight,
                                    isDkimEmail: !0,
                                });
                            else if (i.KeyOpenIDWithEmail.isKeyOpenIDWithEmail(e)) {
                                const t =
                                        "string" === typeof e.emailOptionsOrEmailHash
                                            ? ""
                                            : e.emailOptionsOrEmailHash.emailFrom,
                                    o =
                                        "string" === typeof e.emailOptionsOrEmailHash
                                            ? ""
                                            : e.emailOptionsOrEmailHash.emailHash;
                                n.push({
                                    email: t,
                                    emailHash: o,
                                    weight: e.roleWeight.guardianWeight,
                                    isDkimEmail: !1,
                                });
                            }
                        }),
                            n
                    );
                }
                function p(e, t) {
                    const n = {
                        canSendStartRecoveryTx: !1,
                        isHaveTimeLock: !0,
                        isPolicy: t,
                    };
                    return (
                        e >= 100
                            ? ((n.canSendStartRecoveryTx = !0), (n.isHaveTimeLock = !1))
                            : e < 100 && e >= 50
                                ? ((n.canSendStartRecoveryTx = !0), (n.isHaveTimeLock = !0))
                                : ((n.canSendStartRecoveryTx = !1), (n.isHaveTimeLock = !1)),
                            n
                    );
                }
                function h(e, t) {
                    const n = i.Keyset.fromJson(e);
                    let o = 0;
                    const a = !(n.keys.length > 3);
                    for (const s of n.keys) {
                        let e = "";
                        const n = s.roleWeight.guardianWeight;
                        if (i.KeyOpenIDWithEmail.isKeyOpenIDWithEmail(s))
                            e =
                                "string" === typeof s.emailOptionsOrEmailHash
                                    ? s.emailOptionsOrEmailHash
                                    : s.emailOptionsOrEmailHash.emailHash;
                        else {
                            if (!i.KeyEmailDkim.isKeyEmailDkim(s)) continue;
                            e = s.emailHash;
                        }
                        t.includes(e) && (o += n);
                    }
                    a &&
                    3 === n.keys.length &&
                    (o += n.keys[n.keys.length - 1].roleWeight.ownerWeight);
                    const r = p(o, a);
                    return r;
                }
                async function m(e, t) {
                    const n = i.Keyset.fromJson(e),
                        o = n.keys[0];
                    return (o.signFunc = t), (n.keys[0] = o), n;
                }
                function f(e, t) {
                    if (!e) return "";
                    const n = o.concat([a.Y0(e), o.arrayify(t)]),
                        i = (0, s.createHash)("sha256").update(n).digest("hex");
                    return `0x${i}`;
                }
                function y(e) {
                    if (!e) return "";
                    const t = e.split("@"),
                        n = t[0][0],
                        o = t[0][t[0].length - 1];
                    return e.includes("@") ? `${n}***${o}@${t[1]}` : `${n}***${o}`;
                }
                function w(e) {
                    const t = i.Keyset.fromJson(e),
                        n = t.keys;
                    for (const [o, a] of n.entries()) {
                        if (o < 2) continue;
                        const e = a;
                        if (!e.emailFrom) continue;
                        const t = new i.KeyEmailDkim(
                            "Hash",
                            y(e.emailFrom),
                            "0x0000000000000000000000000000000000000000000000000000000000000000",
                            e.roleWeight,
                            e.getDkimParams(),
                            e.emailHash
                        );
                        n[o] = t;
                    }
                    return t.toJson();
                }
            },
            43395: function (e, t, n) {
                "use strict";
                n.d(t, {
                    DR: function () {
                        return T;
                    },
                    uh: function () {
                        return d;
                    },
                    Sc: function () {
                        return p;
                    },
                    iB: function () {
                        return g;
                    },
                    pi: function () {
                        return v;
                    },
                    KR: function () {
                        return A;
                    },
                    FF: function () {
                        return S;
                    },
                    $K: function () {
                        return m;
                    },
                    Dl: function () {
                        return y;
                    },
                    wM: function () {
                        return f;
                    },
                });
                n(38862);
                var o = n(56827),
                    a = n(23104),
                    i = n(54663),
                    r = n(9678),
                    s = n(94469),
                    c = n(88363),
                    l = n(24702),
                    u = n(15941);
                const d = (e) => {
                        var t, n;
                        null !== (t = window) &&
                        void 0 !== t &&
                        null !== (n = t.flutter_inappwebview) &&
                        void 0 !== n &&
                        n.callHandler &&
                        ((window.onConnectPageReady = (t) => {
                            try {
                                e(t);
                            } catch (n) {
                                u.error("connectReady:", n);
                            }
                        }),
                            window.flutter_inappwebview.callHandler("onConnectReady", !0));
                    },
                    g = (e) => {
                        var t, n;
                        null !== (t = window) &&
                        void 0 !== t &&
                        null !== (n = t.flutter_inappwebview) &&
                        void 0 !== n &&
                        n.callHandler &&
                        ((window.onSignMessageReady = (t) => {
                            try {
                                e(t);
                            } catch (n) {
                                u.error("signMessageReady:", n);
                            }
                        }),
                            window.flutter_inappwebview.callHandler(
                                "onSignMessageReady",
                                !0
                            ));
                    },
                    p = (e) => {
                        var t, n;
                        null !== (t = window) &&
                        void 0 !== t &&
                        null !== (n = t.flutter_inappwebview) &&
                        void 0 !== n &&
                        n.callHandler &&
                        ((window.onSendTransactionReady = (t) => {
                            try {
                                e(t);
                            } catch (n) {
                                u.error("sendTransactionReady:", n);
                            }
                        }),
                            window.flutter_inappwebview.callHandler(
                                "onSendTransactionReady",
                                !0
                            ));
                    };
                var h = n(15941);
                const m = (e) => {
                        var t;
                        null !== (t = window) &&
                        void 0 !== t &&
                        t.vuplex &&
                        ((window.onConnectPageReady = (t) => {
                            try {
                                e(t);
                            } catch (n) {
                                h.error("vuplexConnectReady", n);
                            }
                        }),
                            window.vuplex.postMessage("onConnectReady"));
                    },
                    f = (e) => {
                        var t;
                        null !== (t = window) &&
                        void 0 !== t &&
                        t.vuplex &&
                        ((window.onSignMessagePageReady = (t) => {
                            try {
                                e(t);
                            } catch (n) {
                                h.error("vuplexSignMessageReady", n);
                            }
                        }),
                            window.vuplex.postMessage("onSignMessageReady"));
                    },
                    y = (e) => {
                        var t;
                        null !== (t = window) &&
                        void 0 !== t &&
                        t.vuplex &&
                        ((window.onSendTransactionPageReady = (t) => {
                            try {
                                e(t);
                            } catch (n) {
                                h.error("vuplexSendTransactionReady", n);
                            }
                        }),
                            window.vuplex.postMessage("onSendTransactionReady"));
                    };
                var w = n(15941);
                const v = (e) => {
                        var t;
                        null !== (t = window) &&
                        void 0 !== t &&
                        t.ue &&
                        (window.onConnectPageReady = (t) => {
                            try {
                                e(t);
                            } catch (n) {
                                w.error("unrealConnectReady", n);
                            }
                        });
                    },
                    S = (e) => {
                        var t;
                        null !== (t = window) &&
                        void 0 !== t &&
                        t.ue &&
                        (window.onSignMessagePageReady = (t) => {
                            try {
                                e(t);
                            } catch (n) {
                                w.error("unrealSignMessageReady", n);
                            }
                        });
                    },
                    A = (e) => {
                        var t;
                        null !== (t = window) &&
                        void 0 !== t &&
                        t.ue &&
                        (window.onSendTransactionPageReady = (t) => {
                            try {
                                e(t);
                            } catch (n) {
                                w.error("unrealSendTransactionReady", n);
                            }
                        });
                    },
                    T = (e) => {
                        const { t: t } = l.Z.global;
                        c.T.alert(t("AddressInconsistentTip"), t("Notification"), {
                            confirmButtonText: t("Confirm"),
                            center: !0,
                            showClose: !1,
                            showCancelButton: !1,
                        })
                            .then(() => {
                                if (
                                    ((0, o.Sr)() &&
                                    (0, i.oi)(
                                        new a.cW(
                                            "UP_RESPONSE",
                                            JSON.stringify(new a.vq("DECLINE", "invalid login"))
                                        )
                                    ),
                                    (0, o.Zh)() &&
                                    window.flutter_inappwebview.callHandler(
                                        "onUserInfoInvalid",
                                        new a.cW(
                                            "UP_RESPONSE",
                                            JSON.stringify(new a.vq("DECLINE", "invalid login"))
                                        )
                                    ),
                                        (0, o.fl)())
                                )
                                    window.vuplex.postMessage(
                                        new a.cW(
                                            "UP_RESPONSE",
                                            JSON.stringify(new a.vq("DECLINE", "invalid login"))
                                        )
                                    );
                                else {
                                    var t, n, c, l, u, d, g, p, h;
                                    if ((0, o.cr)())
                                        return (
                                            null === (t = window) ||
                                            void 0 === t ||
                                            null === (n = t.ue) ||
                                            void 0 === n ||
                                            null === (c = n.unipass) ||
                                            void 0 === c ||
                                            c.onlogin(new a.xY("", "", !1)),
                                            null === (l = window) ||
                                            void 0 === l ||
                                            null === (u = l.ue) ||
                                            void 0 === u ||
                                            null === (d = u.unipass) ||
                                            void 0 === d ||
                                            d.onsignmessage(""),
                                                void (
                                                    null === (g = window) ||
                                                    void 0 === g ||
                                                    null === (p = g.ue) ||
                                                    void 0 === p ||
                                                    null === (h = p.unipass) ||
                                                    void 0 === h ||
                                                    h.onsendtransaction("")
                                                )
                                        );
                                    if (sessionStorage.redirectUrl) {
                                        const t = new URL(
                                            sessionStorage.redirectUrl
                                        ).searchParams.get("redirectUrl");
                                        sessionStorage.removeItem("redirectUrl");
                                        const n = {
                                                type: e.type,
                                                errorCode: 409,
                                                errorMsg:
                                                    "Address mismatch. Please reconnect to UniPass in the app for authentication.",
                                            },
                                            o = r.encode(s.Y0(JSON.stringify(n)));
                                        location.href = `${decodeURI(t)}#${o}`;
                                    } else;
                                }
                            })
                            .catch(() => {});
                    };
            },
            65219: function (e, t, n) {
                "use strict";
                n.d(t, {
                    U: function () {
                        return i;
                    },
                    i: function () {
                        return a;
                    },
                });
                n(48675), n(3462), n(33824), n(37380), n(1118);
                var o = n(87079);
                const a = async (e) => {
                    const t = (0, o.randomBytes)(16),
                        n = await window.crypto.subtle.generateKey(
                            { name: "AES-CBC", length: 256 },
                            !1,
                            ["encrypt", "decrypt"]
                        ),
                        a = await window.crypto.subtle.encrypt(
                            { name: "AES-CBC", iv: t },
                            n,
                            (0, o.toUtf8Bytes)(e)
                        );
                    return {
                        encrypted_key: (0, o.hexlify)(
                            (0, o.concat)([
                                (0, o.hexlify)(t),
                                (0, o.hexlify)(new Uint8Array(a)),
                            ])
                        ),
                        aes_key: n,
                    };
                };
                async function i(e, t) {
                    const n = (0, o.arrayify)(t),
                        a = await window.crypto.subtle.decrypt(
                            { name: "AES-CBC", iv: n.slice(0, 16) },
                            e,
                            n.slice(16)
                        );
                    return (0, o.toUtf8String)(new Uint8Array(a));
                }
            },
            14041: function (e, t, n) {
                "use strict";
                n.d(t, {
                    W: function () {
                        return o;
                    },
                });
                const o = (e, t) => !(!e || !t) && e.toLowerCase() === t.toLowerCase();
            },
            12434: function (e, t, n) {
                "use strict";
                n(38862), n(21703);
                var o = n(87079),
                    a = n(59878),
                    i = n(35351),
                    r = n(4369);
                n(98074);
                const s = async (e) => {
                        const t = await i.Z.startKeygen(e),
                            n = t.data.tssRes,
                            [o, a] = await r.TssWorker.getP2KeyGen1(n),
                            s = {
                                sessionId: n.sessionId,
                                tssMsg: a,
                                email: e.email,
                                action: e.action,
                            };
                        return { context2: o, keygenInput: s };
                    },
                    c = async (e) => {
                        const t = await i.Z.getKeygen(e.keygenInput),
                            n = t.data.tssRes,
                            [a, s] = await r.TssWorker.getP2KeyGen2(n, e.context2),
                            c = (0, o.computeAddress)(s.point),
                            l = {
                                sessionId: n.sessionId,
                                email: e.keygenInput.email,
                                userId: n.userId,
                                localKeyAddress: c,
                                action: e.keygenInput.action,
                            };
                        return { signContext2: a, finishKeygenInput: l };
                    },
                    l = async (e) => {
                        const { signContext2: t, finishKeygenInput: n } = e;
                        await i.Z.finishKeygen(n);
                        const { userId: o, localKeyAddress: a } = n;
                        return {
                            localKeyAddress: a,
                            userId: o,
                            keystore: JSON.stringify(t),
                        };
                    },
                    u = async (e) => {
                        try {
                            let n;
                            try {
                                n = await s(e);
                            } catch (t) {
                                return null;
                            }
                            const o = await c(n),
                                a = await l(o);
                            return a;
                        } catch (t) {
                            return u(e);
                        }
                    };
                const d = async (e, t, n) => {
                        const a = (0, o.hashMessage)((0, o.arrayify)(n)),
                            s = Array.from((0, o.arrayify)(a)),
                            c = await r.TssWorker.getLi17P2Sign1(e, s);
                        if (!c) throw Error("error");
                        const [l, u] = c,
                            d = n,
                            g = await i.Z.startSign({
                                tssMsg: u,
                                value: d,
                                localKeyAddress: t,
                            }),
                            p = g.data.tssRes,
                            h = p.sessionId,
                            [m, f] = await r.TssWorker.getLi17P2Sign2(l, p.msg);
                        return { tssMsg: [m, f], value: d, sessionId: h };
                    },
                    g = async (e) => {
                        const t = await i.Z.sign(e),
                            n = t.data.tssRes;
                        let a = n.msg;
                        (a.r = (0, o.zeroPad)(a.r, 32)), (a.s = (0, o.zeroPad)(a.s, 32));
                        const r = (0, o.concat)([a.r, a.s, a.recid]);
                        a = (0, o.hexlify)(r);
                        const s = a.slice(0, a.length - 2);
                        return (
                            a.endsWith("01") && (a = `${s}1c`),
                            a.endsWith("00") && (a = `${s}1b`),
                                a
                        );
                    },
                    p = async (e, t, n) => {
                        try {
                            let a;
                            try {
                                a = await d(e, t, n);
                            } catch (o) {
                                return "";
                            }
                            const i = await g(a);
                            return i;
                        } catch (o) {
                            return p(e, t, n);
                        }
                    },
                    h = async (e, t, n, i = a.SignType.EthSign) => {
                        const r = await p(JSON.parse(e), t, n),
                            s = (0, o.solidityPack)(["bytes", "uint8"], [r, i]);
                        return s;
                    },
                    m = { generateLocalKey: u, generateTssTxSignature: h };
                t["ZP"] = m;
            },
            14052: function (e, t, n) {
                "use strict";
                n.d(t, {
                    E3: function () {
                        return S;
                    },
                    Hs: function () {
                        return L;
                    },
                    JG: function () {
                        return C;
                    },
                    Tg: function () {
                        return P;
                    },
                    az: function () {
                        return I;
                    },
                    b_: function () {
                        return w;
                    },
                    dN: function () {
                        return k;
                    },
                    dT: function () {
                        return v;
                    },
                    fS: function () {
                        return b;
                    },
                    go: function () {
                        return E;
                    },
                    m0: function () {
                        return O;
                    },
                    oH: function () {
                        return U;
                    },
                    pL: function () {
                        return T;
                    },
                    tq: function () {
                        return R;
                    },
                    x9: function () {
                        return A;
                    },
                    yC: function () {
                        return _;
                    },
                });
                var o = n(73396),
                    a = n(86367),
                    i = n(5658),
                    r = (n(68757), n(21703), n(88041)),
                    s = n(70498),
                    c = n(61481),
                    l = n(31565),
                    u = n(88363),
                    d = n(47128),
                    g = n(60990),
                    p = n(56827),
                    h = n(87079),
                    m = n(24702),
                    f = n(7544),
                    y = n.n(f);
                const w = (e, t = 3e3) => {
                        (0, l.z8)({
                            message: e,
                            type: "success",
                            icon: (0, o.h)(d.Z, { name: "success" }),
                            duration: t,
                            center: !0,
                            customClass: "up-message-success",
                            grouping: !0,
                        });
                    },
                    v = (e) => {
                        (0, l.z8)({
                            message: e,
                            type: "success",
                            icon: (0, o.h)(d.Z, { name: "success" }),
                            center: !0,
                            customClass: "up-message-info",
                            grouping: !0,
                        });
                    },
                    S = (e) => {
                        (0, l.z8)({
                            message: e,
                            type: "error",
                            icon: (0, o.h)(d.Z, { name: "wrong" }),
                            duration: 5e3,
                            customClass: "up-message-error",
                            grouping: !0,
                        });
                    },
                    A = (e, t, n = !1) => {
                        (0, l.z8)({
                            message: e,
                            type: "error",
                            icon: (0, o.h)(d.Z, { name: "wrong" }),
                            duration: t,
                            showClose: n,
                            customClass: "up-message-error",
                            grouping: !0,
                        });
                    },
                    T = {
                        0: "GoogleOAuth",
                        1: "Email",
                        2: "Apple",
                        3: "UniPassEmail",
                        4: "Custodial_KMS_email",
                    },
                    _ = async (e, t, n) => {
                        const o = (0, c.L)().accountInfo;
                        let { address: a, email: i } = o;
                        t && ((i = t.email || i), (a = t.address || a));
                        const r = n || o.oauth_provider,
                            s = T[r] || "-";
                        (t = {
                            appName: sessionStorage.appName || "UniPassWallet",
                            referrer: sessionStorage.referrer || "UniPassWallet",
                            uniqueID: s && i ? `${s}_${(0, h.hashMessage)(i)}` : "-",
                            openType: (0, p.F_)(),
                            accountType: s,
                            ...t,
                        }),
                            (t.email = i ? `email_${(0, h.hashMessage)(i)}` : "-"),
                            (t.account = a ? `address_${(0, h.hashMessage)(a)}` : "-"),
                            (0, g.uT)().event(e, t);
                    },
                    C = (e) => {
                        const { t: t } = m.Z.global;
                        (0, a.VPI)().copy(e), w(t("CopySuccess"));
                    },
                    P = (e) => {
                        if (!e) return "";
                        const t = e.slice(0, 6),
                            n = e.slice(-4);
                        return t + "..." + n;
                    },
                    E = (e, t = !1) => {
                        const { t: n } = m.Z.global;
                        for (const a of [" ", "+"]) e = e.replaceAll(a, "");
                        const o = e.indexOf("@");
                        if (-1 !== o) {
                            let a = e.slice(0, o),
                                i = "";
                            const s = e
                                .slice(o + 1)
                                .replaceAll("@", "")
                                .toLowerCase();
                            if (
                                (/[A-Z]/.test(a) &&
                                (r.dY.includes(s) && (a = a.toLowerCase()),
                                r.T9.includes(s) &&
                                (i =
                                    a.includes(".") && r.rf.includes(s)
                                        ? n("SameCaseDot")
                                        : n("SameCase"))),
                                a.includes(".") && r.rf.includes(s) && !i && (i = n("SameDot")),
                                    t)
                            )
                                return i;
                            e = a + "@" + s;
                        }
                        return e;
                    },
                    k = (e, t) => {
                        var n;
                        if (((e = e.replaceAll(/[^\d.]/g, "")), 0 === e.length)) return "";
                        const o =
                                null === (n = (0, s.Y)().coin) || void 0 === n
                                    ? void 0
                                    : n.decimals,
                            a = e.indexOf(".");
                        if (-1 !== a) {
                            let n = e.slice(0, a),
                                i = e.slice(a + 1).replaceAll(".", "");
                            t && ("" === n && (n = "0"), "" === i && (i = "0")),
                                (i = i.slice(0, o)),
                                (e = n + "." + i);
                        }
                        return e;
                    },
                    b = (e) => {
                        const t = /[^A-z\d!"#$%&\\'()*+,-./:;<=>?@[\]^_`{|}~]/g;
                        return e.replaceAll(t, "");
                    },
                    I = (e, t = 4) => Number(Number(e).toFixed(t)),
                    U = (e, t, n) => {
                        const { t: o } = m.Z.global,
                            a = t;
                        return a
                            ? !1 === /^\S{8,32}$/.test(a)
                                ? n(new Error(o("PasswordRule1")))
                                : !1 === /(?=.*[A-Z])(?=.*\S)[^]/.test(a)
                                    ? n(new Error(o("PasswordRule2")))
                                    : !1 === /(?=[a-z])[^]/.test(a)
                                        ? n(new Error(o("PasswordRule3")))
                                        : !1 === /(?=[\d]+)/.test(a)
                                            ? n(new Error(o("PasswordRule4")))
                                            : void n()
                            : n(new Error(o("PasswordEmpty")));
                    },
                    O = (e) => {
                        const t = (0, i.QT)();
                        (t.locale.value = e), localStorage.setItem("language", e);
                    };
                function R() {
                    const e = y().getParser(window.navigator.userAgent);
                    return "mobile" === e.getPlatformType(!0);
                }
                const L = () => {
                    const { t: e } = (0, i.QT)(),
                        t = (0, c.L)(),
                        n = (t, n, o) => {
                            const a = n;
                            if (!a) return o();
                            const i = /^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$/;
                            if (!i.test(a)) return o(new Error(e("EmailWrongFormat")));
                            o();
                        },
                        o = (n, o, a) => {
                            const i = o;
                            if (!i) return a();
                            const r = /^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$/;
                            if (!r.test(i)) return a(new Error(e("EmailWrongFormat")));
                            if (!sessionStorage.mailServices)
                                return a(new Error(e("NetworkError")));
                            let s = !1;
                            for (const e of sessionStorage.mailServices.split(","))
                                i.endsWith("@" + e) && (s = !0);
                            if (!s)
                                return (t.showSupportEmail = !0), a(new Error(e("NotSupport")));
                            a();
                        },
                        a = () => {
                            u.T.confirm(e("SureLogOut"), e("LogOutAccount"), {
                                confirmButtonText: e("LogOut"),
                                cancelButtonText: e("Cancel"),
                            })
                                .then(() => {
                                    t.exit();
                                })
                                .catch(() => {});
                        };
                    return {
                        checkEmailFormat: n,
                        checkDkimEmailFormat: o,
                        checkPassword: U,
                        formatAddress: P,
                        formatEmail: E,
                        formatPassword: b,
                        formatBalance: I,
                        formatAmount: k,
                        copy: C,
                        success: w,
                        error: S,
                        info: v,
                        userExit: a,
                        setLanguage: O,
                    };
                };
            },
            73513: function (e, t, n) {
                "use strict";
                n.d(t, {
                    Z: function () {
                        return l;
                    },
                });
                var o = n(63614),
                    a = (n(86809), n(73396));
                function i(e, t) {
                    const n = o.mi;
                    return (
                        (0, a.wg)(),
                            (0, a.j4)(
                                n,
                                (0, a.dG)(e.$attrs, { class: "up-button" }),
                                (0, a.Nv)({ _: 2 }, [
                                    (0, a.Ko)(e.$slots, (t, n) => ({
                                        name: n,
                                        fn: (0, a.w5)(() => [(0, a.WI)(e.$slots, n)]),
                                    })),
                                ]),
                                1040
                            )
                    );
                }
                var r = n(40089);
                const s = {},
                    c = (0, r.Z)(s, [["render", i]]);
                var l = c;
            },
            50186: function (e, t, n) {
                "use strict";
                n.d(t, {
                    Z: function () {
                        return l;
                    },
                });
                var o = n(22710),
                    a = (n(9910), n(73396));
                function i(e, t) {
                    const n = o.d0;
                    return (
                        (0, a.wg)(),
                            (0, a.j4)(
                                n,
                                (0, a.dG)({ class: "up-confirm" }, e.$attrs, {
                                    center: "",
                                    "close-on-click-modal": !1,
                                    "close-on-press-escape": !1,
                                }),
                                (0, a.Nv)({ _: 2 }, [
                                    (0, a.Ko)(e.$slots, (t, n) => ({
                                        name: n,
                                        fn: (0, a.w5)(() => [(0, a.WI)(e.$slots, n)]),
                                    })),
                                ]),
                                1040
                            )
                    );
                }
                var r = n(40089);
                const s = {},
                    c = (0, r.Z)(s, [["render", i]]);
                var l = c;
            },
            51610: function (e, t, n) {
                "use strict";
                n.d(t, {
                    Z: function () {
                        return l;
                    },
                });
                var o = n(22710),
                    a = (n(9910), n(73396));
                function i(e, t) {
                    const n = o.d0;
                    return (
                        (0, a.wg)(),
                            (0, a.j4)(
                                n,
                                (0, a.dG)(e.$attrs, { center: "", "show-close": !1 }),
                                (0, a.Nv)({ _: 2 }, [
                                    (0, a.Ko)(e.$slots, (t, n) => ({
                                        name: n,
                                        fn: (0, a.w5)(() => [(0, a.WI)(e.$slots, n)]),
                                    })),
                                ]),
                                1040
                            )
                    );
                }
                var r = n(40089);
                const s = {},
                    c = (0, r.Z)(s, [["render", i]]);
                var l = c;
            },
            47128: function (e, t, n) {
                "use strict";
                n.d(t, {
                    Z: function () {
                        return l;
                    },
                });
                var o = n(86367),
                    a = n(73396),
                    i = n(44870),
                    r = n(87139),
                    s = (0, a.aZ)({
                        __name: "up-icon",
                        props: {
                            name: { default: "" },
                            width: { default: "" },
                            height: { default: "" },
                            type: null,
                        },
                        setup(e) {
                            const t = e,
                                n = (0, o.e7M)(),
                                s = (0, a.Fl)(() => {
                                    let e = t.name;
                                    if (("USDt" === e && (e = "USDT"), "coin" === t.type)) {
                                        const t = Object.keys(window.__iconpark__).filter((e) =>
                                            /^[A-Z]+$/.test(e)
                                        );
                                        return t.includes(e)
                                            ? e
                                            : n.value
                                                ? "coin-dark"
                                                : "coin-light";
                                    }
                                    return e;
                                });
                            return (t, n) => {
                                const o = (0, a.up)("iconpark-icon");
                                return (
                                    (0, a.wg)(),
                                        (0, a.j4)(
                                            o,
                                            {
                                                "icon-id": (0, i.SU)(s),
                                                width: e.width,
                                                height: e.height,
                                                class: (0, r.C_)(["iconpark", `icon-${(0, i.SU)(s)}`]),
                                            },
                                            null,
                                            8,
                                            ["icon-id", "width", "height", "class"]
                                        )
                                );
                            };
                        },
                    });
                const c = s;
                var l = c;
            },
            32814: function (e, t, n) {
                var o = {
                    "./_.vue": [50654, 654],
                    "./async-account.vue": [92238, 3349, 3499, 1416, 4451, 3941],
                    "./buy-coins.vue": [68076, 8076],
                    "./connect.vue": [21559, 3349, 3499, 1416, 739, 7548],
                    "./index.vue": [12019, 5134, 3349, 8385, 7844],
                    "./loading.vue": [79392, 9392],
                    "./login.vue": [9258, 5134, 7198, 9320],
                    "./logout.vue": [13543, 3543],
                    "./password-login.vue": [59909, 5134, 6714],
                    "./password-register.vue": [97679, 5134, 8006],
                    "./recovery.vue": [34807, 5134, 4161, 8974],
                    "./recovery/result.vue": [63766, 1369],
                    "./register.vue": [79932, 5134, 7198, 7936],
                    "./register/loading.vue": [2788, 2788],
                    "./send-nft.vue": [45525, 5134, 4161, 8992, 604],
                    "./send-transaction.vue": [48997, 3349, 3499, 1416, 4451, 1092],
                    "./send.vue": [67386, 5134, 4161, 8992, 6592],
                    "./send/result.vue": [21387, 4161, 8992, 993],
                    "./send/sign.vue": [16805, 3349, 3499, 1416, 4451, 3812],
                    "./setting.vue": [49947, 9947],
                    "./setting/2FA.vue": [71967, 1967],
                    "./setting/2FA/email.vue": [63393, 3393],
                    "./setting/2FA/google.vue": [55396, 510, 3648],
                    "./setting/2FA/phone.vue": [6509, 510, 8468],
                    "./setting/4337.vue": [66372, 6372],
                    "./setting/chain.vue": [16804, 4156],
                    "./setting/change-password.vue": [36095, 6095],
                    "./setting/guardian.vue": [2228, 5134, 739, 2923],
                    "./sign-message.vue": [54963, 3349, 3499, 1416, 4451, 6211],
                    "./verify-code.vue": [67405, 5134, 6936],
                    "./verify/google.vue": [41385, 8385, 1385],
                    "./verify/phone.vue": [44475, 5134, 8385, 6771],
                    "./wallet-connect-loading.vue": [92612, 2612],
                    "./wallet-connect.vue": [55476, 3349, 3499, 8215],
                    "./wc.vue": [25612, 3349, 5612],
                };
                function a(e) {
                    if (!n.o(o, e))
                        return Promise.resolve().then(function () {
                            var t = new Error("Cannot find module '" + e + "'");
                            throw ((t.code = "MODULE_NOT_FOUND"), t);
                        });
                    var t = o[e],
                        a = t[0];
                    return Promise.all(t.slice(1).map(n.e)).then(function () {
                        return n(a);
                    });
                }
                (a.keys = function () {
                    return Object.keys(o);
                }),
                    (a.id = 32814),
                    (e.exports = a);
            },
            70717: function (e, t, n) {
                var o = {
                    "./": [12019, 5134, 3349, 8385, 7844],
                    "./_": [50654, 654],
                    "./_.vue": [50654, 654],
                    "./async-account": [92238, 3349, 3499, 1416, 4451, 3941],
                    "./async-account.vue": [92238, 3349, 3499, 1416, 4451, 3941],
                    "./buy-coins": [68076, 8076],
                    "./buy-coins.vue": [68076, 8076],
                    "./connect": [21559, 3349, 3499, 1416, 739, 7548],
                    "./connect.vue": [21559, 3349, 3499, 1416, 739, 7548],
                    "./index": [12019, 5134, 3349, 8385, 7844],
                    "./index.vue": [12019, 5134, 3349, 8385, 7844],
                    "./loading": [79392, 9392],
                    "./loading.vue": [79392, 9392],
                    "./login": [9258, 5134, 7198, 9320],
                    "./login.vue": [9258, 5134, 7198, 9320],
                    "./logout": [13543, 3543],
                    "./logout.vue": [13543, 3543],
                    "./password-login": [59909, 5134, 6714],
                    "./password-login.vue": [59909, 5134, 6714],
                    "./password-register": [97679, 5134, 8006],
                    "./password-register.vue": [97679, 5134, 8006],
                    "./recovery": [34807, 5134, 4161, 8974],
                    "./recovery.vue": [34807, 5134, 4161, 8974],
                    "./recovery/result": [63766, 1369],
                    "./recovery/result.vue": [63766, 1369],
                    "./register": [79932, 5134, 7198, 7936],
                    "./register.vue": [79932, 5134, 7198, 7936],
                    "./register/loading": [2788, 2788],
                    "./register/loading.vue": [2788, 2788],
                    "./send": [67386, 5134, 4161, 8992, 6592],
                    "./send-nft": [45525, 5134, 4161, 8992, 604],
                    "./send-nft.vue": [45525, 5134, 4161, 8992, 604],
                    "./send-transaction": [48997, 3349, 3499, 1416, 4451, 1092],
                    "./send-transaction.vue": [48997, 3349, 3499, 1416, 4451, 1092],
                    "./send.vue": [67386, 5134, 4161, 8992, 6592],
                    "./send/result": [21387, 4161, 8992, 993],
                    "./send/result.vue": [21387, 4161, 8992, 993],
                    "./send/sign": [16805, 3349, 3499, 1416, 4451, 3812],
                    "./send/sign.vue": [16805, 3349, 3499, 1416, 4451, 3812],
                    "./setting": [49947, 9947],
                    "./setting.vue": [49947, 9947],
                    "./setting/2FA": [71967, 1967],
                    "./setting/2FA.vue": [71967, 1967],
                    "./setting/2FA/email": [63393, 3393],
                    "./setting/2FA/email.vue": [63393, 3393],
                    "./setting/2FA/google": [55396, 510, 3648],
                    "./setting/2FA/google.vue": [55396, 510, 3648],
                    "./setting/2FA/phone": [6509, 510, 8468],
                    "./setting/2FA/phone.vue": [6509, 510, 8468],
                    "./setting/4337": [66372, 6372],
                    "./setting/4337.vue": [66372, 6372],
                    "./setting/chain": [16804, 4156],
                    "./setting/chain.vue": [16804, 4156],
                    "./setting/change-password": [36095, 6095],
                    "./setting/change-password.vue": [36095, 6095],
                    "./setting/guardian": [2228, 5134, 739, 2923],
                    "./setting/guardian.vue": [2228, 5134, 739, 2923],
                    "./sign-message": [54963, 3349, 3499, 1416, 4451, 6211],
                    "./sign-message.vue": [54963, 3349, 3499, 1416, 4451, 6211],
                    "./verify-code": [67405, 5134, 6936],
                    "./verify-code.vue": [67405, 5134, 6936],
                    "./verify/google": [41385, 8385, 1385],
                    "./verify/google.vue": [41385, 8385, 1385],
                    "./verify/phone": [44475, 5134, 8385, 6771],
                    "./verify/phone.vue": [44475, 5134, 8385, 6771],
                    "./wallet-connect": [55476, 3349, 3499, 8215],
                    "./wallet-connect-loading": [92612, 2612],
                    "./wallet-connect-loading.vue": [92612, 2612],
                    "./wallet-connect.vue": [55476, 3349, 3499, 8215],
                    "./wc": [25612, 3349, 5612],
                    "./wc.vue": [25612, 3349, 5612],
                };
                function a(e) {
                    if (!n.o(o, e))
                        return Promise.resolve().then(function () {
                            var t = new Error("Cannot find module '" + e + "'");
                            throw ((t.code = "MODULE_NOT_FOUND"), t);
                        });
                    var t = o[e],
                        a = t[0];
                    return Promise.all(t.slice(1).map(n.e)).then(function () {
                        return n(a);
                    });
                }
                (a.keys = function () {
                    return Object.keys(o);
                }),
                    (a.id = 70717),
                    (e.exports = a);
            },
            88677: function () {},
            62808: function () {},
            28022: function () {},
            46601: function () {},
            89214: function () {},
            71922: function () {},
            2363: function () {},
            52361: function () {},
            94616: function () {},
        },
        t = {};
    function n(o) {
        var a = t[o];
        if (void 0 !== a) return a.exports;
        var i = (t[o] = { id: o, loaded: !1, exports: {} });
        return e[o].call(i.exports, i, i.exports, n), (i.loaded = !0), i.exports;
    }
    (n.m = e),
        (function () {
            n.amdO = {};
        })(),
        (function () {
            var e = [];
            n.O = function (t, o, a, i) {
                if (!o) {
                    var r = 1 / 0;
                    for (u = 0; u < e.length; u++) {
                        (o = e[u][0]), (a = e[u][1]), (i = e[u][2]);
                        for (var s = !0, c = 0; c < o.length; c++)
                            (!1 & i || r >= i) &&
                            Object.keys(n.O).every(function (e) {
                                return n.O[e](o[c]);
                            })
                                ? o.splice(c--, 1)
                                : ((s = !1), i < r && (r = i));
                        if (s) {
                            e.splice(u--, 1);
                            var l = a();
                            void 0 !== l && (t = l);
                        }
                    }
                    return t;
                }
                i = i || 0;
                for (var u = e.length; u > 0 && e[u - 1][2] > i; u--) e[u] = e[u - 1];
                e[u] = [o, a, i];
            };
        })(),
        (function () {
            n.n = function (e) {
                var t =
                    e && e.__esModule
                        ? function () {
                            return e["default"];
                        }
                        : function () {
                            return e;
                        };
                return n.d(t, { a: t }), t;
            };
        })(),
        (function () {
            n.d = function (e, t) {
                for (var o in t)
                    n.o(t, o) &&
                    !n.o(e, o) &&
                    Object.defineProperty(e, o, { enumerable: !0, get: t[o] });
            };
        })(),
        (function () {
            (n.f = {}),
                (n.e = function (e) {
                    return Promise.all(
                        Object.keys(n.f).reduce(function (t, o) {
                            return n.f[o](e, t), t;
                        }, [])
                    );
                });
        })(),
        (function () {
            n.u = function (e) {
                return (
                    "js/" +
                    e +
                    "." +
                    {
                        510: "07db0c87",
                        604: "1142561f",
                        654: "18fa4bbe",
                        739: "10bb5c1b",
                        789: "4521182e",
                        993: "69f55381",
                        1092: "128c4d41",
                        1369: "60296d7b",
                        1385: "f16d57f5",
                        1416: "1a3e1a8d",
                        1854: "8c91164c",
                        1967: "364f19b3",
                        2431: "eb0422af",
                        2612: "44c56cce",
                        2788: "9495cda0",
                        2801: "2b900705",
                        2923: "13afe8d3",
                        3349: "04ea6884",
                        3393: "ad58a7a4",
                        3499: "f867a76d",
                        3543: "3c3bbefc",
                        3648: "41f4a50c",
                        3812: "2f32a2ae",
                        3941: "5989f4ca",
                        4043: "7f4ee6f0",
                        4156: "d4028626",
                        4161: "b3156c28",
                        4451: "97f5adbd",
                        5134: "f1a299ce",
                        5612: "a075ae87",
                        6095: "9fcff478",
                        6211: "9bb7f424",
                        6372: "ee2a7f3b",
                        6592: "419d3975",
                        6714: "e4e533cd",
                        6771: "e0dc11a8",
                        6936: "4c63c37e",
                        7198: "9bbc527c",
                        7548: "6a293b72",
                        7844: "cd695ccd",
                        7936: "b53cd344",
                        8006: "530c5fd6",
                        8076: "4871e9b6",
                        8215: "feee5898",
                        8385: "565c8077",
                        8468: "ced97292",
                        8912: "fd32dbb7",
                        8918: "ef02a995",
                        8974: "dda7e767",
                        8992: "44291c14",
                        9320: "e1b8dfa8",
                        9392: "be8d6577",
                        9947: "ec9d5a53",
                    }[e] +
                    ".js"
                );
            };
        })(),
        (function () {
            n.miniCssF = function (e) {
                return (
                    "css/" +
                    e +
                    "." +
                    {
                        604: "639831e1",
                        654: "dd7224a1",
                        789: "9980aee7",
                        993: "5012595e",
                        1092: "4d472385",
                        1369: "35bb3e3c",
                        1385: "702d9fbb",
                        1854: "73659bce",
                        1967: "dad75d7e",
                        2612: "3a8c1e60",
                        2788: "dd7224a1",
                        2923: "80121560",
                        3393: "fa643d32",
                        3543: "8021e886",
                        3648: "12cd514c",
                        3812: "3ad4ed51",
                        3941: "4d472385",
                        4043: "e7206baf",
                        4156: "16fbef61",
                        6095: "46caca30",
                        6211: "23688015",
                        6372: "2046527c",
                        6592: "acb1dd5a",
                        6714: "25cbce4a",
                        6771: "70bfdeb1",
                        6936: "49f62889",
                        7548: "385ee6e2",
                        7844: "b53e1f08",
                        7936: "bd0e59f4",
                        8006: "0e18dd88",
                        8076: "21c24868",
                        8215: "a1a0cdbd",
                        8468: "12cd514c",
                        8912: "f1e429ae",
                        8918: "4265db33",
                        8974: "1295cb48",
                        9320: "bd0e59f4",
                        9947: "e74768cb",
                    }[e] +
                    ".css"
                );
            };
        })(),
        (function () {
            n.g = (function () {
                if ("object" === typeof globalThis) return globalThis;
                try {
                    return this || new Function("return this")();
                } catch (e) {
                    if ("object" === typeof window) return window;
                }
            })();
        })(),
        (function () {
            n.hmd = function (e) {
                return (
                    (e = Object.create(e)),
                    e.children || (e.children = []),
                        Object.defineProperty(e, "exports", {
                            enumerable: !0,
                            set: function () {
                                throw new Error(
                                    "ES Modules may not assign module.exports or exports.*, Use ESM export syntax, instead: " +
                                    e.id
                                );
                            },
                        }),
                        e
                );
            };
        })(),
        (function () {
            n.o = function (e, t) {
                return Object.prototype.hasOwnProperty.call(e, t);
            };
        })(),
        (function () {
            var e = {},
                t = "unipass-wallet:";
            n.l = function (o, a, i, r) {
                if (e[o]) e[o].push(a);
                else {
                    var s, c;
                    if (void 0 !== i)
                        for (
                            var l = document.getElementsByTagName("script"), u = 0;
                            u < l.length;
                            u++
                        ) {
                            var d = l[u];
                            if (
                                d.getAttribute("src") == o ||
                                d.getAttribute("data-webpack") == t + i
                            ) {
                                s = d;
                                break;
                            }
                        }
                    s ||
                    ((c = !0),
                        (s = document.createElement("script")),
                        (s.charset = "utf-8"),
                        (s.timeout = 120),
                    n.nc && s.setAttribute("nonce", n.nc),
                        s.setAttribute("data-webpack", t + i),
                        (s.src = o)),
                        (e[o] = [a]);
                    var g = function (t, n) {
                            (s.onerror = s.onload = null), clearTimeout(p);
                            var a = e[o];
                            if (
                                (delete e[o],
                                s.parentNode && s.parentNode.removeChild(s),
                                a &&
                                a.forEach(function (e) {
                                    return e(n);
                                }),
                                    t)
                            )
                                return t(n);
                        },
                        p = setTimeout(
                            g.bind(null, void 0, { type: "timeout", target: s }),
                            12e4
                        );
                    (s.onerror = g.bind(null, s.onerror)),
                        (s.onload = g.bind(null, s.onload)),
                    c && document.head.appendChild(s);
                }
            };
        })(),
        (function () {
            n.r = function (e) {
                "undefined" !== typeof Symbol &&
                Symbol.toStringTag &&
                Object.defineProperty(e, Symbol.toStringTag, { value: "Module" }),
                    Object.defineProperty(e, "__esModule", { value: !0 });
            };
        })(),
        (function () {
            n.nmd = function (e) {
                return (e.paths = []), e.children || (e.children = []), e;
            };
        })(),
        (function () {
            n.p = "/";
        })(),
        (function () {
            var e = function (e, t, n, o) {
                    var a = document.createElement("link");
                    (a.rel = "stylesheet"), (a.type = "text/css");
                    var i = function (i) {
                        if (((a.onerror = a.onload = null), "load" === i.type)) n();
                        else {
                            var r = i && ("load" === i.type ? "missing" : i.type),
                                s = (i && i.target && i.target.href) || t,
                                c = new Error(
                                    "Loading CSS chunk " + e + " failed.\n(" + s + ")"
                                );
                            (c.code = "CSS_CHUNK_LOAD_FAILED"),
                                (c.type = r),
                                (c.request = s),
                                a.parentNode.removeChild(a),
                                o(c);
                        }
                    };
                    return (
                        (a.onerror = a.onload = i),
                            (a.href = t),
                            document.head.appendChild(a),
                            a
                    );
                },
                t = function (e, t) {
                    for (
                        var n = document.getElementsByTagName("link"), o = 0;
                        o < n.length;
                        o++
                    ) {
                        var a = n[o],
                            i = a.getAttribute("data-href") || a.getAttribute("href");
                        if ("stylesheet" === a.rel && (i === e || i === t)) return a;
                    }
                    var r = document.getElementsByTagName("style");
                    for (o = 0; o < r.length; o++) {
                        (a = r[o]), (i = a.getAttribute("data-href"));
                        if (i === e || i === t) return a;
                    }
                },
                o = function (o) {
                    return new Promise(function (a, i) {
                        var r = n.miniCssF(o),
                            s = n.p + r;
                        if (t(r, s)) return a();
                        e(o, s, a, i);
                    });
                },
                a = { 2143: 0 };
            n.f.miniCss = function (e, t) {
                var n = {
                    604: 1,
                    654: 1,
                    789: 1,
                    993: 1,
                    1092: 1,
                    1369: 1,
                    1385: 1,
                    1854: 1,
                    1967: 1,
                    2612: 1,
                    2788: 1,
                    2923: 1,
                    3393: 1,
                    3543: 1,
                    3648: 1,
                    3812: 1,
                    3941: 1,
                    4043: 1,
                    4156: 1,
                    6095: 1,
                    6211: 1,
                    6372: 1,
                    6592: 1,
                    6714: 1,
                    6771: 1,
                    6936: 1,
                    7548: 1,
                    7844: 1,
                    7936: 1,
                    8006: 1,
                    8076: 1,
                    8215: 1,
                    8468: 1,
                    8912: 1,
                    8918: 1,
                    8974: 1,
                    9320: 1,
                    9947: 1,
                };
                a[e]
                    ? t.push(a[e])
                    : 0 !== a[e] &&
                    n[e] &&
                    t.push(
                        (a[e] = o(e).then(
                            function () {
                                a[e] = 0;
                            },
                            function (t) {
                                throw (delete a[e], t);
                            }
                        ))
                    );
            };
        })(),
        (function () {
            n.b = document.baseURI || self.location.href;
            var e = { 2143: 0 };
            (n.f.j = function (t, o) {
                var a = n.o(e, t) ? e[t] : void 0;
                if (0 !== a)
                    if (a) o.push(a[2]);
                    else {
                        var i = new Promise(function (n, o) {
                            a = e[t] = [n, o];
                        });
                        o.push((a[2] = i));
                        var r = n.p + n.u(t),
                            s = new Error(),
                            c = function (o) {
                                if (n.o(e, t) && ((a = e[t]), 0 !== a && (e[t] = void 0), a)) {
                                    var i = o && ("load" === o.type ? "missing" : o.type),
                                        r = o && o.target && o.target.src;
                                    (s.message =
                                        "Loading chunk " + t + " failed.\n(" + i + ": " + r + ")"),
                                        (s.name = "ChunkLoadError"),
                                        (s.type = i),
                                        (s.request = r),
                                        a[1](s);
                                }
                            };
                        n.l(r, c, "chunk-" + t, t);
                    }
            }),
                (n.O.j = function (t) {
                    return 0 === e[t];
                });
            var t = function (t, o) {
                    var a,
                        i,
                        r = o[0],
                        s = o[1],
                        c = o[2],
                        l = 0;
                    if (
                        r.some(function (t) {
                            return 0 !== e[t];
                        })
                    ) {
                        for (a in s) n.o(s, a) && (n.m[a] = s[a]);
                        if (c) var u = c(n);
                    }
                    for (t && t(o); l < r.length; l++)
                        (i = r[l]), n.o(e, i) && e[i] && e[i][0](), (e[i] = 0);
                    return n.O(u);
                },
                o = (self["webpackChunkunipass_wallet"] =
                    self["webpackChunkunipass_wallet"] || []);
            o.forEach(t.bind(null, 0)), (o.push = t.bind(null, o.push.bind(o)));
        })();
    var o = n.O(void 0, [4998], function () {
        return n(38054);
    });
    o = n.O(o);
})();
