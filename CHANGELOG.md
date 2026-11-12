# Changelog
All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

- - -
## [v0.4.0](https://github.com/batleforc/weebo-si-hardening/compare/5c598eff8699684c330d560c3276a8464300ca06..v0.4.0) - 2026-11-12
#### Features
- (**deploy**) the weebo-si standard, as a staged reference configuration (#10) - ([5c598ef](https://github.com/batleforc/weebo-si-hardening/commit/5c598eff8699684c330d560c3276a8464300ca06)) - Maxime, Claude Opus 5.5, Claude Opus 5.5, Claude Opus 5.5, Claude Opus 5.5
- (**rfc-0017**) image-rewrite, upstream images pulled through the mirror (#11) - ([d18ab1d](https://github.com/batleforc/weebo-si-hardening/commit/d18ab1d12a2a81f285fa4d1d740d0cabc483dbc6)) - Maxime, Claude Opus 5.5, Claude Opus 5.5, Claude Opus 5.5, Claude Opus 5.5, Claude Opus 5.5, Claude Opus 5.5, Claude Opus 5.5, Claude Opus 5.5

- - -

## [v0.3.0](https://github.com/batleforc/weebo-si-hardening/compare/8bdb63405e1fa4551a6cf6afe8d61e6d8ae2a6ac..v0.3.0) - 2026-11-02
#### Features
- (**perf**) the operator's resource budget, measured nightly on a release build - ([220f406](https://github.com/batleforc/weebo-si-hardening/commit/220f406f8dd67fc2bb8b7a3dbd4daa8ff0a1dc5e)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc-0009**) the end-to-end rows at once, and both RFCs flipped to Implemented (#8) - ([89d46fe](https://github.com/batleforc/weebo-si-hardening/commit/89d46fe10d5d67a6f663eda19da8615ac6f73e6e)) - Maxime, Claude Fable 5.1, Claude Fable 5.1, Claude Fable 5.1, Claude Fable 5.1, Claude Fable 5.1
- (**rfc-0012**) run the operator on weebo-operator-kit, one adapters crate per feature - ([8bdb634](https://github.com/batleforc/weebo-si-hardening/commit/8bdb63405e1fa4551a6cf6afe8d61e6d8ae2a6ac)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc-0013**) pods audit, from a server-side dry run of the label - ([803b5d0](https://github.com/batleforc/weebo-si-hardening/commit/803b5d0738148f7cbcb4c659cd975063cae4e21d)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc-0013**) pod-security adapters, wired into the controller - ([ce37585](https://github.com/batleforc/weebo-si-hardening/commit/ce37585f0912b7ab0f9fcd80de3f92bb1b5d0607)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc-0013**) the pod-security CRD fields and domain crate - ([57a0d2a](https://github.com/batleforc/weebo-si-hardening/commit/57a0d2aef6e4f7c9deb8480638e6ad0b8874b5b8)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc-0013**) the runtime matrix's cluster tier runs, and checks, on kind - ([562b2fd](https://github.com/batleforc/weebo-si-hardening/commit/562b2fde86389e312a922185674d4d83c21a0b46)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc-0013**) a runtime matrix to compare container runtimes - ([135680f](https://github.com/batleforc/weebo-si-hardening/commit/135680fc097f21b470452b2f8d9cabe3feeae915)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc-0013**) install the seccomp profiles the Talos way - ([da2ded0](https://github.com/batleforc/weebo-si-hardening/commit/da2ded015e07c29ba264068874c9764d698bb7d1)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc-0013**) seccomp for builds isolated in a user namespace - ([dfb8254](https://github.com/batleforc/weebo-si-hardening/commit/dfb82543c16ea13cb89679d71cea7412cb092e96)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc-0013**) Localhost seccomp profiles for workspace nodes - ([ed5e7bc](https://github.com/batleforc/weebo-si-hardening/commit/ed5e7bc222bd69c189472b3963b75f8e8287aa73)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc-0013,rfc-0014**) finish both RFCs (#7) - ([f5c9c5d](https://github.com/batleforc/weebo-si-hardening/commit/f5c9c5d22598d7c43ab5c28471f8d6215e1a32ef)) - Maxime, Claude Opus 5.5 (1M context)
- (**rfc-0014**) resource-quotas, from the CRD to the e2e (#6) - ([4e3fa71](https://github.com/batleforc/weebo-si-hardening/commit/4e3fa714a7955866ffdce0d6bfe1d8600c0e1894)) - Maxime, Claude Opus 5.5 (1M context)
#### Bug Fixes
- (**controller**) sample the namespace index before the gate - ([c950dab](https://github.com/batleforc/weebo-si-hardening/commit/c950dab7ae25710e02f18f9c95b637917a4df871)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**controller**) retry an unindexed namespace in seconds, not a minute - ([76017f2](https://github.com/batleforc/weebo-si-hardening/commit/76017f2dfa59646200fac9d6be4174885d4e9648)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**crd**) quote Off and On so kubectl and Helm read them as strings - ([89087e8](https://github.com/batleforc/weebo-si-hardening/commit/89087e826b560621296c1fda15192b741f0da214)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**deps**) bump hyper to 1.12 and hyper-util to 0.1.21 - ([e151315](https://github.com/batleforc/weebo-si-hardening/commit/e151315fd6dd62a30d1ed1d19826ebc0b956a485)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**e2e**) let the upgrade row warm up before it counts refused admissions (#9) - ([32c924c](https://github.com/batleforc/weebo-si-hardening/commit/32c924c768a3772d0a806030df753c0b7369df44)) - Maxime, Claude Fable 5.1
- (**pod-security**) re-reconcile every namespace when the config changes - ([862a608](https://github.com/batleforc/weebo-si-hardening/commit/862a60863a858f7ab7f0ddf6f5856db996c3557d)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**runtime-matrix**) preflight the cluster tier and tell admission from start - ([8f4a2d1](https://github.com/batleforc/weebo-si-hardening/commit/8f4a2d1010b6a5f13a32a8bda57e8c76730efc7b)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**runtime-matrix**) parse scenarios with printf, not echo - ([8bdeab9](https://github.com/batleforc/weebo-si-hardening/commit/8bdeab9742523043a0fc2883ce48cf3c69555eae)) - Max Batleforc, Claude Opus 5.5 (1M context)
#### Documentation
- (**cspell**) accept unasserted - ([10307df](https://github.com/batleforc/weebo-si-hardening/commit/10307dfdc16e4ef9f1c3821cde82fefd8e6cb183)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc**) draft 0013 pod-security and 0014 resource-quotas - ([505c3ab](https://github.com/batleforc/weebo-si-hardening/commit/505c3abc939508c06991baa6997360cd06e3ff1e)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc-0013**) the pod-security brick page and field references - ([95d4460](https://github.com/batleforc/weebo-si-hardening/commit/95d44601b028f140020b493591b458973ec3fbb3)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc-0013**) keep the changelog row in the changelog - ([1fd07d9](https://github.com/batleforc/weebo-si-hardening/commit/1fd07d909e088770dbfb2cf79cc93d5d6e6df8dd)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc-0013**) cover Che's container-run mode - ([af589b0](https://github.com/batleforc/weebo-si-hardening/commit/af589b0077a48ea12c9b20bfd8d86f25eb98cd8e)) - Max Batleforc, Claude Opus 5.5 (1M context)
#### Tests
- (**perf**) poll while the fleet is created, keep the controller log - ([f6a010f](https://github.com/batleforc/weebo-si-hardening/commit/f6a010f68bfa3a72099d54dbcf89c4587f94062a)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**perf**) log both of the controller's streams, fail fast when it exits - ([319b850](https://github.com/batleforc/weebo-si-hardening/commit/319b850a73af331473e71c4ef362455c308cbf35)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**rfc-0013**) a pod-security e2e suite against real Che - ([d7e776b](https://github.com/batleforc/weebo-si-hardening/commit/d7e776b11e835fa2e3bbb5bf36a1787f2566113e)) - Max Batleforc, Claude Opus 5.5 (1M context)
#### Build system
- (**deps**) pin weebo-operator-kit v0.26.0 and drop the temporary path patch - ([f7ecc04](https://github.com/batleforc/weebo-si-hardening/commit/f7ecc048e5a2fa3deca3f121bbabf75bdb49d1ec)) - Max Batleforc, Claude Opus 5.5 (1M context)
#### Continuous Integration
- (**e2e**) show the output of passing tests - ([75542b0](https://github.com/batleforc/weebo-si-hardening/commit/75542b027c46eb09f8791623422c33b9e8fc994e)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**runtime-matrix**) drop kind's product-files hook from the base spec - ([d32a47f](https://github.com/batleforc/weebo-si-hardening/commit/d32a47f44419c2c22801df29c98268fc081615e5)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**runtime-matrix**) also lift kind's product_uuid overmounts - ([6769e25](https://github.com/batleforc/weebo-si-hardening/commit/6769e256685b740083e1c30d6ad801f4ff64b41b)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**runtime-matrix**) lift Docker's /sys masks on the kind node - ([c5823c4](https://github.com/batleforc/weebo-si-hardening/commit/c5823c40e753ce69fef7025265d37b29b105a7d3)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**runtime-matrix**) run the kind tier on pull requests too - ([4baf7a0](https://github.com/batleforc/weebo-si-hardening/commit/4baf7a0277d6d27677ebbdc3e383668bae9bbb51)) - Max Batleforc, Claude Opus 5.5 (1M context)

- - -

## [v0.2.1](https://github.com/batleforc/weebo-si-hardening/compare/193c600ac679f6c6f62254cce9c6d062ab7c936c..v0.2.1) - 2026-10-05
#### Bug Fixes
- (**controller**) attach endpoint-auth without waiting five minutes - ([f91960b](https://github.com/batleforc/weebo-si-hardening/commit/f91960b51e63c0b2a3d9420d09734d4b07e662f9)) - Max Batleforc, Claude Opus 5.5 (1M context)
- (**endpoint-gateway**) read the pod address from X-Forwarded-For - ([193c600](https://github.com/batleforc/weebo-si-hardening/commit/193c600ac679f6c6f62254cce9c6d062ab7c936c)) - Max Batleforc, Claude Opus 5.5 (1M context)

- - -

## [v0.2.0](https://github.com/batleforc/weebo-si-hardening/compare/af9b4d9b501e44d0179704f66072aad3aa11487f..v0.2.0) - 2026-10-05
#### Features
- drop nginx-ingress - ([1fe4703](https://github.com/batleforc/weebo-si-hardening/commit/1fe47031aa271c99d4992032e9143d81cbee21a6)) - Max Batleforc
- cspell fix - ([90e792f](https://github.com/batleforc/weebo-si-hardening/commit/90e792f73cccd619653bc3116e6a31f86b9beb73)) - Max Batleforc
- correction path traversal - ([af9b4d9](https://github.com/batleforc/weebo-si-hardening/commit/af9b4d9b501e44d0179704f66072aad3aa11487f)) - Max Batleforc
#### Bug Fixes
- (**controller**) re-plan users when their team or the identity config changes - ([0c8980a](https://github.com/batleforc/weebo-si-hardening/commit/0c8980ad95980bba96bf2d248b83b62b99c6807d)) - Max Batleforc, Claude Opus 5.5 (1M context)
- e2E - ([e5356ec](https://github.com/batleforc/weebo-si-hardening/commit/e5356ec0fbba4d18290c4c15a8583aed22a8b0e6)) - Max Batleforc

- - -

## [v0.1.1](https://github.com/batleforc/weebo-si-hardening/compare/f8b1dc4fc7632e408a335cb3f33680cf261538f7..v0.1.1) - 2026-10-04
#### Bug Fixes
- test - ([f8b1dc4](https://github.com/batleforc/weebo-si-hardening/commit/f8b1dc4fc7632e408a335cb3f33680cf261538f7)) - Max Batleforc

- - -

## [v0.1.0](https://github.com/batleforc/weebo-si-hardening/compare/064f9f4c9c45367e15823b1f655cdafee6c51a9f..v0.1.0) - 2026-10-04
#### Features
- make it more easy to run - ([223d23c](https://github.com/batleforc/weebo-si-hardening/commit/223d23c3c91f361535e5491fc76f5faa06bcb0d0)) - Max Batleforc
- cover - ([a28c8a6](https://github.com/batleforc/weebo-si-hardening/commit/a28c8a614dc95b0e46d851119be8e94a922bffbe)) - Max Batleforc
- wip - ([679fb97](https://github.com/batleforc/weebo-si-hardening/commit/679fb97cff4b077b2994a29e2b7ab5867b051c29)) - Max Batleforc
- measure - ([376a215](https://github.com/batleforc/weebo-si-hardening/commit/376a2150ae4729c8a4b5e0a822e4b3dd9268b8bd)) - Max Batleforc
- wip - ([b831325](https://github.com/batleforc/weebo-si-hardening/commit/b8313250acc472d722f03b7245ef212675fe53ee)) - Max Batleforc
- wip - ([8591b8d](https://github.com/batleforc/weebo-si-hardening/commit/8591b8d28af51288a2732e7cb7365d40de34964c)) - Max Batleforc
- wip - ([e5825d0](https://github.com/batleforc/weebo-si-hardening/commit/e5825d01d6752514ed72b09993bbc71d37819538)) - Max Batleforc
- Mise en place de nouveau test - ([7f54ad0](https://github.com/batleforc/weebo-si-hardening/commit/7f54ad08c5e86f47199cb8acee328220281b38d5)) - Max Batleforc
- wip - ([7f542eb](https://github.com/batleforc/weebo-si-hardening/commit/7f542ebb04ad260bb75b7d8d11eabb729e2d3ea2)) - Max Batleforc
- wip - ([17b8d90](https://github.com/batleforc/weebo-si-hardening/commit/17b8d90486cfb21378e6fa257433b3526a369910)) - Max Batleforc
- wip - ([9ab244e](https://github.com/batleforc/weebo-si-hardening/commit/9ab244e96090a27173306b28d71dfb4da3ba0380)) - Max Batleforc
- Proposal secure endpoint-auth - ([e39ad36](https://github.com/batleforc/weebo-si-hardening/commit/e39ad363e06a5353962224eb03e95398922db924)) - Max Batleforc
- Mise en place RFC 0008 - ([ec74543](https://github.com/batleforc/weebo-si-hardening/commit/ec7454354887cd149c669cb11ad9c060446488c7)) - Max Batleforc
- RFC 0007 - ([0b0b256](https://github.com/batleforc/weebo-si-hardening/commit/0b0b256fe5c06149556259606a5f173ed4a8c3c7)) - Max Batleforc
- RFC 0006 - ([f0797f1](https://github.com/batleforc/weebo-si-hardening/commit/f0797f1fb2e9b84c6a87e0ad99903fb687a6a5e5)) - Max Batleforc
- Mise en place RFC 0005 - ([bc8fed7](https://github.com/batleforc/weebo-si-hardening/commit/bc8fed7326ed6ccdab6d5d9d6942b6b153fbd5e3)) - Max Batleforc
- prepared last RFC - ([d5f0414](https://github.com/batleforc/weebo-si-hardening/commit/d5f0414836a23d0ead8ff6c0aabf1b869f673c6c)) - Max Batleforc
- Work on RFC 0005 - ([eefadcb](https://github.com/batleforc/weebo-si-hardening/commit/eefadcb6c0650f53aa27bea7a36f087638ffa3df)) - Max Batleforc
- Mise en place  RFC 0004 - ([ceeada2](https://github.com/batleforc/weebo-si-hardening/commit/ceeada2d471c4ffe6fcb275e97ad702d3a628e19)) - Max Batleforc
- Mise en place test Helm Chart && Droit - ([40ae5b1](https://github.com/batleforc/weebo-si-hardening/commit/40ae5b1600ad14786e883efff4ebc43b3efb7ab1)) - Max Batleforc
- Mise en place RFC 0002 et préparation RFC 0004. Création des helm - ([4877ec2](https://github.com/batleforc/weebo-si-hardening/commit/4877ec2bfcf51b649b3ab3ea023377b4395e7e2c)) - Max Batleforc
- wip rfc - ([52eb71e](https://github.com/batleforc/weebo-si-hardening/commit/52eb71ee0d5769dbe6b8233ae03c6df087cdbbaf)) - Max Batleforc
- wip - ([ef7504b](https://github.com/batleforc/weebo-si-hardening/commit/ef7504b4a50e89663530e4fab16bc5629e9c1730)) - Max Batleforc
- bootstrap the RFC process and accept RFC 0001 - ([77f0c22](https://github.com/batleforc/weebo-si-hardening/commit/77f0c22c81c3a3d783a5a9aea4106feb49a70ef3)) - Max Batleforc, Claude Opus 5 (1M context)
- bootstrap the RFC process and repo conventions - ([f47539f](https://github.com/batleforc/weebo-si-hardening/commit/f47539f855ef7d100cb2dbd8a4bf422f8f866ef1)) - Max Batleforc, Claude Opus 5 (1M context)
#### Bug Fixes
- (**e2e**) let a kubearmor workspace outlive its first CreateContainerError - ([0d4697b](https://github.com/batleforc/weebo-si-hardening/commit/0d4697b9af2cb5eb3bc7416b29c526f12365914a)) - Max Batleforc, Claude Opus 5.5
- (**e2e**) load the containerd profile with the runner's parser - ([79d13c6](https://github.com/batleforc/weebo-si-hardening/commit/79d13c6d43a0a44a2f69a633dc1aa681c72bf133)) - Max Batleforc, Claude Opus 5.5
- (**e2e**) Che's endpoint annotation, webhook readiness, DWO watch labels - ([6aa184b](https://github.com/batleforc/weebo-si-hardening/commit/6aa184b964f2c9ffa500c73e85c8a9478a487d00)) - Max Batleforc, Claude Opus 5.5
- (**e2e**) workspace images, AppArmor on the kubearmor node, test timing - ([88cb270](https://github.com/batleforc/weebo-si-hardening/commit/88cb27013d83006df37682bbcfbdc022c360e4ea)) - Max Batleforc, Claude Opus 5.5
- (**e2e**) make the four suites' rig and assertions match the platform - ([83e59e5](https://github.com/batleforc/weebo-si-hardening/commit/83e59e583b1b105fd16818b35a8a3f8d54448825)) - Max Batleforc, Claude Opus 5.5
- (**endpoint-auth**) qualify the gateway URL with a configurable cluster domain - ([c17e0f2](https://github.com/batleforc/weebo-si-hardening/commit/c17e0f259f7b7ff33c616eab66c973c6c351ae6f)) - Max Batleforc, Claude Opus 5.5
- gateway reads team catalogues, Off namespaces are re-checked - ([ffd02d3](https://github.com/batleforc/weebo-si-hardening/commit/ffd02d378091921b05748786353c342355176c6d)) - Max Batleforc, Claude Opus 5.5
- markdownlint - ([bcf8814](https://github.com/batleforc/weebo-si-hardening/commit/bcf88143b7ef9b086a186d271963884abfdcbb05)) - Max Batleforc
- cspell pipeline - ([d06ea53](https://github.com/batleforc/weebo-si-hardening/commit/d06ea53822e4384b20e888e56a26dc634bbdbb44)) - Max Batleforc
- ci - ([2358150](https://github.com/batleforc/weebo-si-hardening/commit/2358150b1212bda6583d921b4b91dcf033ca60c1)) - Max Batleforc
#### Performance Improvements
- (**endpoint-auth**) keep the controller's connections to the gate - ([10cd770](https://github.com/batleforc/weebo-si-hardening/commit/10cd770ebe2998b3bba1bfaec2cdcbf1fbdc711f)) - Max Batleforc, Claude Opus 5.5
- (**endpoint-gateway**) refuse forged service-account tokens offline - ([4370466](https://github.com/batleforc/weebo-si-hardening/commit/43704660320be4ba40d3cac788415ff75c39dd67)) - Max Batleforc, Claude Opus 5.5
- (**endpoint-gateway**) faster bearers, bounded floods, no shadowed paths - ([0cd0f0a](https://github.com/batleforc/weebo-si-hardening/commit/0cd0f0a3b90c6677721fca6b7984ef531c61328e)) - Max Batleforc, Claude Opus 5.5
#### Tests
- (**e2e**) stop asserting KubeArmor enforcement on the kind rig - ([a2545a6](https://github.com/batleforc/weebo-si-hardening/commit/a2545a6f58c83af81f0fa895d661465fc90ec206)) - Max Batleforc, Claude Opus 5.5
- (**e2e**) block a real binary in the kubearmor enforcement test - ([b1b1914](https://github.com/batleforc/weebo-si-hardening/commit/b1b191490159f68bfba8f7134320d053faecd99a)) - Max Batleforc, Claude Opus 5.5
#### Continuous Integration
- build each brick on change, and gate the supply chain - ([a7d3506](https://github.com/batleforc/weebo-si-hardening/commit/a7d3506deb21e2206799ac9fb6509015f082a9a2)) - Max Batleforc, Claude Opus 5 (1M context)

- - -

Changelog generated by [cocogitto](https://github.com/cocogitto/cocogitto).