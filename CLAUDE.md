# Lumen OAuth

`lumen-oauth` 是一个 Go Service 项目：用标准库 `net/http` 实现 OAuth 2.0 / OpenID Connect 授权服务器，为 Lumen 平台提供统一认证、动态客户端注册、刷新令牌轮换、RBAC、注册验证和邀请入驻能力。

## 当前目标

- 维护一个安全优先、单二进制部署的 OAuth/OIDC 授权服务。
- 核心协议能力包括 Authorization Code + PKCE、Client Credentials、Refresh Token Rotation、OIDC Discovery/JWKS、RFC 7591 DCR。
- 默认不引入 Web 框架、ORM、外部 JWT 库或新的依赖注入框架。

## 优先级

- 本文件是项目级最高优先约束。
- 用户当轮明确指令高于本文默认规则。
- Skill、通用 Go 建议或外部模板与本文冲突时，以本文为准。
- 不确定时先读取现有代码、README 和 `ARCHITECTURE_SCAFFOLD.md`，再按当前模式保守扩展。

## 决策状态

- 本文件基于当前仓库事实编写：`go.mod`、`README.md`、`ARCHITECTURE_SCAFFOLD.md`、`configs/config.example.yaml`、`cmd/` 和 `internal/`。
- 当前仓库没有 `Makefile`、`.golangci.yml`、`.claude/skills/` 或既有 `CLAUDE.md`。
- 未被代码或配置验证的选择列在“待确认事项”，不要把它们当成已实现约束。

## 项目类型

- 类型：Service / API。
- 入口：`cmd/lumen-oauth/main.go`，通过 `--config` 指定 YAML 配置，默认 `configs/config.example.yaml`。
- HTTP：标准库 `net/http`，路由和中间件在 `internal/interfaces/http`。
- 架构：六边形架构 / 分层架构，依赖方向为 `interfaces -> application -> domain` 和 `infrastructure -> application -> domain`。
- 日志：标准库 `log/slog`，封装在 `internal/platform/logging`，支持 JSON/TEXT。
- 存储：生产默认 PostgreSQL，开发/测试可用 SQLite；代码中的仓库适配器在 `internal/infrastructure/sqlite`，同时承载 SQLite 和 PostgreSQL 初始化与查询差异。

## 当前结构

```text
cmd/lumen-oauth/                 # 进程入口、flag、signal context
configs/                         # YAML 示例配置
internal/config/                 # 配置结构、默认值、校验、YAML loader
internal/domain/                 # 纯领域模型：user/client/grant/token/session/role 等
internal/application/            # 用例服务与 ports 接口
internal/bootstrap/              # 依赖组装、server 生命周期、repository 打开
internal/infrastructure/         # DB、JWT、JWKS、密码、邮件、redirect、clock、idgen 适配器
internal/interfaces/http/        # handlers、middleware、routes、HTTP contract tests
internal/platform/               # logging 和 observability primitives
```

## 架构规则

- `domain` 包只放领域模型和值对象，不依赖 HTTP、数据库、配置或平台包。
- `application` 包编排业务流程，依赖 `internal/application/ports` 中的小接口。
- `interfaces/http` 只处理协议层输入输出、cookie/header/status code、DTO 绑定和路由注册。
- `infrastructure` 实现外部适配器，包括 repository、JWT、password、redirect、email、clock、idgen。
- `bootstrap` 只做依赖装配、配置到实现的选择、server 生命周期；不要把业务分支塞进 bootstrap。
- 新能力优先放入已有边界；只有确认为跨 feature 的平台能力才放进 `internal/platform`。
- 新接口优先放在 `internal/application/ports`，并保持小而按调用方定义。

## OAuth 与安全规则

- PKCE 只支持 S256，不增加 `plain` 降级路径。
- 密码哈希使用 PBKDF2-SHA256；配置中 `auth.password_hash.algorithm` 当前只接受 `pbkdf2-sha256`。
- JWT 当前由 `internal/infrastructure/jwt` 手写 HS256 签名和验证；不要默认引入第三方 JWT 库。
- client secret、authorization code、refresh token、CSRF token 等敏感值按现有实现哈希存储或常量时间比较；不要记录明文 token、cookie、密码、验证码、signing key。
- DCR 支持 `open`、`guarded`、`iat_required`、`disabled`；新增逻辑必须保持 redirect URI 校验规则清晰可测。
- Refresh Token Rotation 相关改动必须覆盖正常轮换、重用检测和 grant 级撤销。

## 配置约定

- 配置入口是 YAML 文件，结构定义在 `internal/config/config.go`，加载逻辑在 `internal/config/load.go`。
- 默认监听地址为 `:9080`，默认 issuer 示例为 `http://127.0.0.1:9080`。
- 新配置项必须包含结构字段、默认值或明确校验、示例配置，以及相关测试。
- 不要绕过 `Config.Validate` 在业务代码里分散做基础配置校验。

## 日志与可观测性

- 使用 `internal/platform/logging.Logger`，不要默认引入 zap、zerolog 或第三方 slog 扩展。
- 日志字段使用结构化 key/value；错误字段使用 `"error"`。
- request-scoped 信息通过 context 和 middleware 传递，现有 logger 支持从 context 读取 `trace_id`。
- 不记录 secrets、tokens、cookies、完整请求体或密码哈希。
- Metrics scaffold 在 `internal/platform/observability` 和 HTTP middleware；`observability.metrics_path` 控制 expvar 指标端点，同时保留 `/debug/vars` 兼容端点。
- pprof 通过 `observability.pprof_enabled` 显式开启，默认关闭；只在受信任网络或受保护入口后暴露。

## 数据库/存储约定

- `storage.driver` 支持 `postgres` 和 `sqlite`。
- PostgreSQL 使用 `github.com/jackc/pgx/v5`；SQLite 使用 `modernc.org/sqlite`。
- 所有 DB 调用传递 `context.Context`，SQL 使用参数化查询。
- repository 可以使用独立 record/scan 逻辑，但返回 application/domain 需要的领域类型。
- PostgreSQL integration test 通过 `LUMEN_OAUTH_POSTGRES_URL` 启用；没有该环境变量时应跳过。
- 迁移策略当前未单独抽出工具；不要假设 goose/migrate/sqlc 已被采用。

## 测试与质量门

```bash
go test ./...
go test ./internal/application/...
go test ./internal/interfaces/http/...
go run ./cmd/lumen-oauth --config configs/config.example.yaml
```

- 没有 Makefile 时，不要把 `make check` 当作项目事实。
- 单元测试和 contract tests 当前使用标准库 `testing`，不要默认新增 testify 或 goleak。
- 涉及 HTTP 行为的改动优先补充 `internal/interfaces/http/routes` 或 middleware contract tests。
- 涉及存储的改动至少覆盖 SQLite 路径；PostgreSQL 行为差异用 `LUMEN_OAUTH_POSTGRES_URL` 集成测试覆盖。
- 安全敏感改动必须包含失败路径测试：无效 token、过期值、重复使用、错误 redirect、缺失 CSRF 或权限不足。

## Agent 执行规则

- 改代码前先读取受影响 package、`internal/application/ports` 和 `internal/bootstrap/app.go` 的 wiring。
- 保持依赖方向，不要让 domain 反向依赖 application、infrastructure、interfaces 或 platform。
- 优先复用现有 helper、constructor、logger、config loader 和测试风格。
- 新依赖必须有明确收益，并先检查标准库或现有依赖是否足够。
- 改完先跑最小相关测试，再按风险决定是否跑 `go test ./...`。
- 如果 README、架构文档、代码和本文冲突，最终行为以代码事实为准，并在结果里说明冲突。

## Skills 使用约定

- 项目上下文：创建或更新 `CLAUDE.md` 时使用 `golang-claude-md`。
- 架构/布局：新增 feature、调整目录或改 bootstrap 时使用 `golang-project-layout` + `golang-design-patterns`。
- 命名：新增 package、interface、constructor、错误名时使用 `golang-naming`。
- 测试：新增或调整测试时使用 `golang-testing`，但断言风格服从本项目标准库优先规则。
- 错误处理：改动错误流、错误包装、HTTP 错误映射时使用 `golang-error-handling`。
- 日志：本项目使用 `log/slog` 封装；日志相关任务使用 `golang-samber-slog` 只作为 slog 生态参考，不引入 samber 包，除非用户明确批准。
- 数据库：改动 repository、事务、SQL 或存储测试时使用 `golang-database` + `golang-context`。
- 并发/生命周期：改 server shutdown、goroutine、channel、context cancellation 时使用 `golang-concurrency` + `golang-context`。
- 可观测性：改 metrics、trace、pprof、alert 或日志关联时使用 `golang-observability`，日志实现仍服从本文件。
- 安全：处理认证、授权、输入校验、密钥、cookie、redirect、文件或网络时使用 `golang-security` + `golang-safety`。
- 性能：先用 `golang-troubleshooting` 定位，再用 `golang-performance` 优化。

## Skill 覆盖与禁用项

- `golang-log-zap` 不适用于当前仓库，除非项目明确迁移到 zap。
- 不要把 golang-skeleton 的 zap、Makefile、gotests、pgx-only 约束照搬到本仓库。
- 不要默认新增 Web 框架、ORM、DI 容器、JWT 库、断言库或迁移工具。
- Skill 示例中的 logger、DB driver、目录名、测试框架与本文冲突时，以本文为准。

## 改代码时的注意点

- OAuth/OIDC 行为改动要同步检查 README 中列出的端点、scope、TTL、DCR 和安全机制描述。
- 日志或 metrics 改动要保持低基数字段：route pattern、method、status_class 可以作为聚合维度，用户 ID、完整 URL、token、email 不可以。
- 修改 handler 时同步看 route contract tests；修改 middleware 时同步看 middleware tests。
- 修改 repository 时同步看 `repositories_test.go` 和 PostgreSQL integration test 的跳过条件。
- 修改配置时同步更新 `configs/config.example.yaml` 和 `internal/config/config_test.go`。
- 修改 bootstrap wiring 时确认资源关闭、server shutdown 和 registration/email 分支仍然可运行。

## 待确认事项

- 是否要补充 `Makefile`，把 `go test ./...`、lint、build、run 固化为统一质量门。
- 是否要引入 `.golangci.yml`；当前仓库没有 lint 配置。
- 是否继续保留 `ARCHITECTURE_SCAFFOLD.md` 中的 Phase 0 TODO，还是迁移为 issue/task 列表。
- 是否需要独立迁移工具；当前 repository 初始化逻辑内聚在 `internal/infrastructure/sqlite`。
