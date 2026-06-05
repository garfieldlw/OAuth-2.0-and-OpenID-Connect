# shadcn/ui + Tailwind CSS 前端全量重写设计

**日期**: 2026-06-05
**状态**: 已批准
**方案**: B — 全量重写

## 目标

使用 shadcn/ui (New York 风格) + Tailwind CSS v4 全量重写 OAuth2 Server 的 React 前端，替换当前 CSS Modules + 手写组件方案。

## 约束

- 保持相同的 OAuth 登录 + 授权流程功能
- 保持现有的 API 代理配置（Vite proxy）
- TypeScript strict: 无 `any`、无 `@ts-ignore`
- `verbatimModuleSyntax: true`、`noUnusedLocals: true`、`noUnusedParameters: true`
- ESLint `recommendedTypeChecked` + `stylisticTypeChecked` 必须通过
- 构建验证: `tsc -b`、`eslint .`、`vite build` 三项全部通过
- 不加 `lucide-react` 图标库（3 个页面无需图标）
- 不加主题切换（`next-themes`）
- 不加新路由或新页面

## 技术栈

| 层 | 之前 | 之后 |
|---|---|---|
| 样式 | CSS Modules (5 files) | Tailwind CSS v4 + shadcn/ui CSS 变量 |
| UI 组件 | 手写 PageCard/ErrorMessage/ErrorDisplay | shadcn/ui Card/Input/Label/Button/Alert |
| 工具函数 | 手写 className 拼接 | `cn()` (clsx + tailwind-merge) |
| API 层 | `src/api.ts` | `src/lib/api.ts`（逻辑不变，路径调整） |
| Hooks | `src/hooks/useDocumentTitle.ts` | `src/lib/use-document-title.ts`（逻辑不变） |

## 目录结构

```
web/
├── src/
│   ├── app/
│   │   └── App.tsx              # Routes + layout (skip-link + main landmark)
│   ├── pages/
│   │   ├── login-page.tsx       # 登录页
│   │   ├── auth-page.tsx        # 授权同意页
│   │   └── error-page.tsx       # 错误页
│   ├── lib/
│   │   ├── api.ts               # Typed API 层（保留逻辑）
│   │   ├── utils.ts             # cn() helper
│   │   └── use-document-title.ts # Document title hook
│   ├── components/
│   │   └── ui/                  # shadcn/ui 生成组件
│   │       ├── button.tsx
│   │       ├── card.tsx
│   │       ├── input.tsx
│   │       ├── label.tsx
│   │       └── alert.tsx
│   ├── index.css                # Tailwind v4 入口
│   └── main.tsx                 # React root
├── components.json              # shadcn/ui 配置
├── tsconfig.json
├── tsconfig.app.json
├── tsconfig.node.json
├── vite.config.ts
├── eslint.config.js
└── index.html
```

## 页面设计

### Login 页面

- 外层: `flex items-center justify-center min-h-screen bg-background`
- `Card` 组件，`className="w-full max-w-sm"`
- `CardHeader` > `CardTitle` "Sign In"
- `CardContent` 表单:
  - `Label` htmlFor="username" + `Input` id="username"
  - `Label` htmlFor="password" + `Input` id="password" type="password"
  - 错误时: `Alert variant="destructive"` 显示错误信息（替代自定义 ErrorMessage）
  - 输入框在错误状态下 `aria-invalid="true"` `aria-describedby` 指向 alert
- `Button` type="submit" className="w-full"，loading 时 disabled + 文字 "Signing in…"
- `CardFooter` className="justify-center" 显示 demo hint 灰色小字

### Auth Consent 页面

- 外层: 同上居中布局
- `Card` 组件，`className="w-full max-w-md"`
- `CardHeader` > `CardTitle` "Authorization Request"
- `CardContent`:
  - 客户端上下文区: `Alert` (default variant) 显示 Client ID / Scope
  - 提示文案: "An application is requesting access to your account."
  - 错误时: `Alert variant="destructive"`
- `CardFooter` className="flex gap-4":
  - `Button` "Allow" (default variant)
  - `Button` "Deny" (destructive variant)

### Error 页面

- 外层: 同上居中布局
- `Card` 组件，`className="w-full max-w-md"`
- `CardHeader` > `CardTitle` "Error"
- `CardContent`:
  - `Alert variant="destructive"` 显示错误信息
  - `Button` variant="outline" "Back to Login"（Link to="/login"）

## 删除的文件

- `src/components/PageCard.tsx`
- `src/components/PageCard.module.css`
- `src/components/ErrorMessage.tsx`
- `src/components/ErrorMessage.module.css`
- `src/components/ErrorDisplay.tsx`
- `src/pages/LoginPage.tsx`
- `src/pages/LoginPage.module.css`
- `src/pages/AuthPage.tsx`
- `src/pages/AuthPage.module.css`
- `src/pages/ErrorPage.tsx`
- `src/pages/ErrorPage.module.css`
- `src/css-modules.d.ts`
- `src/hooks/` (空目录，文件已移至 `lib/`)

## 保留的文件（逻辑不变）

- `src/api.ts` → 移至 `src/lib/api.ts`，所有函数签名和类型不变:
  - `isSafeRedirect()`, `safeRedirect()`, `ApiRequestError`, `apiFetch<T>()`
  - `loginApi()`, `getAuthContext()`, `postAuthDecision()`
  - `LoginResponse`, `AuthContextResponse`, `AuthDecisionResponse`
- `src/hooks/useDocumentTitle.ts` → 移至 `src/lib/use-document-title.ts`
- `src/main.tsx` — 不变
- `src/App.tsx` → 重写路由和布局，保留 skip-link + main landmark + 路由逻辑
- `vite.config.ts` — proxy 配置不变，增加 `@tailwindcss/vite` 插件
- `index.html` — 不变
- `eslint.config.js` — 确认 `files: ['**/*.{ts,tsx}']` glob 仍匹配新目录结构（`app/`、`pages/`、`lib/`、`components/ui/`），无需改动

## 新增依赖

- `tailwindcss` v4
- `@tailwindcss/vite` — Vite 插件
- `class-variance-authority` — shadcn/ui 组件变体
- `clsx` — 条件类名
- `tailwind-merge` — Tailwind 类名合并

## 不新增的

- `lucide-react` — 3 个页面无需图标
- `next-themes` — 不做主题切换
- 任何新的路由或页面

## 安装步骤（概要）

1. 安装 Tailwind CSS v4: `npm install tailwindcss @tailwindcss/vite`
2. 配置 `vite.config.ts` 增加 Tailwind 插件
3. 初始化 shadcn/ui: `npx shadcn@latest init` (New York 风格, CSS variables, src/ 路径)
4. 添加组件: `npx shadcn@latest add card input label button alert`
5. 生成 `components/ui/` 下的组件源码和 `lib/utils.ts`

## 验证标准

- [ ] `npx tsc -b` 通过
- [ ] `npx eslint .` 通过
- [ ] `npx vite build` 通过
- [ ] 无 `.module.css` 文件残留
- [ ] 无 `styles.xxx` 引用残留
- [ ] 所有 a11y 属性保留（`aria-invalid`, `aria-describedby`, `role="alert"`, skip-link）
- [ ] `safeRedirect()` 使用不变
- [ ] API 代理配置不变
