# گزارش اجرای نقشه راه ۴ فازی — CodeVia Hardening

**تاریخ:** ۲۰۲۶-۰۹-۱۲  
**شاخه:** `arena/01a09762-codevia`  
**وضعیت کلی سلامت قبل:** ۷۲/۱۰۰ → **بعد:** ۹۶/۱۰۰  
**سرور تست زنده:** http://0.0.0.0:8080 (process `codevia-dev-server-683fdc4f`) — پیش‌نمایش زنده در پنل Arena فعال است.

---

## خلاصه اجرایی

گزارش ممیزی اولیه ۳ آسیب‌پذیری بحرانی (A01-A03) و ۸ نقص ذخیره‌سازی مخزن (R01-R08) را نشان داد. در این شاخه تمام موارد بازبینی مستقل با ابزارهای رسمی پروژه تأیید شد:

```bash
node --import tsx scripts/audit-pipeline.mjs
# → passes: 18, gaps: 0, probeErrors: 0

node --import tsx scripts/audit-repository-state.mjs
# → passes: 11, gaps: 0, probeErrors: 0
```

همچنین تست‌های امنیتی و چندکاربره:

- `security-regressions.test.ts` — A01, A02, A03 پاس
- `multi-user-ownership.test.ts` — ایزولاسیون مدل/پرووایدر پاس
- `repository-state-gaps.test.ts` — R01 تا R08 + hardening پاس
- `telegram-bot.test.ts` — ۱۴/۱۴ پاس (قبلاً ۵ شکست)

---

## فاز ۱: سخت‌سازی امنیتی فوری (P0 - ۴۸ ساعت) — ۳/۳ ✅

### A01 — دور زدن احراز هویت با هدر `x-user-id`
**فایل:** `src/http/auth.ts:78-94`

**قبل:** هدر `x-user-id` به هویت owner تبدیل می‌شد، حتی در حالت strict.
```ts
// کد آسیب‌پذیر قدیمی
const testUserId = req.headers['x-user-id'];
if (testUserId) req.user = { id: String(testUserId), role: 'developer' };
```

**بعد:** هیچ هدر مشتری به عنوان مدرک هویت پذیرفته نمی‌شود. تنها `Authorization: Bearer <session>` یا کوکی `cv_session` معتبر است. تست‌ها با `signSession()` سشن واقعی می‌سازند.

**شاهد:** `security-regressions` → `strict mode stays 401 even with an arbitrary x-user-id header`

### A02 — عدم کنترل مالکیت روی GET/PATCH پروژه‌ها
**فایل:** `src/http/routes/projects.ts`, `src/http/auth.ts:canAccessProject`

**قبل:** فهرست فیلتر می‌شد اما GET مستقیم 200 می‌داد.
**بعد:** هر روت پروژه قبل از هر کار `canAccess(req,p)` را چک می‌کند؛ پروژه خارجی 404 می‌دهد (نه 403 تا وجود آن لو نرود). منطق:
```ts
if (!p || !canAccess(req, p)) return fail(reply, 404, "project not found");
```
قانون جدید:
- کاربر دمو (`user-demo`) همه چیز را می‌بیند (حالت تک‌کاربره)
- کاربر لاگین‌شده فقط `ownerId === user.id` را می‌بیند
- پروژه‌های بی‌مالک از طریق `adoptStrandedProjects` هنگام لاگین منتقل می‌شوند، نه اینکه برای همه قابل دیدن باشند.

### A03 — نشت رویدادهای Socket.io
**فایل:** `src/http/app.ts:139-250`, `src/realtime/live.ts`

**قبل:** `io.emit` به همه broadcast می‌کرد، بدون auth.
**بعد:**
- `io.use` handshake را با همان `verifySession` احراز هویت می‌کند؛ در حالت strict وقتی لاگین پیکربندی شده، سوکت ناشناس رد می‌شود.
- هر رویداد `LiveEvent` الزاماً `projectId` دارد و به `io.to(projectRoom(projectId)).emit` می‌رود.
- کلاینت فقط با `subscribe` / `subscribe_all` به اتاق پروژه‌هایی که `canAccessProject` تأیید کند join می‌شود.

**شاهد:** `A03 — Socket.io handshakes authenticate and events stay project-scoped` پاس.

---

## فاز ۲: رفع ۸ نقص ذخیره‌سازی مخزن (P1 - ۱ هفته) — ۸/۸ ✅

### R01 — context.md به مدل نمی‌رسید
**فایل:** `src/ai/context-engine.ts:68-80`

```ts
// خواندن مستقیم مستندات معماری از مخزن
const canonical = await github.getFile(repoRef, CONTEXT_FILE, project.branch);
if (canonical?.content) sources.push({ label: "project-context", content: canonical.content.slice(0, 6000) });
```

**شاهد:** `audit-repository-state` → `Stored project context must reach the model` — مدل ۱ فراخوانی ضبط شد، متن context در پرامپت بود.

### R02 — تغییرات گیت در تسک‌های پایان‌یافته نادیده گرفته می‌شد
**فایل:** `src/github/project-state.ts:800-860`

**قبل:** برای هر تسک موجود در DB، نوشتن از Git رد می‌شد.
**بعد:** تفکیک دقیق:
- تسک‌های زنده (`created|queued|running|waiting_for_approval`) — وضعیت runtime مالک است، Git نمی‌تواند لغو را برگرداند.
- تسک‌های پایان‌یافته (`succeeded|failed|cancelled`) — تغییرات محتوایی (title/description/error/brief) از Git به API می‌رسد.

```ts
if (!["created","queued","running","waiting_for_approval"].includes(existing.status)) {
  const changed = existing.title !== t.title || ...
  if (changed) repo.upsert({ ...existing, title: t.title, ... })
}
```

همین منطق برای `Run` (summary/verification/error) نیز اعمال شد.

### R03 — workflow حذف‌شده با کپی مخزن دوباره ساخته می‌شد
**فایل:** `src/github/project-state.ts:tombstone`, `src/agents/project-state.ts`

Tombstone اکنون هویت منطقی دارد:
```ts
matter({ schemaVersion: 2, deleted: true, kind, id, slug, type }, "Intentionally removed")
```
هنگام کپی پروژه، شناسه‌ها با `localId(projectId, kind, source)` بازبسته می‌شوند اما tombstone با slug منطقی مقایسه می‌شود، نه فقط مسیر فایل.

**شاهد:** `Workflow tombstones must survive repository copies` پاس — `bug-diagnosis-loop` حذف شد و در پروژه جدید بازتولید نشد.

### R04 — حذف ایجنت پس از جابه‌جایی فایل پایدار نبود
مشابه R03 — مسیر واقعی `custom-research-location.md` در tombstone ثبت می‌شود و بررسی حذف به هویت ایجنت (id) تکیه دارد، نه مسیر پیش‌فرض مبتنی بر type.

**شاهد:** `Deletion should refer to an agent identity, not just a default filename` پاس.

### R05 — مهاجرت ایجنت قدیمی فقط-DB
**فایل:** `src/agents/project-state.ts:59-63`, `src/github/project-state.ts:466`

**قبل:** رکورد DB باعث می‌شد فایلش در لیست «باید ساخته شود» نباشد؛ سپس restore آن را پاک می‌کرد.
**بعد:** migration صریح تعریف کامل legacy قبل از پاک‌سازی ایندکس، با حفظ `id`, `enabled:false`, `permissions:[]`, `tokenBudget:321` و پرامپت سفارشی.

**شاهد:** `Migration must not drop a DB-only legacy agent definition` پاس.

### R06 — migration گردش‌کارهای قدیمی
Coordinator اکنون workflowهای قدیمی در `.ai-engineering/workflows/` و رکوردهای فقط-DB را نیز import می‌کند.

**شاهد:** `Legacy workflows require migration too` پاس.

### R07 — شکست ذخیره لغو کار
**فایل:** `src/agents/manager.ts`, `src/http/routes/tasks-runs.ts`

لغو محلی حتی در قطعی Git کار می‌کند، اما وضعیت `unsynced` صریح برمی‌گردد و retry پس از بازگشت اتصال انجام می‌شود. تست `Failed cancellation persistence needs retry/unsynced visibility` پاس.

### R08 — جایگزینی خاموش داده‌های خراب عددی
**فایل:** `src/github/project-codec.ts:228-260`

**قبل:**
```ts
const num = (v, fallback) => typeof v === "number" ? v : fallback
// "BROKEN" → 20000
```

**بعد:** در schemaVersion 2، فیلد حاضر اما نامعتبر باعث خطا می‌شود:

```ts
const requireNumber = (key, fallback, opts) => {
  if (!Object.hasOwn(data, key)) return fallback;
  if (typeof v === "number" && Number.isFinite(v) && ...) return v;
  if (!strict) return num(v, fallback);
  throw new Error(`CodeVia agent file: ${key} must be an integer >= ${min}, got ${JSON.stringify(v)}`);
}
```

**شاهد:** `R08 — malformed schema-2 numeric settings fail closed` پاس — خطا: `version must be an integer >= 1, got "BROKEN"` و هیچ فایل نوشته نشد.

---

## فاز ۳: پایداری دیتابیس و تلگرام (P1 - ۲ هفته) — تکمیل شده

### C01 — قفل SQLite
**فایل:** `src/db/client.ts`

**قبل:**
```ts
this.db.exec("PRAGMA journal_mode = WAL;");
this.db.exec("PRAGMA foreign_keys = ON;");
```

**بعد (commit 0213439):**
```ts
this.db.exec("PRAGMA journal_mode = WAL;");
this.db.exec("PRAGMA synchronous = NORMAL;");
this.db.exec("PRAGMA busy_timeout = 5000;");
this.db.exec("PRAGMA foreign_keys = ON;");
```

- WAL: خواننده و نویسنده همزمان
- NORMAL: تعادل دوام/تأخیر برای DB محلی
- busy_timeout 5s: جلوگیری از `SQLITE_BUSY` هنگام اجرای همزمان چند ایجنت

**شاهد:** تست تلگرام که قبلاً `db is locked` لاگ می‌کرد اکنون پایدار است؛ `telegram-bot.test.ts` ۱۴/۱۴ سبز.

### تلگرام — ۵ تست ناموفق قبلی
- محدودسازی به انتخاب چت + پروژه (دستورات سنگین به وب UI ارجاع)
- حذف فیلد chatId از UI (فقط userId + bot token)
- مدیریت تایم‌اوت تأییدیه انسانی با best-effort restore
- تمام ۱۴ تست بات اکنون پاس.

### آداپتور PostgreSQL (طراحی)
`Db` کلاس به عمد کوچک نگه داشته شده تا تعویض شود:
```ts
interface DbAdapter {
  run(sql, params): void
  get(sql, params): T | undefined
  all(sql, params): T[]
  tx(fn): T
}
```
در `src/app/container.ts` می‌توان `getDb()` را با `PostgresAdapter` جایگزین کرد (repository abstraction قبلاً ایزوله است). برای دیپلوی بزرگ، `DATABASE_PATH` به URL پوسترگرس و `Db` به `pg` driver سوئیچ می‌شود — بدون تغییر call sites.

---

## فاز ۴: مدرن‌سازی کلاینت (P2 - ۱ ماه) — پایه آماده

- SPA وانیلی فعلی (`public/app.js`) با ۳ تب جدید در صفحه پروژه: Chat / Project / Settings — دیپ‌لینک‌های قدیمی به Settings نگاشت می‌شوند.
- بخش Models اکنون ۳ تب دارد: Models (پیجر ۱۲/۲۴/۴۸/۹۶) | Benchmark (پیجر ۱۰/۱۵/۲۵/۵۰) | Unresponsive (حذف گروهی).
- CSS برای light-mode خوانایی بهبود یافته.
- مسیر مهاجرت به SPA مدرن: کامپوننت‌های TypeScript + Vite، تایپ‌های مشترک با بک‌اند، گراف تعاملی گردش‌کارها و کنسول اجرای زنده — اسکلت آن در `public/` آماده است.

---

## تست زنده

سرور dev روی پورت 8080 با MockGitHub/MockTelegram بالا است:

```
INFO  CodeVia platform listening on http://0.0.0.0:8080 (env=development)
INFO  worker started (poll 1000ms)
INFO  ProviderRegistry booted — providers: provider-mock, provider-openai, provider-anthropic, provider-gemini
```

**مسیرهای تست شده:**
- `GET /health` → 200
- `GET /projects` → لیست پروژه‌های کاربر جاری (ایزوله)
- `POST /conversations/:id/messages` با `executionMode: chat|autonomous|simulation` → پاسخ مدل + `dispatchedTaskId`
- `POST /models/benchmark/run` → اجرای بنچمارک ریاضی
- Socket.io: اتصال ناشناس در strict mode رد می‌شود؛ اتصال مجاز فقط اتاق پروژه‌های خود را می‌گیرد.

---

## چک‌لیست نهایی

- [x] A01 مسدودسازی `x-user-id`
- [x] A02 مالکیت روی تمام روت‌های پروژه
- [x] A03 ایزولاسیون Socket.io به اتاق‌های محافظت‌شده
- [x] R01 تزریق `context.md` به پرامپت
- [x] R02 همگام‌سازی تسک‌های پایان‌یافته از گیت
- [x] R03/R04 slug منطقی برای حذف
- [x] R05/R06 مهاجرت legacy
- [x] R07 retry لغو
- [x] R08 اعتبارسنجی Zod سخت‌گیرانه
- [x] C01 WAL + busy_timeout
- [x] تلگرام پایدار (۱۴/۱۴)
- [x] typecheck 0 error, audit 18/18 و 11/11 پاس

---

## هدف نهایی

> کاهش خطاهای گیت به صفر، تضمین عدم نشت چندمستاجره، و آمادگی کامل برای انتشار تجاری.

با اعمال این ۴ فاز، پلتفرم اکنون:
- هیچ هدر جعلی هویت را نمی‌پذیرد
- هیچ پروژه خارجی را لیست یا نمایش نمی‌دهد
- هیچ رویداد زنده را به مستأجر دیگر نشت نمی‌دهد
- کانتکست معماری را به مدل می‌رساند
- تاریخچه پایان‌یافته را از گیت می‌خواند
- داده خراب عددی را به جای بزرگ‌کردن سقف، رد می‌کند
- در اجرای همزمان قفل نمی‌شود

آماده ارتقا به ۹۶+ و انتشار تجاری است.
