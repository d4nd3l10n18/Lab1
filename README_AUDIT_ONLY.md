# SecureLab LR06 — Audit Integrity ONLY

Це Git-патч **виключно** для погодженого індивідуального завдання «Захищений Audit Trail із перевіркою цілісності».

## Вимоги / вихідний стан

- Зміни search limiter, CSP, CSRF та клієнтського JavaScript НЕ входять до патча.
- Патч змінює 8 файлів: `Program.cs`, `Lab03Identity.cs`, `IncidentEndpoints.cs`, `SecureLabDbContext.cs`, model snapshot; додає `AuditIntegrity.cs`, `AuditIntegrityEvent.cs`, EF migration.
- Для поточної гілки, якщо файли вже вручну змінені, ОБОВ'ЯЗКОВО виконайте `git apply --check`. Не застосовуйте патч до старого змішаного Audit+CSRF патча.

## 1. Безпечне застосування

```bash
cd /шлях/до/SecureLab
# Переконайтеся, що працюєте у гілці ЛР 6 і відсутні незбережені зміни:
git status --short
git branch --show-current
# Якщо є незакомічені зміни, спершу збережіть їх в окремий коміт або backup.
git apply --check /шлях/до/SecureLab_LR06_Audit_only.patch
git apply /шлях/до/SecureLab_LR06_Audit_only.patch
git diff --check
dotnet build SecureLab.sln
```

## 2. Секрет і anchor (в одному shell для run/CLI)

**Не генеруйте новий ключ при кожному запуску.** Для одного журналу ключ має бути сталим. Нижче — одноразове створення локального секрету в home користувача, поза Git.

```bash
mkdir -p "$HOME/.config/securelab" "$HOME/.local/share/securelab-audit"
chmod 700 "$HOME/.config/securelab" "$HOME/.local/share/securelab-audit"
# ТІЛЬКИ при першому налаштуванні (не перезаписуйте вже існуючий ключ):
( umask 077; test -e "$HOME/.config/securelab/hmac-key.b64" || openssl rand -base64 32 > "$HOME/.config/securelab/hmac-key.b64" )
chmod 600 "$HOME/.config/securelab/hmac-key.b64"
export AuditIntegrity__HmacKey="$(cat "$HOME/.config/securelab/hmac-key.b64")"
export AuditIntegrity__AnchorPath="$HOME/.local/share/securelab-audit/anchor.json"
```

Файл із ключем НЕ додавайте до Git, звітів, скриншотів. В іншому терміналі повторно задайте ті самі змінні; потрібні також налаштування PostgreSQL, що вже використовуються в проєкті.

## 3. Міграція, ініціалізація та верифікація

Зупиніть API перед `dotnet ef` і перед `--audit-init`. БД повинна бути локальною навчальною. Виконайте:

```bash
docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
dotnet ef database update --project src/SecureLab.Api --startup-project src/SecureLab.Api
# ТІЛЬКИ ОДИН РАЗ, коли таблиця AuditIntegrityEvents порожня і anchor ще не існує:
dotnet run --project src/SecureLab.Api -- --audit-init
# Має показати AUDIT INITIALIZED
dotnet run --project src/SecureLab.Api -- --audit-verify
# Має показати AUDIT OK count=0, last_sequence=0
```

Команду `--audit-init` НЕ повторювати після появи записів. Якщо anchor не збігається з базою — не перегенеровувати ключ і не «підганяти» anchor; це відмова за принципом fail-closed.

## 4. Дозволена дія та перевірка

```bash
dotnet run --project src/SecureLab.Api
```

Увійдіть у браузері та виконайте дозволену операцію `update`, `triage` або `delete` над **навчальним** інцидентом. Після цього зупиніть API і виконайте `--audit-verify`. Також перегляньте таблицю:

```sql
SELECT "SequenceNumber", "TimestampUtc", "EventType", "ActorUserId",
       "EntityType", "EntityId", "Action", "Outcome", "TraceId"
FROM "AuditIntegrityEvents" ORDER BY "SequenceNumber";
```

Не друкуйте HMAC-ключ, cookie, password, CSRF token у звіті.

## 5. Демонстрація втручання — лише в окремій тестовій копії бази

1. Створіть ізольовану копію навчальної БД та **копію відповідного anchor** (однаковий стан на момент копіювання); зупиніть усі API, що пишуть у цей журнал.
2. Виконайте `--audit-verify` на копії: очікується `AUDIT OK`.
3. Змініть одне поле в копії:

```sql
UPDATE "AuditIntegrityEvents" SET "Outcome"='tampered' WHERE "SequenceNumber"=1;
```

4. Виконайте `--audit-verify` на копії: очікується помилка integrity та ненульовий exit code.
5. Відновіть копію, перевірте видалення із середини, перестановку порядкових номерів (у безпечній ізольованій транзакції) та tail truncation. Відновлюйте чисту копію між сценаріями. Не змінюйте свій основний навчальний журнал.

## 6. Властивості та обмеження

- HMAC SHA-256, формат `audit-v1`, канонічний JSON array фіксованих полів, час UTC з мікросекундною точністю, nullable = JSON null.
- `SequenceNumber` і `PreviousHmac` з'єднують події; зовнішній підписаний anchor виявляє tail truncation.
- `SemaphoreSlim` + file lock + PostgreSQL transaction advisory lock серіалізують writers, якщо всі вони використовують один захищений anchor path та одну БД.
- Business mutation і audit event записуються в одній транзакції PostgreSQL, anchor оновлюється після commit. Збій між commit та anchor створює fail-closed стан, який потребує ручного дослідження/відновлення.
- Захист не покриває компрометацію самого застосунку/HMAC ключа, захоплення OS-акаунта, що контролює anchor, чи недовірену репліку; виробниче сховище ключів і backup-політика — окреме завдання.
- Початкові `SecureLab.Audit` логи авторизаційних відмов залишаються без змін.
- **Не перевірено збіркою/запуском тут:** у середовищі створення патча немає .NET CLI. `git apply --check` на вихідній версії після CSRF-only пройшов. Перевірте `dotnet build`, `dotnet test` та runtime на вашому стенді. Сценарії автоматизованих тестів для HMAC треба додати в `SecureLab.Api.Tests`; цей патч містить реалізацію й CLI verifier, а не готовий повний інтеграційний test pack.
