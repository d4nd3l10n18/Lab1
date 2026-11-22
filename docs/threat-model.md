# LR06 — Threat model / модель загроз SecureLab

## Система та межі довіри

```text
[Браузер: недовірені ввід і cookie] --HTTP(S)--> [ASP.NET Core API / Identity]
                                                      |
                                EF Core / SQL ----------+------> [PostgreSQL]
                                                      |
                                секрет із env ---------+------> [HMAC key]
                                локальний файл --------+------> [Anchor поза PostgreSQL]
[Git / NuGet / SDK] -------- build/restore -----------> [API binary]
```

| Актив | Загроза | Межа довіри | Захист у коді | Перевірка |
|---|---|---|---|---|
| Identity cookie / профіль | Підроблена автентифікація, витік credentials | Browser → API | Identity cookie, `HttpOnly`, авторизація, log allowlist | `Lab03AuthTests`, `Lab03CookieFlagsTests` |
| Incident та статус | CSRF від браузера зі збереженою cookie | Browser → API | `IAntiforgery`, `CsrfValidation`, request header | `CsrfRegressionTests.REG_CSRF_01…03` |
| Incident інших користувачів | IDOR / BOLA | API → DB | resource-based authorization | `Lab04AuthorizationTests` |
| Search | зловживання quota та розкриття даних | Browser → API | `incident-search` per-user fixed-window, scope за principal | `SearchRateLimitingTests`, `SearchMechanicsTests` |
| DOM / HTML клієнт | XSS та розкриття request token | Browser → API | безпечні DOM sinks, CSP `script-src 'self'` | `HardeningRegressionTests` + ручний Firefox/Chrome DevTools |
| Audit events | прямий UPDATE/DELETE/перестановка даних БД | PostgreSQL → verifier | HMAC-SHA256 chain, sequence, канонічна серіалізація | `AuditIntegrityTests.AUD_01…10` |
| Кінець audit-журналу | tail truncation, втрата записів | DB → anchor | зовнішній підписаний anchor | `AUD_05`, `AUD_08`, `AUD_09` |
| Audit key | крадіжка HMAC-ключа | Environment → process | secret поза Git, ключ ≥256 біт | configuration review; реальне KMS не входить до scope |
| NuGet / Git | шкідлива або вразлива залежність; випадковий commit секрету | Repository → Build | lockfiles, `--locked-mode`, package audit | команди в `security-review.md` |
| Response та logs | stack trace або credentials у відповіді/логах | API → consumer | `UseExceptionHandler`, ProblemDetails, sanitized logging | ручний Production 500, `Lab03RateLimitAndEventsTests`, `AuditEndpointRegressionTests` |

## Актори та припущення

- Анонімний відвідувач, `alice`/`bob` (Reporter), `morgan` (Analyst), локальний адміністратор стенду.
- Для перевірки integrity порушник може писати до PostgreSQL **без HMAC-ключа та без доступу до anchor**. Повна компрометація API/хоста не покривається.
- Seed пароль, HMAC key, cookie і CSRF token не друкуються в доказах. Відповіді для стороннього API не тестуються.

## Маршрути з mutation та CSRF

| ID | Маршрут | Cookie-authenticated | CSRF | Примітка |
|---|---|---|---|---|
| SC-01 | `POST /api/auth/register` | ні, до login | немає explicit validation | оцінити registration abuse окремо |
| SC-02 | `POST /api/auth/login` | ні, створює cookie | окреме рішення щодо login-CSRF | rate limiter `login` |
| SC-03 | `POST /api/auth/logout` | так | `CsrfValidation` | перевірка до SignOut |
| SC-04 | `POST /api/incidents` | так | `CsrfValidation` | create |
| SC-05 | `PUT /api/incidents/{id}` | так | `CsrfValidation` | update |
| SC-06 | `DELETE /api/incidents/{id}` | так | `CsrfValidation` | delete |
| SC-07 | `POST /api/incidents/{id}/triage` | так | `CsrfValidation` | status history |

## Обмеження

- CORS і SameSite не заміняють CSRF. Antiforgery не захищає від XSS на тому самому origin.
- Обробник CSP у `Program.cs` потребує окремого контрольованого 500 test: вміст заголовків на success не доводить їхню наявність після exception handler.
- HMAC не виявить порушень, якщо зловмисник контролює ключ **і** anchor. Fail-closed після crash потребує ручної процедури відновлення.
- `DatabaseBootstrap --reset-database` не є процедурою скидання audit-журналу; не використовувати на доказовій БД після HMAC init.
