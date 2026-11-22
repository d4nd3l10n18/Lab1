# Підсумковий Security Review — SecureLab, лабораторна робота № 6

**Дисципліна:** Прикладні технології програмування в інформаційній безпеці
**Рівень:** «Відмінно» 
**Індивідуальне завдання (погоджене викладачем):** «Захищений Audit Trail із перевіркою цілісності»
**Студент:** Стець Назар, КБ-43.


## 1. Executive summary

Мета ЛР6 — повторний security review накопичувального застосунку SecureLab, що містить browser client, ASP.NET Core API, Identity cookie authentication та PostgreSQL. Додано explicit ASP.NET Core antiforgery для cookie-authenticated mutation endpoints, per-user search limiter, CSP/security headers, HMAC-chain Audit Trail із зовнішнім anchor і локальним верифікатором. Наявний набір тестів попередніх ЛР збережений; додано нові регресії `CsrfRegressionTests`, `SearchRateLimitingTests`, `HardeningRegressionTests`, `AuditEndpointRegressionTests` та `AuditIntegrityTests`. 

## 2. Scope and exclusions

**In scope:** `src/SecureLab.Api`, `tests/SecureLab.Api.Tests`, `infra/compose.yaml`, tracked configuration, NuGet lockfiles, HTML/JS клієнт (`Client/`), таблиці incidents/Identity/AuditIntegrityEvents, console logs, зовнішній HMAC anchor. **Тільки локальний стенд** з тестовими акаунтами, без реальних секретів.

**Not tested automatically:** зовнішні системи, production-сервер, nginx/інша reverse proxy, mobile client, Redis (не застосовується), повний Git history scan, OS-level `fsync` директорії. `git log`/history, advisory і браузерні перевірки потрібно виконати окремо.

## 3. System overview and trust boundaries

Детальна модель: [`threat-model.md`](threat-model.md). Основні межі: browser → API (authentication, CSRF, validation, CSP); API → PostgreSQL (query parameterization, authorization, transactional audit); configuration → process (HMAC key поза Git); PostgreSQL → anchor (tampering detection); Git/NuGet → build (locked restore, advisory audit).

| Asset | Threat | Control | Verification |
|---|---|---|---|
| Incident | IDOR/BOLA | resource-based authorization | Lab04AuthorizationTests |
| Cookie-authenticated incident | CSRF | ASP.NET Core antiforgery explicit validation | REG-CSRF-01…03 |
| Search | flooding / global rate contention | user-partitioned fixed window | RL search tests |
| Browser DOM | XSS | DOM safe sinks, CSP | Lab05 pack, CSP DevTools |
| Audit events | database tampering | HMAC chain, external anchor | AUD-01…10 |
| Credentials | leakage | no raw credentials in logs, env secrets | existing auth log tests, review |

## 4. Methodology and test environment

- PostgreSQL: локальний Docker Compose `infra/compose.yaml`, порт у `.env.example` — `54329`. 
- API: Development, `http://localhost:5080`; HTTPS WebApplicationFactory у tests. Production broken profile — окрема перевірка.
- Seed: `SeedUsers__Password` тільки в environment, значення не записується.
- Початковий Git: `git log -1 --oneline v0.5.0` → **внести**.
- Review-start commit: `cat docs/evidence-lab06/start_commit.txt` — файл є в архіві, перевірити відповідність Git.
- Verified HEAD після злиття: **внести**.
- Тести використовують відокремлені тимчасові БД `lr06_test_<GUID>`, `lr06_audit_<GUID>` і anchor у temp directory. Тестовий PostgreSQL користувач повинен мати `CREATEDB`.
- Порядок: `dotnet restore --locked-mode` → `dotnet build` → `dotnet test` → browser manual, Production broken, dependency audit, log review, merge + full rerun.

## 5. Findings summary

| ID | Актив | Вплив / пріоритет | Статус | Retest |
|---|---|---|---|---|
| F-01 | Incident mutation | CSRF / P1 | код захисту наявний; фінальний тест NOT RUN | REG-CSRF-01 |
| F-02 | Production response headers | можлива невідповідність 500 / P2 | candidate, не підтверджено | HDR-PROD-500 |
| F-03 | Audit availability при anchor mismatch | відмова у вході / P2 | candidate, поведінка fail-closed очікувана; UX/transactionality оцінити | AUD-08 + LOGIN-FAILURE |

**Норматив для «Відмінно»:** три підтверджені виправлені findings із доказами before → fix → retest + positive regression. F-02/03 не можна автоматично зарахувати; залишити як gaps або замінити підтвердженими знахідками.


## 7. Regression results

Повний інвентар, test methods та команди — [`regression-matrix-lr06.md`](regression-matrix-lr06.md). Наявні докази `csrf-before.json`, `csrf-after-denied.json`, `csrf-after-success.json` із вихідного архіву збережені; вручну перевірити їхню актуальність та відсутність секретів.

| Scenario | Test/evidence | Очікування | Факт |
|---|---|---|---|
| REG-CSRF-01 | `CsrfRegressionTests.REG_CSRF_01…` | 400 unchanged + 204 changed | NOT RUN |
| REG-CSRF-02 | invalid request token | 400 unchanged | NOT RUN |
| REG-CSRF-03 | mismatch antiforgery cookie/token | 400 unchanged | NOT RUN |
| REG-CSRF-04…06 | logout/create/delete/triage | no-token 400, valid-token permitted | NOT RUN |
| RL-SEARCH | search tests | quota 3/10 sec production default; configurable shorter window in test | NOT RUN |
| CORS | HardeningRegressionTests | allow trusted origin, no `ACAO` for untrusted | NOT RUN |
| AUD | AuditIntegrityTests 01…10 | detect tampering, concurrent integrity | NOT RUN |
| PRIOR | existing Lab02/03/04/05 relevant tests | no regressions | NOT RUN |

### Команди фінальної регресії

```bash
docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
dotnet restore SecureLab.sln --locked-mode
dotnet build SecureLab.sln -c Release --no-restore
dotnet test SecureLab.sln -c Release --no-build --logger 'console;verbosity=normal'
```

Для `SeedUsers__Password` попередньо використати захищене локальне environment, як у `regression-matrix-lr06.md`. Зберегти sanitized console output: `docs/evidence-lab06/final-test-run.txt`, реальний код завершення.

## 8. Hardening controls

| Control | Ризик | Реалізація | Verification / status | Обмеження |
|---|---|---|---|---|
| `AddProblemDetails`, `UseExceptionHandler` | stack traces у production | `Program.cs` | ручний Production 500 — NOT RUN | саме 500 потребує контролю |
| `X-Content-Type-Options`, `Referrer-Policy` | MIME sniffing, referrer leakage | `Program.cs` | HardeningRegressionTests, Production — NOT RUN | middleware re-execution на 500 |
| CSP `script-src 'self'`, `object-src 'none'` | inline script, object injection | `Program.cs` | DevTools + headers — NOT RUN | CSP ≠ XSS proof |
| Cookie `HttpOnly`, SameSite | cookie exposure, частина CSRF | `Lab03Identity.cs` | cookie tests — NOT RUN | не заміняє antiforgery |
| Antiforgery filter | state-changing CSRF | `CsrfValidation.cs`, `csrf.js` | REG-CSRF-01…03 — NOT RUN | login/register — окремий ризик |
| CORS allowlist 4173 | cross-origin reading | `Program.cs` | CORS tests + browser — NOT RUN | curl не доводить SOP |
| Login limiter | password spraying | `LoginRateLimiting.cs` | Lab03RateLimitAndEventsTests — NOT RUN | per-IP, локальний IP залежить від proxy |
| Search limiter | automated query abuse | `LoginRateLimiting.cs` | SearchRateLimitingTests — NOT RUN | per-user partition, 3/10 sec default |
| HMAC Audit Trail | DB tampering | `AuditIntegrity.cs`, DB/anchor | AUD tests — NOT RUN | full app compromise outside scope |

### Endpoint perimeter

| ID | Route | Cookie authentication | State change | Explicit validation |
|---|---|---|---|---|
| SC-01 | POST `/api/auth/register` | ні | user creation | не застосовується до cookie authenticated perimeter |
| SC-02 | POST `/api/auth/login` | ні до входу | session creation | окреме login-CSRF рішення |
| SC-03 | POST `/api/auth/logout` | так | sign out | `CsrfValidation` |
| SC-04 | POST `/api/incidents` | так | create | `CsrfValidation` |
| SC-05 | PUT `/api/incidents/{id}` | так | update | `CsrfValidation` |
| SC-06 | DELETE `/api/incidents/{id}` | так | delete | `CsrfValidation` |
| SC-07 | POST `/api/incidents/{id}/triage` | так | status transition | `CsrfValidation` |

**CSP manual:** Network → JS для `auth-lab.html` та `browser-lab.html`; не повинно бути необґрунтованого «Refused to load script». **Production:** `bash ../lr06-resources/commands/production.sh broken`, зупинивши Development API, та sanitized HTTP 500 headers; якщо команда падає до Listening, це записати як blocker, а не PASS.

### Advanced variant — HMAC Audit Trail

Повний опис: [`audit-integrity.md`](audit-integrity.md). Ключі не пишемо до репозиторію. `--audit-init` лише для порожньої таблиці та відсутнього anchor; `--audit-verify` лише локально, **публічного endpoint немає**. HMAC ланцюг виявляє зміну, середнє видалення та перестановку; зовнішній anchor — обрізання з кінця. Advisory lock + file lock серіалізують writer. Невідповідність перериває операцію, не дозволяючи автоматично довірити новому DB state. Окремий `AUD_08` моделює stale anchor. Механізм не захищає від компрометації застосунку та HMAC-ключа.

## 9. Dependency and secret audit

**Наявні механізми:** `packages.lock.json`, restore `--locked-mode`, `infra/.env.example` як навчальний example, `.gitignore`. 

```bash
git status --short
git ls-files '*appsettings*.json' '*.env*' '*compose*.yaml'
git grep -n -I -i -E 'password|secret|api.?key' -- .
dotnet package list --vulnerable --include-transitive
dotnet package list --vulnerable --include-transitive --format json
```


## 10. Residual risks

| Ризик | Чому лишається | Пріоритет/відповідальний | Наступна дія |
|---|---|---|---|
| Повна компрометація API або HMAC key | chain можуть перекувати | High / розробник | OS secret store, key rotation та захист host |
| Збій між DB commit та оновленням anchor | доступність блокується fail-closed | High / оператор | ручне recovery з незалежним backup та incident review |
| File-system durability | directory fsync не тестувався | Medium / розробник | OS-level fault injection |
| Production-like 500 headers | перевірка до final run відсутня | Medium / розробник | broken profile retest |
| DB reset після HMAC init | reset не координує anchor chain | Medium / розробник | reset тільки на окремій тестовій копії |
| Неповна coverage log sinks | unit tests не заміняють manual logs | Medium / розробник | sanitized six-scenario inspection |
| Відсутнє окреме підтвердження 3 fixed findings | evaluation requirement | High / студент | відтворити й документувати три реальні дефекти |

## 11. Conclusion

Підготовлено код і нові automated test cases для LR06 та індивідуального HMAC-завдання; автоматизовані результати ще **не підтверджено** у середовищі автора цього пакета. Висновок «security review пройдено» може бути сформульовано **лише після** успішної збірки, фінальної регресії, browser/Production перевірок та оформлення findings. Незалежно від кількості позитивних тестів абсолютну відсутність вразливостей не стверджувати.
