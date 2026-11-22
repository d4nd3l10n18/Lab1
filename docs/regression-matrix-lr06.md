# LR06 — матриця автоматизованих та ручних регресій

**Стан:** тести створені/розширені на основі `Lab1(3).zip`; PASS/FAIL не заповнені, оскільки в середовищі підготовки немає dotnet та запущеної навчальної PostgreSQL. Результати записати після локального запуску. Не підміняйте очікуваний результат фактичним.

## Автоматизовані тести

| Блок | Файл | Що перевіряє | Очікування | Фактичний результат |
|---|---|---|---|---|
| REG-CSRF-01 | `CsrfRegressionTests.cs` | cookie login → PUT без токена → state unchanged → PUT з токеном → state changed | 400, без зміни, 204, зміна | NOT RUN |
| REG-CSRF-02/03 | той самий | invalid token; mismatched cookie/request pair | 400 і no mutation | NOT RUN |
| REG-CSRF-04…06 | той самий | logout/create/delete/triage without/with token | 400 before mutation, success after token | NOT RUN |
| RL-01…04 | `SearchRateLimitingTests.cs` | 3 requests, 429, Bob independent, `/api/me`, recovery | 200×3;429; Bob 200; recovery 200 | NOT RUN |
| RL-05 | той самий | anonymous / search | 401 | NOT RUN |
| HDR | `HardeningRegressionTests.cs` | CSP/nosniff/referrer на static/API 200/400/404 | відповідні headers | NOT RUN |
| CORS | той самий | allowed origin, denied origin, preflight | allow 4173, deny 4174 | NOT RUN |
| AUD-01…10 | `AuditIntegrityTests.cs` | чистий chain; tampering; concurrency; crash/anchor; rollback | див. `audit-integrity.md` | NOT RUN |
| AUD-HTTP | `AuditEndpointRegressionTests.cs` | audit login denied/success, update denied/success | event fields + verify OK | NOT RUN |
| ЛР 02–05 | наявні `Lab02*`, `Lab03*`, `Lab04*`, `SearchMechanicsTests` | SQLi/validation/authn/IDOR/XSS | правила попередніх методичок | NOT RUN |

## Команди

В окремому terminal із середовищем для тестів (пароль не друкувати):

```bash
read -rsp 'Seed password: ' SeedUsers__Password; echo
export SeedUsers__Password
docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
dotnet restore SecureLab.sln --locked-mode
dotnet build SecureLab.sln -c Release --no-restore
dotnet test SecureLab.sln -c Release --no-build --filter 'FullyQualifiedName~CsrfRegressionTests|FullyQualifiedName~SearchRateLimitingTests|FullyQualifiedName~HardeningRegressionTests|FullyQualifiedName~AuditIntegrityTests|FullyQualifiedName~AuditEndpointRegressionTests' --logger 'console;verbosity=normal'
dotnet test SecureLab.sln -c Release --no-build --logger 'console;verbosity=normal'
```

**Безпека:** factory створює `lr06_test_<GUID>` та `lr06_audit_<GUID>` замість модифікації основної `securelab`; роль має вміти CREATE/DROP DATABASE. Переконайтеся, що `ConnectionStrings__SecureLab` вказує на **локальний стенд**, а не на production. Не використовуйте `--reset-database` на фінальному audit-журналі.

## Обов'язково вручну (не покрито надійним unit-test)

- `PROD-500`: Production broken profile, контрольований 500; ProblemDetails без stack trace/connection string; CSP/referrer/nosniff **на 500**. Фактичний status і response sanitized screenshot.
- `CSP-BROWSER`: Network та Console у Chrome/Firefox для `auth-lab.html` і `browser-lab.html`; JavaScript успішно завантажується, не виникають необґрунтовані CSP violations.
- `CORS-BROWSER`: два origins `localhost:4173` і `:4174`; browser SOP/CORS enforcement, а не лише curl headers.
- `DEPS`: `dotnet package list --vulnerable --include-transitive` та оцінка advisories.
- `SECRETS`: git tracked files, `.gitignore`, history лише в межах записаного scope, six logging scenarios без credentials.
- `AUD-OS`: файл anchor захищено OS permissions, restart, вручну збережені sanitized SQL evidence; відновлення після crash.

