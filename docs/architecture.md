# Карта архітектури

## Компоненти

| Компонент | Розташування | Відповідальність |
|---|---|---|
| Browser client | `src/SecureLab.Api/Client/` | HTTP-запити через `fetch`, безпечний вивід через `textContent`/`createTextNode` |
| ASP.NET Core API | `Presentation/`, `Program.cs` | Маршрути, читання параметрів, allowlist `status`, HTTP-відповіді, Problem Details |
| Application | `Application/Incidents/IncidentQueries.cs` | Read-only запити (`AsNoTracking`), проєкція в response DTO |
| EF Core / Npgsql | `Data/SecureLabDbContext.cs` | Відображення `DbSet<Incident>` на таблицю `incidents` |
| PostgreSQL | `infra/compose.yaml` | Дані в локальному контейнері Docker Compose |

## Змінений маршрут: підсумок за severity

```text
кнопка «Показати підсумок» у Client/index.html
  → loadSeveritySummary у Client/app.js
  → GET /api/incidents/severity-summary[?status=...]
  → IncidentEndpoints.GetSeveritySummaryAsync (allowlist status)
  → IncidentQueries.GetSeveritySummaryAsync
  → SecureLabDbContext.Incidents / таблиця incidents (GROUP BY severity)
  → IncidentSeveritySummaryResponse (severity, count) як JSON
  → renderSeveritySummary: textContent у <li>
```

Контракт: лише наявні групи; порядок Critical → High → Medium → Low
(сортування в SQL було б лексикографічним); `?status=` необов'язковий,
значення поза allowlist дає 400 Validation Problem Details; порожній
результат — `[]` (наприклад, `status=Resolved`).

## Межі довіри

| Межа | Дані | Що не можна припускати | Контроль |
|---|---|---|---|
| браузер → API | method, URL, `status`, `{id}` | що запит створено з UI (`<select>`) | allowlist `status`, `:guid`, 404/400 |
| API → PostgreSQL | умови запиту | що збережений текст безпечний | параметризація EF Core, `AsNoTracking`, явна проєкція |
| API → браузер | JSON | що право читати entity = право бачити всі поля | окремі DTO без `OwnerUserId`/email/внутрішніх коментарів |
| response → DOM | текст із JSON | що текст можна вставляти як HTML | `textContent`, `createTextNode` |
| конфігурація → API | connection string | що локальні значення придатні деінде | `ConnectionStrings__SecureLab` поза Git |

## Конфігураційні входи та залежності

| Вхід | Що визначає | Хто читає |
|---|---|---|
| `global.json` | SDK 10.0.401 (`latestPatch`) | `dotnet` CLI |
| `infra/.env.example` (`POSTGRES_PORT`) | порт PostgreSQL на хості | `docker compose` |
| `infra/compose.yaml` | контейнер, локальні навчальні облікові дані, порт | `docker compose` |
| `appsettings.json` | рівні логування, `IncludeScopes`, `Database:AllowReset=false` | API |
| `appsettings.Development.json` | локальний connection string, `AllowReset=true`, міграції при старті | API (Development) |
| `ConnectionStrings__SecureLab` | перевизначає connection string | API |
| `Properties/launchSettings.json` | URL `localhost:5080`, `ASPNETCORE_ENVIRONMENT=Development` | `dotnet run` |
| `SecureLabApiFactory` | тести запускають API в Development, тобто в ту саму БД | тести |

Порядок пріоритету конфігурації: `appsettings.json` < `appsettings.Development.json` < змінні середовища.
Зміна порту БД потребує узгодження `POSTGRES_PORT` і `ConnectionStrings__SecureLab`.

## Журналювання

`Program.cs` відкриває для запиту scope з `TraceId` (`Activity.Current?.Id`, той самий,
що `traceId` у Problem Details). `IncidentQueries.GetSeveritySummaryAsync` пише кількість
груп і фільтр status; описи інцидентів, connection string, cookies, токени не логуються.

## Повернення до seed

Зупинити API, потім:
`dotnet run --no-build --configuration Release --project src/SecureLab.Api -- --reset-database`
(очищає лише навчальні таблиці; працює тільки в Development з `Database:AllowReset=true`).

## Знахідки в starter

1. `GetListAsync` приймав `status=1` та `status=New,Triaged` через `Enum.TryParse`+`IsDefined`.
   Виправлено: явний allowlist назв (`TryParseStatus`), 400 для решти.
2. Невідомий `/api/...` повертав 200 і HTML через SPA-fallback. Виправлено: `/api/{**path}` → 404 problem+json.
3. Пропозиція: `scripts/test.*` перед тестами відновлюють seed, бо тести використовують ту саму БД.