# Звіт WEB ЛР 2

## 1. Ідентифікація

- ПІБ і група: Стець Назар Максимович, КБ-43
- Спільний baseline 2-A; індивідуального номера немає.
- Заявлений рівень: відмінний («Відмінно»)
- Гілка: `lab/2-input-sqli`
- Release, base_commit та entry_parent із квитанції `.scaffolds/lab-02.json`:
  - release: `lab-02-start-v1`
  - base_commit: `aed59bd067cc2460d5a4a46e0c7b67271459f531`
  - entry_parent: `aed59bd067cc2460d5a4a46e0c7b67271459f531`
- Vulnerable commit: `a4f3c5632a7282a2f94c780a740520f7c0a0e117`
- Fixed commit коду: `d4216fb9f48f4b7641bcd9e61e1b2752b337af91`
- Фінальний тег `v0.2.0` стоїть на commit звіту, створеному після fixed commit; між fixed commit і тегом код не змінювався (`git diff <FIXED_SHA> v0.2.0 -- src tests` порожній).

## 2. Контракт і CP-01

Реалізовано `POST /api/incidents` у `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs`. Request DTO `CreateIncidentRequest` містить лише `title`, `description`, `severity`, `occurredAtUtc`. Відповідь формує окремий `CreatedIncidentResponse` (201 Created, заголовок `Location`).

**Правила контракту:**

| Поле | Правило | Відповідь у разі порушення |
|---|---|---|
| `title` | не порожній після `Trim()`; довжина вхідного значення до `Trim()` не більше 160 | 400, ключ `title` |
| `description` | не порожній після `Trim()`; довжина до `Trim()` не більше 4000 | 400, ключ `description` |
| `severity` | `Enum.TryParse` без урахування регістру **та** `Enum.IsDefined`: Low, Medium, High, Critical | 400, ключ `severity` |
| `occurredAtUtc` | обов'язкове; не пізніше `now + 5 хв` (`now` фіксується один раз на початку обробки) | 400, ключ `occurredAtUtc` |
| `occurredAtUtc` (T-10) | не раніше ніж за 365 днів до `now` | 400, ключ `occurredAtUtc` |
| cross-field (T-09) | для High/Critical `description` після `Trim()` має щонайменше 40 символів | 400, ключ `description` |
| конфлікт (T-03) | той самий `title` після `Trim()` з урахуванням регістру серед інцидентів у статусах New, Triaged, InProgress, Resolved; Closed не блокує | 409 |

Помилки збираються в `Dictionary<string, string[]>` і повертаються одним `Results.ValidationProblem(errors)` до створення entity та доступу до БД. Часове зміщення не відхиляється: перед записом викликається `.ToUniversalTime()` (`13:00+03:00` і `10:00Z` — той самий момент).

**Server-managed поля.** `Id`, `OwnerUserId` (фіксований demo-користувач Alice, `DbSeeder.AliceId`), `Status` (завжди `New`), `CreatedAtUtc`, `UpdatedAtUtc` встановлює лише сервер. У `CreateIncidentRequest` таких властивостей немає, тому зайві поля JSON ігноруються (захист від overposting).

**CP-01. Чому потрібні і `Enum.TryParse`, і `Enum.IsDefined`.** `Enum.TryParse` успішно перетворює числовий рядок: `"7"` стає `(IncidentSeverity)7`, хоча такого елемента в enum немає. `Enum.IsDefined` відхиляє значення поза набором Low, Medium, High, Critical. Тому запит із `severity: "7"` отримує 400, а не створює запис із недопустимим значенням.

**Маршрут перевірки.** JSON → binding у `CreateIncidentRequest` → серверна валідація (базові поля, cross-field) → 400 `application/problem+json` з `errors` або перехід до предметного правила (409) → запис у БД → response DTO. Зміна `<select>` або HTML-атрибута `required` у браузері не замінює цю перевірку: клієнтом керує користувач, а інший HTTP-клієнт надішле довільне тіло запиту.

**Overposting.** Запит із зайвими полями `id`, `ownerUserId`, `status: "Closed"`, `createdAtUtc` створив запис із новим `id`, статусом `New` і власником Alice (див. T-01 і A-02).

## 3. Security-сценарій і CP-02/CP-03

1. **Контекст і гіпотеза.** Локальний endpoint `GET /api/incidents/search` отримує недовірені `q` і `sortBy`. Гіпотеза: значення входить до SQL-структури, а не лишається даними. Усі дії виконано лише локально (Development, PostgreSQL з `infra/compose.yaml`, штучний seed).

2. **Стан до.** Vulnerable commit `a4f3c5632a7282a2f94c780a740520f7c0a0e117`. Метод: обробник `GET /api/incidents/search` у `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs`, рядок `<N>` (конкатенація `"SELECT … ILIKE '%" + q + "%' … ORDER BY " + order`) і виклик `db.Incidents.FromSqlRaw(sql)`, рядок `<M>`. Для `sortBy` гілка `_ => sortBy` у `switch` віддає клієнтське значення прямо в `ORDER BY`.

3. **Мінімальний PoC.** Власний read-only сценарій C зі `tests/http/lab-02-checks.http` (єдиний дозволений контрольний ввід, закодований в URL). Руйнівних дій і інших payload не було.

4. **Спостереження (vulnerable commit, після reset).**
   - A (`q=USB`): 200, один запис.
   - B (`q=zz-no-match`): 200, `[]`.
   - C (контрольний ввід): 200, **усі 5 записів seed**, тобто вибірка небажано розширена.
   - D (`q=O'Brien`): 500 Problem Details без внутрішніх деталей; у журналі API: `Failed executing DbCommand`, `syntax error at or near "Brien"`. Легітимний апостроф сам закрив рядковий літерал.
   - У журналі для B і C `Parameters=[]`: значення передано всередині тексту команди, а не окремо.

5. **Першопричина.** Недовірений `q` (і `sortBy`) з'єднувався зі SQL-текстом до виконання, після чого PostgreSQL одержувала один суцільний текст і не могла відрізнити дані від інструкції. У випадку C апостроф закрив літерал, `OR TRUE` став частиною умови `WHERE`, а `--` закоментував решту рядка. Фільтр апострофа або заборона `OR` не усувають механізм, бо ламають легітимні дані (D) і не захищають структуру запиту.

6. **Виправлення.**
   - Значення `q`: LINQ + `EF.Functions.ILike(…, pattern, "\\")`; EF Core передає шаблон параметром (`@pattern`). Власна `EscapeLike` екранує `\`, `%`, `_` (у такому порядку), тому пошук — literal substring.
   - `sortBy`: allowlist через `switch` (`createdAtUtc` за замовчуванням, `severity`, `status`) з рангами Critical > High > Medium > Low і New > Triaged > InProgress > Resolved > Closed; другий ключ `Id`; після сортування `Take(50)`. Невідоме значення → 400 з ключем `sortBy`, до SQL не доходить.
   - Серверна валідація для контракту створення (розділ 2).
   - Diff: `evidence/security-diff.txt`.

7. **Retest і позитивна регресія (fixed commit).** Контрольний ввід C повертає 200 і `[]`; `q=USB` повертає рівно один запис (`…0005`); `q=O'Brien` повертає «O'Brien classroom report»; `q=комп'ютерного` повертає один запис; `%`, `_`, `\` шукаються буквально (на seed — `[]`). У журналі API тепер `Parameters=[@pattern=…, @pattern0=…]` і `ILIKE @pattern ESCAPE '\'`: значення передано окремо від тексту SQL.

8. **Залишковий ризик.** Виправлення не замінює authorization (власник інциденту поки фіксований), пагінацію чи rate limiting, не доводить безпеку інших endpoint-ів поза переглянутими в A-01 та не визначає production logging policy.

**CP-02.** Vulnerable commit, точка складання SQL, маршрут `query string → параметр q → конкатенація → FromSqlRaw → PostgreSQL` і таблиця спостережень наведені вище. Запланований механізм виправлення: параметризація значень через LINQ/`ILike`, allowlist для структури (`sortBy`).

**CP-03.** Раніше PostgreSQL одержувала один текст після конкатенації (`Parameters=[]`). Тепер значення `pattern` передається окремо (`Parameters=[@pattern…]`), а структуру `ORDER BY` вибирає серверний allowlist. Diff між станами: `evidence/security-diff.txt`.

## 4. Фактичні перевірки DEL-02

Усі сценарії виконано локально на штучному seed. «Auto» означає автоматичний тест у `tests/SecureLab.Api.Tests` (`Lab02ContractTests.cs`, `Lab02SecurityTests.cs`).

| ID | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|
| T-01 | Коректне створення | унікальний title, valid DTO | `POST /api/incidents` (title з пробілами, `severity: "low"`, зміщення `+03:00`) | 201, response DTO без зайвих полів | 201, `Location`, title без пробілів, `status: New`, `severity: Low`, поля `ownerUserId` у відповіді немає | `evidence/t01-response.txt`; auto `T01_ValidPost_Returns201_WithServerManagedFields` |
| T-02 | Некоректний DTO | fixed commit | POST з порожнім title / description, `severity: "7"` і `"Nope"`, без `occurredAtUtc`, дата 2099, title 161 символ, description 4001 символ | 400, `application/problem+json`, ключ поля в `errors` | 400 `application/problem+json`, у `errors` відповідні ключі; stack trace, SQL, connection string відсутні | `evidence/t02-severity7.txt`; auto `T02_InvalidDto_Returns400Problem`, `T02_TooLongTitleAndDescription_Return400` |
| T-03 | Предметний конфлікт | існує активний інцидент із тим самим title | повторний POST із тим самим title (з пробілами по краях) | 409 у Problem Details | 409 `application/problem+json`, є `title`, `status`, `detail`; інший регістр — 201; після переведення в Closed повторне створення — 201 | `evidence/t03-response.txt`; auto `T03_DuplicateActiveTitle_Returns409_ButClosedDoesNotBlock` |
| S-01 | SQLi до виправлення | vulnerable commit, reset, local seed | власний read-only сценарій C | небажано розширена вибірка | 200, усі 5 записів seed; D (`O'Brien`) — 500 | `evidence/s01-A-before.txt`, `s01-B-before.txt`, `s01-C-before.txt`, `s01-D-before.txt`; commit `a4f3c56…` |
| S-02 | Retest SQLi | fixed commit, reset, той самий seed | той самий сценарій C + автотест множини | 200, порожня множина | 200, `[]`; auto `S02_ControlInput_ReturnsEmptySet` (`Assert.Empty`) і позитивний контроль `S02_PositiveControl_UsbReturnsExactlyOneRecord` (рівно один запис, Id `…0005`) | `evidence/s02-C-after.txt`; auto-тести |
| T-04 | Позитивна регресія | fixed commit | `q=USB`, `q=O'Brien`, `q=комп'ютерного`, `%`, `_`, `\` | коректні записи, без 500; wildcard буквально | `USB` — 1 запис; `O'Brien` — 1 запис (`…0004`); `комп'ютерного` — 1 запис; `%`, `_`, `\` — `[]` | `evidence/t04-usb-after.txt`, `evidence/t04-apostrophe-after.txt`; auto `T04_*` |
| T-05 | Невідоме сортування | fixed commit, reset | `GET /api/incidents/search?sortBy=price` (також `title; select 1`, `created_at_utc`) | 400 | 400 `application/problem+json`, `errors.sortBy`; SQL відсутній | `evidence/t05-response.txt`; auto `T05_UnknownSortBy_Returns400WithSortByKey` |
| T-06 | Ресурс не знайдено | baseline endpoint доступний | `GET /api/incidents/99999999-9999-9999-9999-999999999999` | 404 у Problem Details | 404 `application/problem+json`, title «Інцидент не знайдено» | `evidence/t06-response.txt` |
| T-09 | Cross-field 2-A | унікальний title, решта полів коректна | два POST: High (і Critical), description 39 та 40 символів після `Trim()` | 39 → 400 `description`; 40 → проходить | 39 → 400 з ключем `description`; 40 → 201; Low із коротким description → 201 | `evidence/t09-39.txt`, `evidence/t09-40.txt`; auto `T09_*` |
| T-10 | Додаткова предметна перевірка | правило задокументовано | порушити лише правило: `occurredAtUtc` старіший за 365 днів | 400, ключ `occurredAtUtc`; допустимий випадок успішний | дата 2020-01-01 (і −400 днів у тесті) → 400 `occurredAtUtc`; дата −30 днів → 201 | `evidence/t10-old.txt`, `evidence/t10-ok.txt`; auto `T10_OccurredAtOlderThan365Days_Returns400_Recent_Returns201` |
| A-01 | Огляд data-access points | fixed commit | `git grep`, `data-access-scan.py`, перегляд усіх точок доступу до БД у `src` | для кожної точки: файл/метод, категорія, висновок | див. таблицю нижче | таблиця A-01 нижче |
| A-02 | Overposting | fixed commit | POST із зайвими `id`, `ownerUserId`, `status: "Closed"`, `createdAtUtc` | server-managed поля не змінюються | новий `id` (не надісланий), `Status = New`, власник Alice (`DbSeeder.AliceId`), `CreatedAtUtc` не 2000-01-01; auto `A02_Overposting_ExtraFieldsAreIgnored` | див. A-02 нижче; auto-тест |

### A-01. Огляд data-access points

Команди: `git grep -n -e FromSqlRaw -e ExecuteSqlRaw -e "ORDER BY" -- src tests`; `git grep -n -F -e '$"SELECT' -e '+ query' -- src tests`; `data-access-scan.py`; додатково перегляд LINQ і доступу через `SecureLabDbContext` у `src`.

| Файл:рядок / метод | Категорія | Висновок |
|---|---|---|
| `src/SecureLab.Api/Data/DatabaseBootstrap.cs`, `ExecuteSqlRawAsync` | статичний службовий SQL, без користувацьких значень | безпечно: рядок константний, user input не бере участі |
| `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs`, `GET /api/incidents/search` | LINQ + `EF.Functions.ILike`, значення параметром `@pattern`; сортування через allowlist | безпечно: значення не входить у текст SQL; невідомий `sortBy` → 400 |
| `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs`, `POST /api/incidents` (`AnyAsync`) | LINQ-predicate, `title` параметром | безпечно |
| `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs`, `POST /api/incidents` (`Add`, `SaveChangesAsync`) | EF-запис через entity, server-managed поля задає сервер | безпечно |
| `src/SecureLab.Api/Scaffolding/Lab02Seed.cs` | EF, штучні константні дані | безпечно |
| `src/SecureLab.Api/Data/DbSeeder.cs` | EF, штучні константні дані | безпечно |
| `src/SecureLab.Api/Application/Incidents/IncidentQueries.cs` (ЛР 1) | LINQ-запити, значення параметрами | безпечно |
| `src/SecureLab.Api/Presentation/Endpoints/IncidentEndpoints.cs` (ЛР 1) | виклики запитів через сервіс/DbContext | безпечно: raw SQL відсутній |
| `tests/SecureLab.Api.Tests/Lab02ContractTests.cs`, `CleanupAsync` та `ExecuteUpdateAsync` у T-03 | LINQ `ExecuteDelete`/`ExecuteUpdate` з унікальним title з тесту | безпечно: лише тестове середовище, значення з тесту |

Після виправлення `git grep` знаходить лише `ExecuteSqlRawAsync` у `DatabaseBootstrap.cs`; друга команда нічого не виводить.

### A-02. Mass-assignment (overposting)

- **До (ризик без вигаданого дефекту).** Якби request DTO повторював entity, клієнт міг би підмінити server-managed поля `id`, `ownerUserId`, `status`, `createdAtUtc`. Відтвореного дефекту в коді не було.
- **Місце захисту.** `CreateIncidentRequest` (`Lab02Endpoints.cs`, наприкінці файла): лише `Title`, `Description`, `Severity`, `OccurredAtUtc`.
- **Після.** Автотест `A02_Overposting_ExtraFieldsAreIgnored` надсилає зайві поля й перевіряє, що збережений запис має новий `id`, `Status = New`, власника Alice, а `CreatedAtUtc` не підмінено.
- **Чутливість тесту.** `<ОДНЕ РЕЧЕННЯ: тимчасово додав `string? Status` до request і `Enum.Parse<IncidentStatus>(request.Status ?? "New")` в обробник — тест упав з Expected: New, Actual: Closed; після `git restore` пройшов. Якщо не виконували, видаліть цей пункт.>`

### T-10. Додаткове предметне правило

- Правило: `occurredAtUtc` не раніше ніж за 365 днів до поточного UTC-часу сервера.
- Межа: `now.AddDays(-365)`; відповідь 400, ключ `occurredAtUtc`.
- Недопустимий запит: `"occurredAtUtc": "2020-01-01T00:00:00Z"` → 400.
- Допустимий запит: `"occurredAtUtc": "2026-10-01T00:00:00Z"` → 201.
- Правило не послаблює і не змінює правил 2-A: воно перевіряється в тому самому handler до доступу до БД.

### Build і baseline-тести після останньої зміни

`dotnet build tests/SecureLab.Api.Tests -c Release` — успішно. `dotnet test tests/SecureLab.Api.Tests -c Release` після reset — `Failed: 0, Passed: <N>`. Успадкований тест підсумку за severity з ЛР 1 оновлено лише в очікуваних лічильниках (scaffold додав два Low: Low=3, Medium=1, High=1); перевірки порядку `High, Medium, Low` збережено.

## 5. Обмеження і висновок

- Попередній `AnyAsync` перед записом пояснює предметний конфлікт як 409, але **не гарантує** інваріант за одночасних запитів: два паралельні POST із тим самим title можуть обидва пройти перевірку. У реальному застосунку потрібне обмеження БД (унікальний індекс) або транзакційне рішення; у ЛР 2 migration не додавалися.
- Зіпсований JSON (синтаксична помилка, число замість рядка) у стартовому конвеєрі дає 500 через `BadHttpRequestException` до виклику обробника. Це окремий дефект, а не результат моєї валідації; сценарії T-02 використовують синтаксично правильний JSON.
- Власник нового інциденту береться з фіксованого demo context (`DbSeeder.AliceId`); справжній authenticated principal з'явиться в ЛР 3.
- Пошук обмежений `Take(50)` без пагінації.
- Дублікати перевіряються з урахуванням регістру (`Alert` і `alert` — різні title): це навчальне спрощення, а не загальна політика.
- Перевірено лише локальний стенд зі штучними даними. Виправлення пошуку не замінює authorization, rate limiting і перевірку інших endpoint-ів поза переглянутими в A-01.

**Висновок.** Контракт створення інциденту перевіряється на сервері (required, довжини, enum, дата, cross-field, предметний конфлікт) і повертає безпечні `application/problem+json` без внутрішніх деталей. Першопричину SQL injection (змішування `q` і `sortBy` зі SQL-текстом) усунуто параметризацією через LINQ/`ILike` та allowlist для структури запиту; повторний контрольний ввід більше не змінює логіку запиту, а звичайний пошук і пошук із апострофом працюють.

## 7. Передавання

- Remote доступний викладачеві або bundle перевірено: `<git bundle verify → is okay; list-heads показує lab/2-input-sqli, v0.2.0, v0.1.0>`.
- У Moodle файли/докази видимі й роботу надіслано.
- Git diff та історію перевірено на секрети (`git diff --staged`, `git log --all --name-only`); `.env`, паролі, токени, дампи БД та логи з credentials у репозиторії відсутні, відкриті локальні credentials baseline навчальні.