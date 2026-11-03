# Звіт WEB ЛР03

## Відтворення (усі рівні)

- Обраний рівень/оцінка: Відмінно
- Автор/група: Стець Назар Максимович, КБ-43
- Baseline: 2-A (індивідуального варіанта немає)
- Base tag `v0.2.0`: `44449b12b8d782b614112235406f9b9a46db48fe`
- Scaffold:
  - release: `lab-03-start-v1`
  - base_commit: `44449b12b8d782b614112235406f9b9a46db48fe` (з `.scaffolds/lab-03.json`)
- Гілка: `lab/3-authentication` (створена від `v0.2.0`)
- Commit коду: `8521b57c62137a87dea03a715b5f94248c20536b`
- Перевірений commit / тег `v0.3.0`: `⟦ЗАПОВНІТЬ: git rev-parse v0.3.0^{commit}⟧`. Між commit коду і тегом код не змінювався (`git diff <commit коду> v0.3.0 -- src tests` порожній).
- ОС/SDK: Debian 13 (Linux); .NET SDK `10.0.401`; `global.json` без змін
- Команди build/tests (з кореня проєкту, пароль навчальних акаунтів заданий змінною середовища `SeedUsers__Password`, значення не зберігається):

  ```bash
  docker compose --env-file infra/.env -f infra/compose.yaml up -d --wait
  dotnet run --project src/SecureLab.Api -- --reset-database
  dotnet build tests/SecureLab.Api.Tests -c Release
  dotnet test tests/SecureLab.Api.Tests -c Release
  ```

- Фактичний результат: build без помилок; усього 70 тестів, з них нових власних для ЛР 3 — класи `Lab03AuthTests`, `Lab03IncidentOwnerTests`, `Lab03RegistrationTests`, `Lab03CookieFlagsTests`, `Lab03RateLimitAndEventsTests`, `Lab03DeepeningTests`. Підсумковий рядок останнього запуску: `Test summary: total: 70, failed: 0`.
- Migration/reset: міграція `Lab03Identity` з scaffold застосовується під час `--reset-database` (таблиці `identity_*` замість `study_users`). Два послідовні reset виконано скриптом `reset-twice` (`код завершення 0`); після кожного reset тести пройшли, сталі Guid Alice/Bob/Morgan/Admin та власники засіяних інцидентів не змінилися.
- Спостереження про відтворюваність: тести ЛР 2 (`Sorting_UsesContractRanks`, `GetSeveritySummary_…`) порівнюють точний seed. Один зайвий запис, створений після reset (вручну через браузерну форму), зламав 5 з них. Після повторного reset усі пройшли. Тому перед кожним фінальним прогоном виконується reset, а ручні експерименти — до нього.

## Власна реалізація і межі

**DTO boundary.**
- Request DTO register (`RegistrationInput`) містить лише `userName`, `email`, `displayName`, `password`. Полів `id`, `role`, `passwordHash` у ньому немає, тому зайві поля JSON ігноруються (перевірено тестом `Register_ExtraRoleAndId_AreIgnored`: користувач одержує згенерований сервером Id і роль `Reporter`).
- Response DTO: `RegisteredUserResponse(id, userName, displayName)` і `MeResponse(id, userName, roles)`. Entity `ApplicationUser` назовні не серіалізується.
- Request DTO створення інциденту `CreateIncidentRequest` без змін: `title`, `description`, `severity`, `occurredAtUtc`. Поля власника в ньому немає.

**Правила register.**

| Поле | Правило | Відповідь |
|---|---|---|
| `userName` | після `Trim()` 3–64 символи, `[A-Za-z0-9._@+-]` | 400, ключ `userName` |
| `email` | до 256 символів, розбір `MailAddress`, адреса збігається з введеною | 400, ключ `email` |
| `displayName` | не порожній, до 120 символів (як у моделі БД), без керівних символів | 400, ключ `displayName` |
| `password` | обов'язковий, не довший за 128 (захист від хешування величезних рядків); решту вимог перевіряє Identity | 400, ключ `password`; пароль у відповіді не повертається |
| Політика пароля Identity | ≥10 символів, велика й мала латинські літери, цифра, спецсимвол | 400, ключ `password` |
| Дублікат userName або email | `DuplicateUserName` / `DuplicateEmail` | 409, однакова безпечна відповідь без вказівки, яке поле зайняте |

Нормалізується лише `Trim()` для `userName`, `email`, `displayName`. Пароль не змінюється і не логується.

**Звідки `/api/me` та create беруть id.** Лише з `HttpContext.User`, claim `ClaimTypes.NameIdentifier` (перетворення в `Guid`; якщо claim немає або не Guid — 500, а не підстановка клієнтського значення). `/api/me` має `.RequireAuthorization()`. `POST /api/incidents` має `.RequireAuthorization()` і встановлює `OwnerUserId = verifiedUserId`. Константу `DbSeeder.AliceId` з ЛР 2 прибрано. Заголовок `X-Demo-UserId` з коду endpoint-ів повністю вилучено з довіри.

**Cookie options (`ConfigureApplicationCookie`, надані scaffold, перевірені й пояснені).**
- `HttpOnly = true`: JavaScript не читає cookie (`document.cookie` її не показує).
- `SameSite = Lax`: обмежує частину cross-site запитів; для same-origin клієнта це обґрунтований baseline. Повного захисту від CSRF не дає.
- `SecurePolicy`: `SameAsRequest` у Development, `Always` в інших середовищах. Локальний HTTP-запуск не доводить Secure: цей атрибут підтверджено лише в тесті з базовою адресою `https://localhost`.
- Назва cookie `.AspNetCore.Identity.Application`, сеансова (без `expires`).
- Обробники `OnRedirectToLogin` / `OnRedirectToAccessDenied` повертають 401 / 403 без redirect.

**Фактичні flags (добрий).** Тест `Lab03CookieFlagsTests`: за HTTPS у `Set-Cookie` є `httponly`, `secure`, `samesite=lax`, `path=/`, немає `expires` та `max-age`. За звичайного HTTP у Development атрибута `secure` немає, `httponly` є. У DevTools (Application → Cookies) для `http://localhost:5080`: HttpOnly позначено, Secure порожній, SameSite = Lax, Expires/Max-Age = Session. Значення cookie не копіювалося.

**Строк дії.** Окремо не змінювався: стандартний для Identity (14 днів із sliding expiration), сама cookie сеансова. Закриття вікна браузера не замінює logout (браузер може відновити сеанс). Server-side відкликання при звичайному logout немає; відкликання при події безпеки показано в поглибленні (а).

**Login.** Логіку надану scaffold збережено: невідомий користувач і хибний пароль дають однаковий 401 (однаковий статус, тип вмісту, поля Problem Details, без `Set-Cookie`). Додано лише: ліміт довжини вхідних даних (`userName` ≤256, `password` ≤128, відповідь така сама 401), події автентифікації, rate limit. Вхід виконується за іменем користувача, не за email. `lockoutOnFailure` вимкнено, захист від підбору забезпечує rate limit.

**Logout (добрий).** `SignInManager.SignOutAsync()`; відповідь 204 із `Set-Cookie`, що видаляє `.AspNetCore.Identity.Application`; endpoint ідемпотентний (повторний logout теж 204). Після logout той самий клієнт одержує 401 на `/api/me`.

**Duplicate-контракт (добрий).** 409 `application/problem+json` для збігу `userName` або `email`; відповіді на обидва випадки ідентичні за формою (тест порівнює `type`, `title`, `status`, `detail`). 400 лишається для некоректних даних.

**Rate limit і події (добрий).**
- Політика `login` (fixed window), ключ — IP клієнта (`RemoteIpAddress`, у тестовому host — `"unknown"`); за замовчуванням 10 спроб за 60 с, значення читаються з конфігурації `RateLimiting:Login:*`. Відповідь 429 (`application/problem+json`); ліміт спрацьовує до перевірки пароля, тому правильний і хибний пароль, відомий і невідомий користувач дають однаковий 429.
- Тест: для окремого host ліміт 3 спроби за 3 с. Три хибні спроби дають 401, четверта (з правильним паролем) і п'ята (невідомий користувач) — 429 з однаковою формою відповіді; після очікування 3,5 с вхід знову дає 204.
- У тестовій фабриці за замовчуванням ліміт 1000, щоб інші тести не вичерпували квоту (усі клієнти тестового host мають спільний ключ `"unknown"`).
- Події: `Auth event {EventType}: result {Result}, user {UserId}, at {OccurredAtUtc}, trace {TraceId}` для `login` (`success` / `failure` / `rate_limited`) і `logout`.

**CSRF навчальний борг.** `SameSite=Lax` відсікає частину cross-site надсилань, але state-changing endpoints (`POST /api/incidents`, `/api/auth/logout`, `/api/auth/register`) не мають антипідробного токена. Це усвідомлений навчальний борг до ЛР 6. Ні `HttpOnly`, ні CORS CSRF не усувають.

**Обрані поглиблення (відмінний).**
- (а) Втрата чинності старого сеансу після серверної події: `UpdateSecurityStampAsync` → наступний запит тією самою cookie дає 401.
- (б) Готовність hasher до оновлення параметрів: старий hash (10 000 ітерацій) → `SuccessRehashNeeded`; після успішного login hash у БД змінюється і відповідає поточним параметрам.
- Бонус: стислий threat analysis login flow (нижче).

## Докази

### Маршрут довіри

Запит входу (`POST /api/auth/login`) → стандартна перевірка пароля `SignInManager.PasswordSignInAsync` (Identity порівнює з `PasswordHash`) → захищена cookie `.AspNetCore.Identity.Application` (HttpOnly, SameSite=Lax, Secure за профілем) → браузер сам додає cookie до кожного наступного запиту → authentication handler (`UseAuthentication`) розшифровує й перевіряє cookie → claims у `HttpContext.User` → `UseAuthorization` перевіряє `.RequireAuthorization()` (анонімний запит → 401) → endpoint бере `NameIdentifier` з principal і встановлює `OwnerUserId` на сервері.

### Password verification і hash

Пароль перевіряється лише в `SignInManager.PasswordSignInAsync` (login) і виставляється через `UserManager.CreateAsync` (register); власного хешування немає. `PasswordHash` не потрапляє в жоден response DTO і не логується. Identity V3 зберігає в `PasswordHash` PBKDF2 (HMAC-SHA512, 100 000 повторень), випадкову сіль окремо для кожного акаунта та результат обчислення; тому два акаунти з однаковим паролем мають різні hash, а масовий перебір дорожчий за звичайне SHA-256.

### Чому client UserId не є доказом особи

Значення в body, query чи header (`ownerUserId`, `X-Demo-UserId`) — це лише заява клієнта; його може написати будь-хто. Довіра ґрунтується на cookie, яку сервер зашифрував своїми ключами: клієнт не може її підробити. Тому джерело ідентичності — тільки перевірений principal.

### Таблиця результатів

| ID | Рівень | Передумова/дія | Очікувано | Фактично | Безпечний доказ |
|---|---|---|---|---|---|
| T-01 | достатній | register з коректним DTO | safe 201 | 201, `Location: /api/me`, тіло лише `displayName`, `id`, `userName` | `T01_ValidRegistration_Returns201_WithSafeBody` пройшов; ручна проба `register-check.html`: `T-01 201 application/json` |
| T-02 | достатній | invalid / duplicate | safe rejection | 400 `application/problem+json` з ключем `errors` для 7 некоректних випадків (короткий пароль, без цифри, без великої літери, хибний email, недопустимі символи userName, порожній і 121-символьний displayName), користувача не створено; дублікат — 409 | `T02_Invalid_Returns400Problem_AndCreatesNoUser` (7 випадків), `T02_Duplicate_Returns409_WithoutRevealingWhichFieldClashed` пройшли; пароль у відповіді відсутній |
| T-03 | достатній | схема `identity_users` + Identity verifier | password не збережено відкрито | у `identity_users` стовпець `PasswordHash` типу `text`, стовпця для відкритого пароля немає; hash ≠ пароль, не містить пароль, hash двох акаунтів з однаковим паролем різні | вивід `\d identity_users` (без даних); `T03_StoredPassword_IsSaltedHash_NotPlaintext` пройшов |
| A-01 | достатній | анонімний POST `/api/incidents` і GET `/api/me` | 401, не redirect | 401, без `Location`, без `WWW-Authenticate`, `application/problem+json`; запис не створено | `A01_AnonymousCreate_Returns401_NotRedirect_AndCreatesNothing`, `A01_AnonymousMe_Returns401` пройшли |
| A-02 | достатній | login alice → `/api/me` | principal user | 200, `id` = Guid Alice, `userName` = `alice`, роль `Reporter`; точний набір полів `id`, `roles`, `userName` | `A02_LoginThenMe_ReturnsOnlyCurrentPrincipalSafeFields` пройшов |
| A-05 | достатній | Bob створює запис із forged owner Alice (`ownerUserId`, `OwnerUserId`, `createdByUserId`) та `X-Demo-UserId` Alice | новий owner = Bob; зайве поле ігнорується | 201; `OwnerUserId` у БД = Guid Bob, не Alice. Те саме у зворотний бік (Alice із forged Bob) | `A05_ForgedOwnerInJson_DoesNotChangeOwner` (2 випадки) пройшов; owner зчитано з БД за Id створеного запису |
| S-01 | достатній | аналіз credentials boundary | без витоків | див. «Перевірка витоку (S-01)» нижче | checklist |
| A-03 | добрий | cookie Alice + `X-Demo-UserId` Bob → `/api/me` | principal не змінюється | 200, `id` = Alice; без cookie з тим самим header — 401 | `A03_ForeignDemoHeader_DoesNotChangeCurrentUser`, `A03_DemoHeaderWithoutCookie_Returns401` пройшли |
| A-04 | добрий | create без owner у DTO (Alice і Bob) | owner = principal | `OwnerUserId` = Guid користувача, що ввійшов | `A04_CreateWithoutOwner_TakesOwnerFromPrincipal` (2 випадки) пройшов |
| A-06 | добрий | login → logout → захищений запит | 401 | logout 204 з `Set-Cookie`, що видаляє основну cookie; наступний `/api/me` тим самим клієнтом — 401 | `A06_Logout_ThenProtectedRequest_Returns401` пройшов |
| A-07 | добрий | невідомий користувач vs хибний пароль | однаковий зовнішній результат | обидва 401, однаковий `Content-Type` і однакові `type`, `title`, `status`, `detail`; `Set-Cookie` немає; `traceId` порівнюється окремо | `A07_UnknownUser_And_WrongPassword_GiveIdenticalExternalResult` пройшов |
| Browser flow | добрий | п'ять перевірок етапу 4 | state/profile/create/logout | (1) до входу «Стан: не ввійшли», профілю немає; (2) після login Alice — «Сеанс активний», поля Alice; (3) create-запит без поля власника → 201; (4) після logout профіль очищено, повторний `/api/me` → 401; (5) `localStorage`/`sessionStorage` не використовуються, у Console немає credentials | спостереження в `auth-lab.html` (DevTools Network/Application); значення cookie та payload з паролем не фіксувалися |
| Duplicate | добрий | обраний контракт і регресія | послідовний 400/409 | 409 для збігу userName і для збігу email з ідентичною формою відповіді | `T02_Duplicate_Returns409_WithoutRevealingWhichFieldClashed` пройшов |
| Cookie flags | добрий | тест фактичних flags | контракт фіксованого профілю | HTTPS: `httponly`, `secure`, `samesite=lax`, `path=/`, без `expires`/`max-age`; HTTP у Development: без `secure` | `Lab03CookieFlagsTests` (2 тести) пройшли; DevTools: HttpOnly ✓, Secure порожній, Lax, Session |
| Rate limit і події | добрий | перевищення ліміту, відновлення, аналіз події | 429, відновлення після вікна, без credentials | 3×401 → 429 (навіть із правильним паролем і для невідомого користувача, однакова форма) → через 3,5 с 204; у журналі є події `rate_limited`, `failure`, `success`; жоден запис журналу (включно з EF) не містить ні правильного, ні хибного пароля | `Login_Exceeding_Limit_Returns429_Recovers_AndEventsHaveNoCredentials` пройшов |
| Поглиблення (а) | відмінний | подія безпеки → старий сеанс | cookie перестає діяти | після `UpdateSecurityStampAsync` той самий клієнт одержує 401 на `/api/me`; у тестовому host `ValidationInterval = 0` (за замовчуванням перевірка раз на 30 хв) | `SecurityStampUpdate_InvalidatesExistingSession_OnNextRequest` пройшов |
| Поглиблення (б) | відмінний | старий hash → оновлення | `SuccessRehashNeeded`, потім новий hash | hash із 10 000 ітерацій: поточний hasher повертає `SuccessRehashNeeded`; після успішного login hash у БД змінено, перевірка поточним hasher дає `Success` (значення hash не друкувалися) | `WeakerLegacyHash_IsRehashed_AfterSuccessfulLogin` пройшов |

### CP-01, CP-02, CP-03

- **CP-01.** Register request DTO / response DTO, виклик `UserManager.CreateAsync`, T-01, T-02, опис T-03 і відсутність чутливих полів показано в таблиці вище. Маршрут: JSON → DTO validation → `UserManager` → Identity store (`identity_users`) → безпечна відповідь.
- **CP-02.** Успішний login і `/api/me` (A-02), 401 до входу (A-01), однаковий 401 для невдалих входів (A-07), cookie options пояснено вище; A-03, A-06, тест flags виконано (рівень «Добре»+). Початковий стан до змін: `/api/me` без `X-Demo-UserId` повертав 501, з header — профіль названого користувача навіть без cookie (дефект довіри до заяви клієнта); після виправлення — 401 / профіль principal. У DevTools записано лише назву cookie та атрибути.
- **CP-03.** Анонімний POST `/api/incidents` → 401 (A-01); POST із cookie та підробленим `ownerUserId` → owner береться з principal (A-05). Сервер бере власника з `NameIdentifier` у `HttpContext.User`; hidden form field, header чи тіло запиту не є access control, бо ними керує клієнт.

### Перевірка витоку (S-01)

- Response DTO мають allowlist полів; тести `A02`, `T01` перевіряють точний набір властивостей (немає `passwordHash`, `securityStamp`, `email`, `password`, cookie, token).
- Відповіді на помилки (`400`, `401`, `409`, `429`) — Problem Details без пароля, hash, stack trace; тест `T02` перевіряє, що пароль не відлунюється.
- Події автентифікації не містять: пароль, `userName` (у `failure`), cookie, hash, token, `Authorization`, тіло запиту. Тест перехоплює весь журнал (включно з EF) і перевіряє відсутність паролів.
- Тести не використовують `Assert.Equal` / `Assert.Contains` на рядках із секретами, щоб xUnit не друкував їх у разі падіння.
- Перегляд `git diff v0.2.0` за ключовими словами `password`, `hash`, `cookie`, `token`, `secret`: збіги — лише імена полів, змінних і тестів; значень немає. Пароль навчальних акаунтів лише у змінній середовища `SeedUsers__Password`, у файлах проєкту, звіті й Git його немає. У `appsettings.Development.json` лежить пароль локального навчального контейнера PostgreSQL з baseline ЛР 1, а не секрет цієї роботи.
- Скріншоти й текст звіту не містять значень `Cookie` / `Set-Cookie`. Допоміжні `register-check.*` та `probe-check.*` у commit не додавалися.

### Канали перебору облікових записів і компроміси

| Endpoint | Канал | Обраний компроміс |
|---|---|---|
| `POST /api/auth/register` | 409 підтверджує, що обліковий запис із такими даними існує | Контракт дублікатів лишається (потрібен користувачеві); відповідь не вказує, яке поле зайняте; рекомендовано rate limit для register (у цій роботі впроваджено лише для login) |
| `POST /api/auth/login` | тіло відповіді однакове, але час відповіді відрізняється: для невідомого користувача Identity не хешує пароль | Залишковий ризик; зменшує rate limit (10/хв на IP); вирівнювання часу не виконувалося |
| `POST /api/auth/login` (429) | відповідь 429 однакова для будь-якого імені | Ліміт діє до перевірки пароля і не залежить від існування акаунта |

### Обґрунтування partition key і полів події

**Ключ rate limit — IP-адреса.** Ключ за введеним іменем користувача дав би змогу стороннім навмисно заблокувати чужий акаунт; пара `email:password` як ключ неприйнятна (секрет у ключі). Ключ за IP обмежує підбір з одного джерела. Недолік: користувачі за спільним NAT діляють квоту, тому ліміт щедрий (10 спроб за 60 с). Лічильники in-memory, тому це локальний навчальний контрзахід, а не захист розподіленої системи.

**Виключені з події поля:** пароль, hash, cookie, token, `Authorization`, усе тіло запиту й `userName` у невдалому вході (у це поле користувачі іноді вводять пароль). У події є лише: тип, результат, час UTC, `userId` (Guid, тільки для успішних подій), `trace id`.

### Threat analysis login flow (поглиблення)

- **Активи:** облікові дані користувачів; cookie сеансу; відомості про існування облікових записів; цілісність власника створюваних ресурсів.
- **Entry points:** `POST /api/auth/login`, `POST /api/auth/register`, cookie `.AspNetCore.Identity.Application` у кожному запиті, `POST /api/incidents`.
- **Trust boundaries:** браузер ⟷ API (усе, що надходить від клієнта, недовірене, зокрема `ownerUserId` і `X-Demo-UserId`); API ⟷ PostgreSQL; тестовий host ⟷ реальна навчальна БД.
- **Реалістична загроза:** онлайн-підбір пароля / credential stuffing через `/api/auth/login`.
- **Контрзаходи:** PBKDF2-хеш із сіллю й високою вартістю; політика пароля ≥10 символів; однаковий 401 для невідомого користувача й хибного пароля; rate limit 10 спроб за 60 с на IP із відповіддю 429; обмеження довжини вхідних даних; події автентифікації без секретів для виявлення підбору.
- **Залишковий ризик:** розподілений підбір із багатьох IP обходить ліміт за IP; користувачі за спільним NAT можуть тимчасово втратити вхід; timing-канал для перебору імен; in-memory лічильники не діляться між інстансами та скидаються при перезапуску; немає багатофакторної автентифікації; cookie, яку вже скопіювали, діє до завершення строку або події безпеки (звичайний logout її не відкликає); CSRF-захисту немає. Реалізація є навчальною й не претендує на рівень промислової системи.

