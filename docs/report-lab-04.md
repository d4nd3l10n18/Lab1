# Звіт ЛР04. Авторизація, ролі, володіння ресурсом та IDOR/BOLA

- Автор/група: Стець Назар Максимович, КБ-43

## Контекст і межа виконання

- **Рівень:** відмінний («Відмінно»). Виконано достатній і добрий рівні, а також додатково A-11 (search і severity-summary), відокремлений resource-based handler та обґрунтування least privilege й залишкових ризиків.
- **Baseline:** 2-A (індивідуального варіанта немає).
- **Base tag `v0.3.0`:** `b34f25bd15ec3f72aaa99f967f8d33655f7062e3`. Гілка `lab/4-authorization` створена від цього тегу.
- **Головна action:** `GET /api/incidents/{id}` (details/read).
- **Політика відмов для чужого ресурсу:** `404`. Відповідь однакова для чужого й неіснуючого id (один helper `IncidentNotFound()`). `403` застосовується лише тоді, коли principal має право читати ресурс, але не має права на конкретну дію.
- **Маршрути рівня:**
  - `GET /api/incidents`;
  - `GET /api/incidents/{id}`;
  - `PUT /api/incidents/{id}`;
  - `DELETE /api/incidents/{id}`;
  - `POST /api/incidents/{id}/triage`;
  - `GET /api/incident-comments/{id}`;
  - `GET /api/incidents/search`;
  - `GET /api/incidents/severity-summary`;
  - `POST /api/incidents` (успадковано з ЛР 3, без змін).
- **Виправлення ЛР 3 після тегу:** не було. Тег `v0.3.0` не пересувався.


## Матриця і server-side рішення

Повна матриця лежить у `docs/access-matrix.md`. Ключові правила:

| Дія | Reporter | Analyst | Administrator |
|---|---|---|---|
| Список / search / summary | лише власні | усі | лише власні (як owner) |
| Details | owner — 200; чужий — 404 | 200 (читання для аналізу) | owner — 200; чужий — 404 |
| Update content | owner — 204; чужий — 404 | 403 | чужий — 404 |
| Delete | owner і Status=New — 204; owner не-New — 403; чужий — 404 | 403 | чужий — 404 |
| Triage (New → Triaged) | owner — 403 + audit; чужий — 404 + audit | 204; не-New — 409 | немає ролі: 403/404 + audit |
| Internal comment | deny, 404 | allow, якщо дозволено Read parent | deny, 404 |

Administrator не має автоматичних прав, бо предметне правило baseline 2-A не називає для нього операцій над Incident. Усе, що не дозволено явно, заборонено.

**Де реалізовано:**

- **Handler.** `Application/Incidents/IncidentAuthorization.cs`: `IncidentOperations` (Read, ReadInternalComments, Update, Delete, Triage) і `IncidentAuthorizationHandler`. Власник береться з verified principal (`ClaimTypes.NameIdentifier`, перетворений через `Guid.TryParse`), роль — із server-issued role claim (`IsInRole(DbSeeder.AnalystRole)`). Handler зареєстровано в `Program.cs`.
- **Query scoping.** `IncidentQueries.GetListAsync` і `GetSeveritySummaryAsync` (умова `isAnalyst || OwnerUserId == userId` стоїть у запиті до групування). У `Lab02Endpoints` умова стоїть у пошуку до `ILike`, сортування й `Take(50)`.
- **Порядок у mutating endpoint-ах:** завантажити tracked entity → Read (інакше 404) → рішення для дії (інакше 403) → валідація → зміна стану → `SaveChangesAsync`. Зміна стану можлива лише після дозволу.
- **DTO.** `UpdateIncidentRequest(Title, Description)` не містить `ownerUserId`, `status`, `severity` та `role`. Для create залишився `CreateIncidentRequest` з ЛР 3. Response DTO не розкриває `OwnerUserId`.
- **Child.** `GET /api/incident-comments/{id}` завантажує коментар разом із parent incident і виконує те саме централізоване рішення для parent. Internal comment додатково вимагає `ReadInternalComments`. У details internal comments показуються лише за результатом цього рішення.
- **Захист групи.** `/api/incidents` та `/api/incident-comments/{id}` мають `RequireAuthorization()`; `search` захищено окремо.

## Вразливий стан і PoC

- **Vulnerable commit:** `e2eebc8110987f7589a51d354ea1a3c45b0fd708`.
- **Контекст.** У стані після ЛР 3 група `/api/incidents` не мала `RequireAuthorization()`, а `IncidentQueries.GetDetailsAsync` шукав інцидент лише за `id`. Додаткових змін для створення вразливого стану не потрібно: код `v0.3.0` лишився без змін.
- **Гіпотеза.** Alice (Reporter) зможе прочитати інцидент Bob (Reporter), підставивши його id у той самий запит із тією самою cookie.

| Суб'єкт → ресурс | Очікування за матрицею | Фактично до виправлення |
|---|---|---|
| Alice → інцидент Alice | allow, 200 | login 204, read 200 |
| **Alice → інцидент Bob** | deny, 404 | **read 200, дані Bob (IDOR/BOLA)** |
| Morgan (Analyst) → інцидент Alice | allow, 200 | 200 |
| анонім → інцидент Bob | deny, 401 | **200** |

Останній рядок означає, що маршрут не вимагав навіть автентифікації. Це окрема проблема, яку усунуто тим самим виправленням (`RequireAuthorization()` на групі).

Докази «до» (без cookie й пароля) лежать у `docs/evidence-lab04/`:

- `poc-before-own.txt`;
- `poc-before-idor.txt`;
- `poc-before-analyst.txt`;
- `poc-before-anon.txt`;
- `a11-before.txt`.

Вивід `poc-before-idor.txt` у vulnerable-стані: `login_status=204`, `read_status=200`, JSON з `"id": "20000000-0000-0000-0000-000000000002"`, `"title": "Невідома спроба входу"` і `"ownerDisplayName": "Боб Мельник"`.

## Виправлення та retest

- **Fixed commit (= `v0.4.0`):** : `d79d6950767896b7c967a2b6c5e3ba0ea40a9a62`.
- **Retest того самого запиту Alice → Bob:** `login_status=204`, `read_status=404`, тіло Problem Details «Інцидент не знайдено» (даних Bob немає). Докази: `docs/evidence-lab04/poc-after-*.txt`.
- **Анонім → інцидент Bob:** 401, не HTML redirect.
- **Morgan → інцидент Alice:** 200 (entry-контракт ЛР 5 збережено).
- **Alice → власний інцидент:** 200 (позитивна регресія).
- **Для read DTO** не розкриває `ownerUserId`, `email` та інші внутрішні поля; для чужого ресурсу тіло відповіді не містить жодних даних Bob.
- **Для mutation:** після відмови стан читається повторно і не відрізняється від початкового (title, description, `UpdatedAtUtc`, owner, status, severity).
- **Узгодженість 404:** details, update, delete, triage і child endpoint для чужого ресурсу повертають той самий 404. Для неіснуючого id — те саме. Доказ A-10 нижче.

### Зміни в наявних тестах

Після захисту групи `/api/incidents` та `search` анонімні тести ЛР 1–2 (`IncidentEndpointTests`, `Lab02SecurityTests`, `SearchMechanicsTests`) переведено на клієнт після login користувача Morgan (Analyst). Він бачить усі записи, тому їхні очікування (5 інцидентів, O'Brien, порядок сортування, підсумок High 1 / Medium 1 / Low 3) лишилися чинними. Контракт «Alice бачить лише своє» перевіряють нові A-05 і A-11. Це зміна контракту за матрицею, а не послаблення перевірок.

## Доказова таблиця

Фактичні результати відповідають автоматичним тестам класу `Lab04AuthorizationTests` (усі тести зелені). У колонці «Фактично» вказано статуси, які ці тести підтверджують.

| ID | Рівень | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|---|
| A-01 | добрий | Анонімний доступ | немає authentication context | GET list, details, search, summary, comment; PUT, DELETE, POST triage | `401`, не HTML redirect | 401 для всіх 8 запитів; без `Location`; `Content-Type` не `text/html` | `A01_Anonymous_Returns401_NotRedirect` (Theory, 8 рядків) |
| A-02 | достатній, обов'язковий | Власний ресурс | Alice має власний seed resource | `GET /api/incidents/{aliceId}` | allow | 200; `id` збігається; поля `ownerUserId` немає | `A02_Alice_ReadsOwnDetails_WithoutOwnerFields` |
| A-03 | достатній, обов'язковий | Чужий ресурс | Alice, Bob resource | `GET /api/incidents/{bobId}` | `403` або `404` | 404; у відповіді немає даних Bob | `A03_Alice_ReadsBobDetails_Returns404_WithoutBobData` |
| A-03R | достатній, entry-контракт ЛР 5 | Дозволений аналітичний read | Morgan (`Analyst`), ресурс Alice | `GET /api/incidents/{aliceId}` | allow для аналізу; право довільної mutation не випливає | 200; update і delete від Morgan дають 403 (див. A-04) | `A03R_Morgan_Analyst_ReadsAliceDetails`; `.http` Morgan → Alice |
| A-04 | добрий | Чужий ресурс, усі змінювальні дії | Alice, Bob resource | PUT і DELETE з id Bob; PUT/DELETE від Analyst на Alice; DELETE не-New owner | deny, state без змін | Alice → Bob: 404 (PUT і DELETE); Analyst → Alice: 403; owner не-New delete: 403; title, description, `UpdatedAtUtc` без змін, інцидент існує | `A04_Alice_UpdateBob…`, `A04_Alice_DeleteBob…`, `A04_Analyst_UpdateAndDeleteAlice…`, `A04_Owner_DeleteNonNewIncident…` |
| A-05 | добрий | List | Alice | `GET /api/incidents` | лише дозволена множина | у списку є інцидент Alice, немає інцидентів Bob (…0002, …0004) | `A05_List_AsAlice_ContainsOnlyAliceIncidents` |
| A-06 | добрий | Вертикальне підвищення привілеїв | звичайний Reporter (owner) | `POST /api/incidents/{id}/triage` | deny, status без змін | 403; status лишається `New` | `A06_Reporter_Triage_IsForbidden_AndStatusStaysNew` |
| A-07 | добрий | Дозволена привілейована дія | Morgan (`Analyst`), інцидент зі статусом `New` | `POST …/triage` двічі | allow | перший виклик 204, status `Triaged`, запис у history (Morgan, New → Triaged); повторний 409 | `A07_Analyst_Triage_New_BecomesTriaged…` |
| A-08a | добрий | Overposting: контракт ігнорує невідоме поле | authenticated Alice; DTO не містить protected field | PUT з `ownerUserId` (Bob), `status=Resolved`, `severity=Critical`, `role=Administrator`, `isTransitionAllowed=true` | content змінюється, protected state — ні | 204; title змінився; owner = Alice, status = New, severity = Low | `A08a_ForgedOwnerStatusSeverityRole_AreIgnored…` |
| A-08b | добрий, альтернатива | Контракт відхиляє зайве поле | — | — | — | не виконувалось: обрано A-08a | — |
| A-09 | добрий | Аудиторська подія | denied privileged request (Alice triage) | знайти `authorization.denied` у виводі API | безпечна подія без секретів | подія містить subject, action, resource, result, UTC і той самий `traceId`, що в тілі 403; пароля й cookie немає | `A09_DeniedTriage_WritesSafeAuditEvent…`; рядок із терміналу API (нижче) |
| A-10 | добрий, політика `404` | Нерозрізнюваність 404 | один authenticated client (Alice); id Bob і випадковий Guid | два однакові запити, змінено лише id | однакові status, `Content-Type`, тіло без `traceId`/`requestId` | обидва 404, `application/problem+json`, тіла збігаються | `A10_ForeignAndUnknownId_AreIndistinguishable404` |
| A-11 | відмінний | Власні endpoint-и ЛР 1–2 | Alice; Morgan для порівняння | `severity-summary` і `search?q=O'Brien` | лише дозволена множина | summary Alice: Medium 1, Low 2, без High; search Alice: `[]`; search Morgan: 1 запис | `A11_SeveritySummary_AsAlice…`, `A11_Search_AsAlice…`; `a11-after.txt` |
| A-12 | добрий | Child resource та internal comment | Alice (Reporter); `comment-2` (до інциденту Bob); `comment-3` (internal, до інциденту Alice) | `GET /api/incident-comments/{id}` і details Alice | direct child access — deny; internal не потрапляє у відповідь Reporter | `comment-2` → 404; `comment-3` → 404; у details Alice немає `comment-3`; Analyst бачить `comment-3` напряму (200) і в details | `A12_Alice_ReadsCommentOnBobIncident…`, `A12_Reporter_DoesNotSeeInternalComment…`, `A12_Analyst_SeesInternalComment…` |

## Основний finding і залишковий ризик

1. **Контекст.** Ресурс Incident, дія details/read; локальні суб'єкти Alice, Bob (Reporter), Morgan (Analyst), Admin. Усі дані штучні, стенд локальний.
2. **Гіпотеза.** Alice зможе виконати read над інцидентом Bob підстановкою id (горизонтальне підвищення привілеїв).
3. **Стан до.** З тією самою cookie Alice запит із id Bob повертав 200 і дані Bob; анонімний запит теж повертав 200. Vulnerable commit: `e2eebc8110987f7589a51d354ea1a3c45b0fd708`. Докази: `docs/evidence-lab04/poc-before-*.txt`.
4. **Першопричина.** `IncidentQueries.GetDetailsAsync` шукав інцидент лише за `id`, а група `/api/incidents` не мала `RequireAuthorization()`. Порівняння з principal і рішення для ресурсу були відсутні. Відповідь «id передано в URL» механізм описує, але не дефект: сам id у URL нормальний, дефект у відсутності серверної перевірки права.
5. **Виправлення.**
   - Група захищена `RequireAuthorization()`.
   - Рішення для ресурсу централізоване в `IncidentAuthorizationHandler` (owner з principal, роль із серверного claim).
   - List, search і summary обмежені за суб'єктом у самому запиті (query scoping).
   - Межі DTO: `UpdateIncidentRequest` містить лише `title` і `description`; owner, status, severity і role визначає сервер; наступний status для triage встановлює сервер.
   - Єдина політика 404 (один helper).
6. **Retest.** Той самий запит Alice → Bob повертає 404 без даних Bob; update і delete не змінюють стан; анонім отримує 401.
7. **Позитивна регресія.** Alice читає, оновлює і (у статусі New) видаляє власний інцидент; Morgan читає інциденти для аналізу й виконує `New → Triaged`; старі тести ЛР 1–3 зелені після переведення на login.
8. **Залишковий ризик.**
   - CSRF для cookie-authenticated mutating endpoint-ів не усунуто. До ЛР 6 це задокументований навчальний борг ЛР 3.
   - Роль зберігається в cookie, виданій при login. Після зміни ролі в БД потрібен повторний login або оновлення security stamp (за замовчуванням перевірка stamp періодична, не миттєва).
   - Optimistic concurrency для triage не реалізовано: сценарій одночасних переходів викладач не надавав, тож це «не застосовується».
   - Batch та export endpoint-ів у проєкті немає, тому «не застосовується».
   - Analyst бачить усі інциденти за дизайном матриці; обмеження обсягу (tenant чи команди) у baseline немає.
   - Видалення інциденту каскадно видаляє history. У baseline окремого аудиту видалень немає.

**Схема рішення.** Запит Alice з id → cookie формує перевірений principal → завантаження entity (для list, search і summary — обмежений запит) → правило owner/role/status у handler → дозвіл або погоджена відмова (404 для чужого, 403 для відомого, але недозволеного) → відповідь; зміна стану лише після дозволу.

## Browser flow

1. Login `alice` на `/auth-lab.html`.
2. Головна сторінка `http://localhost:5080`: список показує лише власні інциденти Alice (три).
3. У DevTools Console виконано `loadIncidentDetails("20000000-0000-0000-0000-000000000002")` (id Bob). У блоці деталей з'явилося «Помилка: Інцидент не знайдено» 

`app.js` не змінювався: дозволений результат формується через `createTextElement(...)`, повідомлення відмови записується через `textContent`, `innerHTML` не використовується (перевіряє тест `ClientScript_DoesNotUseDangerousInnerHtmlSink`). Клієнт лише показує рішення сервера і не є механізмом контролю доступу. На знімках немає cookie, паролів, вкладок Application/Network.

## Добрий рівень: роль, transition, child, audit

- **Роль.** Єдиний вхід ролі — server-issued role claim у `HttpContext.User`, сформований при login. Роль із body, localStorage чи JavaScript не використовується.
- **Triage.** Рішення ухвалюється всередині endpoint, а не декларативною policy, щоб можна було записати audit. Порядок: tracked entity → `Read` (інакше audit і 404) → `Triage` (інакше audit і 403) → перевірка `Status == New` (інакше 409) → сервер встановлює `Triaged` і пише `IncidentStatusHistory` → `SaveChangesAsync`.
- **Child.** Morgan до коментаря Bob (`comment-2`): Reporter — 404; Analyst — 200 через авторизацію parent. Internal comment (`comment-3`) до інциденту Alice: Reporter (навіть owner) — 404 напряму й відсутній у details; Analyst — 200 і присутній у details.
- **Audit.** Поля: subject (з principal), action, resource, result, час (формує сервер), traceId (`Activity.Current?.Id ?? TraceIdentifier`, збігається з Problem Details). Password, cookie, token, повний body і stack trace не логуються.

## Відмінний рівень (додатково до всього доброго)

- **Відокремлений handler.** Усі рішення для окремого ресурсу (details, update, delete, triage, child) проходять через `IncidentAuthorizationHandler`. Endpoint-и містять лише послідовність «завантажити → запитати рішення → діяти».
- **A-11 — окремий finding «до → після».**
  - *До:* Alice (Reporter) при `severity-summary` бачила `High 1 / Medium 1 / Low 3` (усі п'ять інцидентів), а `search?q=O'Brien` знаходив інцидент Bob `…0004`. Обидва маршрути були поза групою й не вимагали навіть автентифікації.
  - *Причина:* запити не мали умови за суб'єктом, а маршрути — `RequireAuthorization()`; чужі агреговані дані й записи розкривалися.
  - *Виправлення:* `RequireAuthorization()`; умова `isAnalyst || OwnerUserId == userId` у самому запиті: у search до `ILike`, сортування й `Take(50)`, у summary до `GroupBy` (без фільтрації в пам'яті).
  - *Після:* summary Alice — `Medium 1 / Low 2`, без High; `search?q=O'Brien` — `[]`; для Morgan (Analyst) результати повні. Докази: `a11-before.txt` і `a11-after.txt`, тести A-11.
- **Least privilege.**
  - Reporter бачить і змінює лише власне й не має привілейованих переходів.
  - Analyst має читання всіх інцидентів і лише `New → Triaged`. Це потрібно для аналізу, але не дає права на update і delete чужого вмісту.
  - Administrator за предметним правилом baseline 2-A не має прав над Incident, тож без явного дозволу він працює як звичайний owner власних записів. Автоматичного обходу ownership немає.
- **Видимість ресурсу.** Політика 404 приховує існування чужого інциденту від перебору id. 403 повертається лише тоді, коли існування вже відоме суб'єкту (Analyst update/delete, owner triage, owner delete не-New).
- **A-06 і A-08a** успадковано з доброго рівня, повторних тестів не потрібно. Batch/export — «не застосовується». Concurrent transitions — «не застосовується» (сценарій не надавався).

## Перевірки, відтворення і подання

- **Команди** (з кореня проєкту; пароль навчальних акаунтів у змінній `SeedUsers__Password`, значення не зберігається):

  ```bash
  docker compose --env-file infra/.env -f infra/compose.yaml up -d --wait
  dotnet run --project src/SecureLab.Api -- --reset-database
  dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release
  dotnet run --project src/SecureLab.Api --launch-profile http
  ```

- **Результат:** build без помилок; тести: `total: 99, failed: 0`. Нові тести ЛР 4 — клас `Lab04AuthorizationTests`.
- **Recovery:** перед кожним фінальним прогоном виконується `--reset-database`, бо тести ЛР 2 порівнюють точний seed (як і в ЛР 3).
- **Seed.** Додано internal comment `comment-3` (`30000000-0000-0000-0000-000000000003`, до інциденту Alice, автор Morgan), перед vulnerable commit.
- **Hash-и:**
  - vulnerable: `e2eebc8110987f7589a51d354ea1a3c45b0fd708`;
  - fixed / `v0.4.0`: `d79d6950767896b7c967a2b6c5e3ba0ea40a9a62`.
- **Гілка:** `lab/4-authorization`. Репозиторій приватний; vulnerable commit не публікувався у відкритому remote.
- **Невиконане/обмеження:** A-08b не виконувався (обрано A-08a). Окремого вразливого стану для update, delete, triage і child endpoint-ів не існувало: їх створено вже з авторизацією. Для CSRF див. залишковий ризик.
