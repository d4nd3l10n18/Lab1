# Звіт до лабораторної роботи № 1

## 1. Ідентифікація стану

- Варіант: 2-A «Трекер інцидентів».
- Робоча гілка: `lab/1-system`; основна: `master`.
- Фінальний тег: `v0.1.0`.
- Commit hash: `916009e85fa6e3b13ff23c144cca455478224794`.

## 2. Змінений маршрут

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

## 3. Виконані зміни

- severity-summary замість 501: DTO, query (AsNoTracking, GroupBy, Count, ToListAsync), endpoint через DI.
- Політика: лише наявні групи; порядок за критичністю; необов'язковий `?status=` з allowlist.
- Клієнт: кнопка, стани «Завантаження…», «Даних немає», безпечна помилка; DOM через textContent.
- Структуроване журналювання з TraceId без чутливих даних.
- Знахідки starter: `status=1`/`New,Triaged` та SPA-fallback для `/api/...` (стан до/після нижче).

## 4. Перевірка

| ID | Дія | Очікувано | Фактично |
|---|---|---|---|
| T-01 | `GET /health` | 200 | 200 OK, `{"status":"ready"}` |
| T-02 | `GET /api/incidents?status=Triaged` | 200, відфільтрований список | HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Tue, 29 Sep 2026 09:28:15 GMT
Server: Kestrel
Transfer-Encoding: chunked
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

[{"id":"20000000-0000-0000-0000-000000000001","title":"Підозрілий лист із вкладенням","severity":"Medium","status":"Triaged","occurredAtUtc":"2026-08-01T08:30:00+00:00","createdAtUtc":"2026-08-01T09:00:00+00:00"}] |
| T-03 | `GET /api/incidents?status=Resolved` | 200, `[]` | HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Tue, 29 Sep 2026 09:29:14 GMT
Server: Kestrel
Transfer-Encoding: chunked
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
 |
| T-04 | `GET /api/incidents/99999999-9999-9999-9999-999999999999` | 404 Problem Details | HTTP/1.1 404 Not Found
Content-Type: application/problem+json
Date: Tue, 29 Sep 2026 09:30:34 GMT
Server: Kestrel
Transfer-Encoding: chunked
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{"type":"https://tools.ietf.org/html/rfc9110#section-15.5.5","title":"Інцидент не знайдено","status":404,"detail":"Інцидент '99999999-9999-9999-9999-999999999999' не існує.","traceId":"00-c4468f156e2b662e8e0b512e19326aa8-daf4daad15a01e70-00"} |
| T-05 | `GET /api/incidents?status=Unknown` | 400 Validation Problem Details | HTTP/1.1 400 Bad Request
Content-Type: application/problem+json
Date: Tue, 29 Sep 2026 09:31:24 GMT
Server: Kestrel
Transfer-Encoding: chunked
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

{"type":"https://tools.ietf.org/html/rfc9110#section-15.5.1","title":"One or more validation errors occurred.","status":400,"errors":{"status":["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]},"traceId":"00-cce60e7cb20e05492a1d6d7c13562c50-3e206c1250a74ec1-00"} |
| T-06 | `GET /api/incidents/severity-summary` | 200; High, Medium, Low по 1; без Critical; порядок за критичністю | 200 OK, `application/json; charset=utf-8`, `[{"severity":"High","count":1},{"severity":"Medium","count":1},{"severity":"Low","count":1}]` |
| T-07 | вибрати статус і натиснути «Показати підсумок» у клієнті | список у DOM, що змінюється відповідно до фільтра; стани завантаження, порожньо, помилка | Перевірено всі значення фільтра: Усі → Груп:3 (High:1, Medium:1, Low:1); New → Груп:1 (Low:1); Triaged → Груп:1 (Medium:1); InProgress → Груп:1 (High:1); Resolved → «Даних немає»; Closed → «Даних немає». Стан «Завантаження…» видно при throttling Slow 4G; при зупиненому API — «Не вдалося завантажити підсумок. Спробуйте пізніше.» |
| T-08 | reset seed, повторити T-02 і T-06 | той самий результат |Reset виконано успішно (TRUNCATE ... RESTART IDENTITY CASCADE, повторне заповнення seed). Після reset summary знову дав 3 групи (High:1, Medium:1, Low:1), усі 15 тестів пройшли. |
| T-09 | `GET .../severity-summary?status=Triaged` | 200, `[{"severity":"Medium","count":1}]` | 200 OK, `[{"severity":"Medium","count":1}]` |
| T-10 | `GET .../severity-summary?status=Resolved` | 200, `[]` | 200 OK, `[]` |
| T-11 | `GET .../severity-summary?status=Unknown` | 400 | 400 Bad Request, `application/problem+json` |
| T-12 | `GET .../severity-summary?status=1` | 400 | 400 Bad Request, `application/problem+json` |


## 5. Знахідки в starter

### Знахідка 1: Недостатня валідація параметра `status`

* **Проблема:** До виправлення запит `GET /api/incidents?status=1` повертав `200 OK` зі списком: `Enum.TryParse` приводив числове значення до enum, а `Enum.IsDefined` валідував його як коректне. Аналогічно проходили значення на кшталт `New,Triaged`.
* **Причина:** Перевірка спиралася на штатний парсинг enum, а не на явний перелік дозволених значень (`IncidentEndpoints.GetListAsync`).
* **Виправлення:** Реалізовано спільний для списку (list) та підсумку (summary) allowlist допустимих назв статусів у `IncidentEndpoints.TryParseStatus`.
* **Результат після виправлення:** Запити `?status=1` та `?status=New,Triaged` повертають код `400` (`application/problem+json`).

### Знахідка 2: Некоректне повернення HTML для невідомого API-маршруту

* **Проблема:** До внесення змін запит `GET /api/does-not-exist` повертав `200 OK` із заголовком `Content-Type: text/html` через запасний маршрут `MapFallbackToFile("index.html")`, внаслідок чого API-клієнт не міг відрізнити помилку від успішного виконання.
* **Причина:** Запасний маршрут фронтенду перехоплював усі запити, включно з префіксом `/api/`.
* **Виправлення:** У `Program.cs` перед запасним маршрутом додано обробник для `/api/{**path}`.
* **Результат після виправлення:** Повертається статус `404` з форматом `application/problem+json`.

## 6. Автоматична перевірка

```
Test summary: total: 15, failed: 0, succeeded: 15, skipped: 0, duration: 3.5s
Build succeeded in 5.4s
```

## 7. Перегляд diff

Перед кожним commit переглянуто `git status`, `git diff`, `git diff --staged`: секретів,
`.env`, cookies, токенів, дампів і журналів немає. ВСТАВ дату.

## 8. Висновок

Реалізація ендпоінта `GET /api/incidents/severity-summary` повністю відповідає контракту: повертає статус `200` із фіксованим порядком угруповання, використовує виділений DTO без надлишкових полів, містить allowlist для параметра `status` та забезпечує безпечний рендеринг у DOM. 

Під час виконання завдання було знайдено та усунуто два дефекти базового шаблону (starter):
* недостатню валідацію `status`;
* повернення HTML-сторінки замість помилки для невідомих маршрутів `/api/...`.

Обидва виправлення покриті регресійними тестами. Стан середовища повністю відтворюється за допомогою seed/reset, а фінальний результат закріплено тегом `v0.1.0`.