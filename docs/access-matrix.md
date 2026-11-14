# Матриця доступу ЛР04 (baseline 2-A, рівень: відмінний)

**Політика відмов.** Не автентифікований → `401` (Problem Details, не redirect).
Чужий ресурс, який principal не має права читати, → `404` «Інцидент не знайдено»,
**той самий helper**, що й для неіснуючого id (збігаються status, Content-Type, тіло, окрім traceId).
`403` лише коли principal має право *читати* ресурс, але не має права на *конкретну дію*
(існування ресурсу йому вже відоме). Правило однакове для details/update/delete/triage/child/search/summary.
Обґрунтування: існування чужого інциденту — це розкриття інформації; 403 дозволив би перебір id.

| Дія | Рівень | Анонім | Reporter | Analyst | Administrator | Власник має значення? | Стан реалізації |
|---|---|---|---|---|---|---|---|
| Перегляд списку | добрий | deny, 401 | лише власні | усі | лише власні (як owner; додаткових прав немає) | Так для Reporter | `IncidentQueries.GetListAsync` (scoping); A-05 |
| Пошук `GET /api/incidents/search` | відмінний (A-11) | deny, 401 | лише власні | усі | лише власні | Так для Reporter | scoping у `Lab02Endpoints` до ILike/сортування/`Take(50)`; A-11 |
| Зведення `GET /api/incidents/severity-summary` | відмінний (A-11) | deny, 401 | лише власні | усі | лише власні | Так для Reporter | scoping до `GroupBy`; A-11 |
| Перегляд деталей | достатній | deny, 401 | owner — allow 200; non-owner — deny 404 | allow 200 (читання для аналізу, без права зміни) | owner — allow; чужий — deny 404 | Так | `IncidentOperations.Read` у handler; A-02, A-03, A-03R, A-10 |
| Створення | успадкований baseline | deny, 401 | allow for self, 201 | allow for self | allow for self (baseline ЛР 3, не змінювався) | Сервер призначає власника з principal | `Lab03IncidentOwnerTests` |
| Update content `PUT /api/incidents/{id}` | добрий | deny, 401 | owner — allow 204 (лише title/description); non-owner — 404 | deny 403 (бачить, але не редагує) | чужий — 404; власний — allow | Так | `Update` у handler; A-04, A-08a |
| Delete `DELETE /api/incidents/{id}` | добрий | deny, 401 | owner і Status=New — allow 204; owner не-New — 403; non-owner — 404 | deny 403 | чужий — 404 | Так | `Delete` у handler; A-04 |
| Зміна status `POST /api/incidents/{id}/triage` | добрий | deny, 401 | deny: owner — 403, non-owner — 404; **обидва з audit** | allow лише `New → Triaged` (204); інший status — 409 | deny (немає ролі): 403/404 + audit | Ні (вирішує роль), але ресурс спершу має бути читабельним | `Triage` у handler + перевірка status; A-06, A-07, A-09 |
| Internal comment `GET /api/incident-comments/{id}` і `comments` у details | добрий | deny, 401 | deny, 404; у details не показується | allow, якщо дозволено Read батьківського incident | deny, 404 | Ні; доступ до parent перевіряється окремо | `ReadInternalComments` + `Read` parent; A-12 |
| Export/audit | відмінний, якщо flow існує | — | — | — | — | — | не застосовується (flow немає) |

Administrator не має автоматичних прав: предметне правило baseline 2-A не називає для нього операцій над Incident,
тому будь-що, чого немає в таблиці, — deny (least privilege).