# LR06 — індивідуальне завдання: HMAC Audit Trail

**Погоджена тема:** «Захищений Audit Trail із перевіркою цілісності». Реалізація в `Security/AuditIntegrity.cs`, `Data/Entities/AuditIntegrityEvent.cs`, міграція `20261122180000_AuditIntegrityEvents.cs`, `Program.cs`, Identity/Incident endpoints. Це **розширення**, а не базовий структурований audit trail доброго рівня.

## Модель загроз

У порушника є право `UPDATE`/`DELETE` в PostgreSQL, але немає HMAC-ключа та доступу до anchor. HMAC-SHA256 **не** захищає від повної компрометації процесу або хоста. Приватний ключ не може лежати у Git.

## Формат v1 та правила

Для кожного рядка канонічний JSON-масив із незмінним порядком: `"audit-v1"`, `SequenceNumber`, UTC `TimestampUtc` у форматі `yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'`, `EventType`, `ActorUserId` або JSON null, `EntityType`, `EntityId` або null, `Action`, `Outcome`, `TraceId`, `PreviousHmac`. UTF-8 bytes → HMAC-SHA256. Початок chain: `SequenceNumber=1`, `PreviousHmac=GENESIS`. Результат HMAC — uppercase hex. `CurrentHmac` не входить до канонічного payload власного запису.

Anchor: JSON `Sequence`, `Hash`, `Signature=HMAC(key, "anchor-v1\n{sequence}\n{hash}")`; локальний файл поза БД. Операція: процесний lock + локальний file lock + PostgreSQL advisory transaction lock → verify chain & anchor → бізнес-мутація + audit record однією DB transaction → commit → тимчасовий файл, flush, атомарне перейменування anchor. Невідповідність блокує новий запис; **немає автоматичного re-anchor**.

## Налаштування (локальний тестовий стенд)

```bash
mkdir -p "$HOME/.config/securelab" "$HOME/.local/share/securelab-audit"
chmod 700 "$HOME/.config/securelab" "$HOME/.local/share/securelab-audit"
( umask 077; test -f "$HOME/.config/securelab/hmac-key.b64" || openssl rand -base64 32 > "$HOME/.config/securelab/hmac-key.b64" )
export AuditIntegrity__HmacKey="$(cat "$HOME/.config/securelab/hmac-key.b64")"
export AuditIntegrity__AnchorPath="$HOME/.local/share/securelab-audit/anchor.json"
# Лише якщо таблиця AuditIntegrityEvents порожня, anchor ще не існує:
dotnet run --project src/SecureLab.Api -- --audit-init
dotnet run --project src/SecureLab.Api -- --audit-verify
```

Пароль seed, cookie, HMAC-key і token НЕ записуйте у README, `docs/evidence-lab06`, скриншоти або git. **Не повторюйте `--audit-init` на існуючому журналі.**

## Перевірки

| ID | Подія | Очікувана реакція | Автоматичний тест |
|---|---|---|---|
| AUD-01 | Незмінений журнал, 3 події | verification OK, sequence 1–3 | `AUD_01_ValidChain_AndAnchor_Verify` |
| AUD-02 | UPDATE Outcome рядка №2 | HMAC violation | `AUD_02_ChangeRow_IsDetected` |
| AUD-03 | DELETE середнього рядка | gap / previous-HMAC violation | `AUD_03_DeleteMiddle_IsDetected` |
| AUD-04 | swap SequenceNumber | sequence/MAC violation | `AUD_04_ReorderSequence_IsDetected` |
| AUD-05 | DELETE останнього рядка | anchor mismatch | `AUD_05_TailTruncation_IsDetectedByExternalAnchor` |
| AUD-06 | 10 одночасних appends | всі записи є, 1…10 без дублів | `AUD_06_ConcurrentAppends_AreContiguous` |
| AUD-07 | огляд allowlist полів | не зберігаються credentials | `AUD_07_AuditPayload_DoesNotStoreSecretCanaries` + ручний огляд |
| AUD-08 | old anchor після DB commit | fail closed, append refused | `AUD_08_StaleAnchor_SimulatedCrash_FailsClosed` |
| AUD-09 | forged/missing anchor | verification refused | `AUD_09_MissingOrForgedAnchor_IsRejected` |
| AUD-10 | виняток бізнес-операції | rollback транзакції | `AUD_10_FailingBusinessMutation_RollsBackAudit` |

**Важлива точність:** AUD-08 симулює стан після crash шляхом повернення попереднього anchor; це не процесне kill-testing. AUD-07 перевіряє allowlist-модель і відсутність маркера, але не є повним аналізом усіх logging sinks.

## Окреме середовище інтеграційних тестів

`AuditIntegrityTests` створює одноразову PostgreSQL БД `lr06_audit_<GUID>` і anchor у `Path.GetTempPath()`. Тестова роль PostgreSQL повинна мати `CREATEDB`; основну БД `securelab` тести **не** змінюють. Якщо використовується інша PostgreSQL, задайте `ConnectionStrings__SecureLab` поза Git. На failure перевірити й прибрати залишену тестову БД вручну.

```bash
dotnet test SecureLab.sln -c Release --filter 'FullyQualifiedName~AuditIntegrityTests' --logger 'console;verbosity=normal'
```

## Залишкові ризики

1. Crash після DB commit, до publication anchor: верифікація **fail closed**, автоматичного відновлення немає; потрібен документований ручний incident response і backups.
2. Crash після rename, до durable sync каталогу anchor: файлове durability/`fsync` каталогу не доведено; потрібен окремий OS-level тест.
3. Немає довіри до HMAC у разі повної компрометації API/ключа.
4. Передавання audit status через HTTP 500 може видавати неочікуваний результат для cookie session; потрібна окрема fault-injection регресія для login.
5. У DB reset command немає координованого відновлення HMAC audit provenance; не використовувати reset поверх фінальних доказів.
