using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Security;

// v1 canonical representation: a JSON array with fixed indexes; no input descriptions or secrets.
public sealed class AuditIntegrity(IConfiguration config, SecureLabDbContext db)
{
    private static readonly SemaphoreSlim ProcessLock = new(1, 1);
    private const long LockId = 6106062026;
    private readonly string _path = config["AuditIntegrity:AnchorPath"]
        ?? throw new InvalidOperationException("AuditIntegrity:AnchorPath is required");
    private byte[] Key => LoadKey();

    private byte[] LoadKey()
    {
        var secret = config["AuditIntegrity:HmacKey"]
            ?? throw new InvalidOperationException("AuditIntegrity:HmacKey is required");
        byte[] key;
        try { key = Convert.FromBase64String(secret); }
        catch (FormatException ex) { throw new InvalidOperationException("HMAC key must be base64", ex); }
        if (key.Length < 32) throw new InvalidOperationException("HMAC key must have at least 256 bits");
        return key;
    }

    public static AuditIntegrityEvent Describe(HttpContext http, string action, Guid? entityId, string outcome)
        => new()
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            EventType = action.StartsWith("auth.", StringComparison.Ordinal) ? "authentication" : "incident",
            ActorUserId = Guid.TryParse(http.User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null,
            EntityType = entityId.HasValue ? "Incident" : "Session",
            EntityId = entityId?.ToString("D", CultureInfo.InvariantCulture),
            Action = action,
            Outcome = outcome,
            TraceId = http.TraceIdentifier
        };

    private static string Canonical(AuditIntegrityEvent e)
        => JsonSerializer.Serialize(new object?[]
        {
            "audit-v1", e.SequenceNumber,
            e.TimestampUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture),
            e.EventType, e.ActorUserId?.ToString("D", CultureInfo.InvariantCulture), e.EntityType,
            e.EntityId, e.Action, e.Outcome, e.TraceId, e.PreviousHmac
        });

    private string Mac(string content) => Convert.ToHexString(HMACSHA256.HashData(Key, Encoding.UTF8.GetBytes(content)));
    private string AnchorMac(long seq, string hash) => Mac($"anchor-v1\n{seq}\n{hash}");
    private static bool SameHex(string a, string b)
    {
        try { return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(a), Convert.FromHexString(b)); }
        catch (FormatException) { return false; }
    }
    private sealed record Anchor(long Sequence, string Hash, string Signature);
    private Anchor ReadAnchor()
    {
        if (!File.Exists(_path)) throw new InvalidOperationException("Audit anchor missing: manual review required");
        var anchor = JsonSerializer.Deserialize<Anchor>(File.ReadAllText(_path))
            ?? throw new InvalidOperationException("Invalid anchor");
        if (!SameHex(anchor.Signature, AnchorMac(anchor.Sequence, anchor.Hash)))
            throw new InvalidOperationException("Anchor signature invalid");
        return anchor;
    }
    private void WriteAnchor(long sequence, string hash)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(_path))!;
        Directory.CreateDirectory(dir);
        var temp = _path + ".tmp";
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new Anchor(sequence, hash, AnchorMac(sequence, hash)));
        using (var file = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            file.Write(payload);
            file.Flush(flushToDisk: true);
        }
        // Atomic rename on the same filesystem. The anchor directory must be kept
        // outside Git and inaccessible to the PostgreSQL account.
        File.Move(temp, _path, true);
    }

    private async Task<List<AuditIntegrityEvent>> VerifyDbAsync(CancellationToken ct)
    {
        var events = await db.AuditIntegrityEvents.AsNoTracking().OrderBy(x => x.SequenceNumber).ToListAsync(ct);
        var hash = "GENESIS";
        long seq = 0;
        foreach (var e in events)
        {
            if (e.SequenceNumber != ++seq || e.PreviousHmac != hash || !SameHex(e.CurrentHmac, Mac(Canonical(e))))
                throw new InvalidOperationException($"Audit integrity violation at sequence {seq}");
            hash = e.CurrentHmac;
        }
        return events;
    }
    private void CheckAnchor(IReadOnlyList<AuditIntegrityEvent> records)
    {
        var anchor = ReadAnchor();
        var lastSeq = records.Count == 0 ? 0 : records[^1].SequenceNumber;
        var lastHash = records.Count == 0 ? "GENESIS" : records[^1].CurrentHmac;
        if (anchor.Sequence != lastSeq || anchor.Hash != lastHash)
            throw new InvalidOperationException("Audit anchor mismatch (including tail truncation / crash): investigate, never auto-heal");
    }
    private async Task<FileStream> AcquireFileLockAsync(CancellationToken ct)
    {
        var lockPath = _path + ".lock";
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(lockPath))!);
        for (var attempt = 0; attempt < 200; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try { return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) { await Task.Delay(50, ct); }
        }
        throw new TimeoutException("Could not acquire audit anchor writer lock");
    }

    // Execute mutation and audit insertion in the SAME DB transaction; publish anchor AFTER commit.
    // If the process crashes between commit and anchor, verification fails CLOSED, requiring operator review.
    public async Task ExecuteAsync(AuditIntegrityEvent record, Func<Task> mutation, CancellationToken ct = default)
    {
        await ProcessLock.WaitAsync(ct);
        try
        {
            using var fileLock = await AcquireFileLockAsync(ct);
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await db.Database.ExecuteSqlRawAsync($"SELECT pg_advisory_xact_lock({LockId})", ct);
            var records = await VerifyDbAsync(ct);
            CheckAnchor(records);
            await mutation();
            var previous = records.Count == 0 ? "GENESIS" : records[^1].CurrentHmac;
            record.SequenceNumber = records.Count == 0 ? 1 : records[^1].SequenceNumber + 1;
            record.PreviousHmac = previous;
            record.CurrentHmac = Mac(Canonical(record));
            db.AuditIntegrityEvents.Add(record);
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
            WriteAnchor(record.SequenceNumber, record.CurrentHmac);
        }
        finally { ProcessLock.Release(); }
    }
    public Task AppendAsync(AuditIntegrityEvent record, CancellationToken ct = default)
        => ExecuteAsync(record, () => Task.CompletedTask, ct);

    // Explicit provisioning ONLY when database chain is empty. Never accept an arbitrary existing chain.
    public async Task InitializeEmptyAsync(CancellationToken ct = default)
    {
        await ProcessLock.WaitAsync(ct);
        try
        {
            using var fileLock = await AcquireFileLockAsync(ct);
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await db.Database.ExecuteSqlRawAsync($"SELECT pg_advisory_xact_lock({LockId})", ct);
            if (await db.AuditIntegrityEvents.AnyAsync(ct))
                throw new InvalidOperationException("Nonempty audit DB: cannot initialize anchor");
            if (File.Exists(_path)) throw new InvalidOperationException("Anchor already exists");
            WriteAnchor(0, "GENESIS");
            await tx.CommitAsync(ct);
        }
        finally { ProcessLock.Release(); }
    }
    public async Task<(int Count, long LastSequence)> VerifyAsync(CancellationToken ct = default)
    {
        await ProcessLock.WaitAsync(ct);
        try
        {
            using var fileLock = await AcquireFileLockAsync(ct);
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await db.Database.ExecuteSqlRawAsync($"SELECT pg_advisory_xact_lock({LockId})", ct);
            var records = await VerifyDbAsync(ct);
            CheckAnchor(records);
            await tx.CommitAsync(ct);
            return (records.Count, records.Count == 0 ? 0 : records[^1].SequenceNumber);
        }
        finally { ProcessLock.Release(); }
    }
}
