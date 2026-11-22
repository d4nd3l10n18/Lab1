using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Npgsql;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Security;

namespace SecureLab.Api.Tests;

// Each test creates an independent disposable PostgreSQL database and anchor.
// Never runs SQL tampering against the user's development/evidence database.
public sealed class AuditIntegrityTests
{
    private sealed class Sandbox : IAsyncDisposable
    {
        private readonly string _name = "lr06_audit_" + Guid.NewGuid().ToString("N");
        private readonly string _folder = Path.Combine(Path.GetTempPath(), "audit06-" + Guid.NewGuid().ToString("N"));
        private readonly string _admin;
        private readonly string _dbConnection;
        private readonly IConfiguration _config;
        public string AnchorPath => Path.Combine(_folder, "anchor.json");

        private Sandbox(string sourceConnection)
        {
            var cs = new NpgsqlConnectionStringBuilder(sourceConnection);
            var admin = new NpgsqlConnectionStringBuilder(sourceConnection) { Database = "postgres" };
            _admin = admin.ConnectionString;
            cs.Database = _name;
            _dbConnection = cs.ConnectionString;
            Directory.CreateDirectory(_folder);
            _config = new ConfigurationBuilder().AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["AuditIntegrity:AnchorPath"] = AnchorPath,
                    ["AuditIntegrity:HmacKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                }).Build();
        }

        public static async Task<Sandbox> CreateAsync()
        {
            var cfg = new ConfigurationBuilder()
                .AddJsonFile(Path.Combine(AppContext.BaseDirectory, "appsettings.Development.json"), optional: true)
                .AddEnvironmentVariables().Build();
            var source = cfg.GetConnectionString("SecureLab")
                ?? throw new InvalidOperationException("Set ConnectionStrings__SecureLab outside Git for integration tests.");
            var cs = new NpgsqlConnectionStringBuilder(source);
            if (cs.Host is not ("127.0.0.1" or "localhost" or "::1"))
                throw new InvalidOperationException("Audit integration tests require local PostgreSQL.");
            var sandbox = new Sandbox(source);
            await using (var conn = new NpgsqlConnection(sandbox._admin))
            {
                await conn.OpenAsync();
                await using var cmd = new NpgsqlCommand($"CREATE DATABASE \"{sandbox._name}\"", conn);
                await cmd.ExecuteNonQueryAsync();
            }
            await using (var db = sandbox.NewDb())
                await db.Database.MigrateAsync();
            await using (var db = sandbox.NewDb())
                await new AuditIntegrity(sandbox._config, db).InitializeEmptyAsync();
            return sandbox;
        }

        public SecureLabDbContext NewDb() => new(new DbContextOptionsBuilder<SecureLabDbContext>()
            .UseNpgsql(_dbConnection).Options);

        public AuditIntegrity Audit(SecureLabDbContext db) => new(_config, db);

        public async ValueTask DisposeAsync()
        {
            await using (var connection = new NpgsqlConnection(_admin))
            {
                await connection.OpenAsync();
                await using var command = new NpgsqlCommand(
                    $"DROP DATABASE IF EXISTS \"{_name}\" WITH (FORCE)", connection);
                await command.ExecuteNonQueryAsync();
            }
            if (Directory.Exists(_folder)) Directory.Delete(_folder, true);
        }
    }

    private static AuditIntegrityEvent NewEvent(string action = "incident.triage") => new()
    {
        TimestampUtc = DateTimeOffset.UtcNow,
        EventType = "incident",
        EntityType = "Incident",
        EntityId = Guid.NewGuid().ToString("D"),
        Action = action,
        Outcome = "success",
        TraceId = Guid.NewGuid().ToString("N")
    };

    private static async Task AddAsync(Sandbox sandbox, int count = 3)
    {
        for (var i = 0; i < count; i++)
        {
            await using var db = sandbox.NewDb();
            await sandbox.Audit(db).AppendAsync(NewEvent());
        }
    }

    private static async Task AssertViolationAsync(Sandbox sandbox)
    {
        await using var db = sandbox.NewDb();
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => sandbox.Audit(db).VerifyAsync());
    }

    [Fact]
    public async Task AUD_01_ValidChain_AndAnchor_Verify()
    {
        await using var sandbox = await Sandbox.CreateAsync();
        await AddAsync(sandbox);
        await using var db = sandbox.NewDb();
        var report = await sandbox.Audit(db).VerifyAsync();
        Assert.Equal(3, report.Count);
        Assert.Equal(3, report.LastSequence);
        var list = await db.AuditIntegrityEvents.OrderBy(x => x.SequenceNumber).ToListAsync();
        Assert.Equal(new long[] { 1, 2, 3 }, list.Select(x => x.SequenceNumber));
        Assert.Equal("GENESIS", list[0].PreviousHmac);
        Assert.Equal(list[0].CurrentHmac, list[1].PreviousHmac);
        Assert.Equal(list[1].CurrentHmac, list[2].PreviousHmac);
    }

    [Fact]
    public async Task AUD_02_ChangeRow_IsDetected()
    {
        await using var sandbox = await Sandbox.CreateAsync();
        await AddAsync(sandbox);
        await using (var db = sandbox.NewDb())
            await db.AuditIntegrityEvents.Where(x => x.SequenceNumber == 2)
                .ExecuteUpdateAsync(s => s.SetProperty(e => e.Outcome, "tampered"));
        await AssertViolationAsync(sandbox);
    }

    [Fact]
    public async Task AUD_03_DeleteMiddle_IsDetected()
    {
        await using var sandbox = await Sandbox.CreateAsync();
        await AddAsync(sandbox);
        await using (var db = sandbox.NewDb())
            await db.AuditIntegrityEvents.Where(x => x.SequenceNumber == 2).ExecuteDeleteAsync();
        await AssertViolationAsync(sandbox);
    }

    [Fact]
    public async Task AUD_04_ReorderSequence_IsDetected()
    {
        await using var sandbox = await Sandbox.CreateAsync();
        await AddAsync(sandbox);
        await using (var db = sandbox.NewDb())
        {
            await db.AuditIntegrityEvents.Where(x => x.SequenceNumber == 1)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.SequenceNumber, 100L));
            await db.AuditIntegrityEvents.Where(x => x.SequenceNumber == 2)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.SequenceNumber, 1L));
            await db.AuditIntegrityEvents.Where(x => x.SequenceNumber == 100)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.SequenceNumber, 2L));
        }
        await AssertViolationAsync(sandbox);
    }

    [Fact]
    public async Task AUD_05_TailTruncation_IsDetectedByExternalAnchor()
    {
        await using var sandbox = await Sandbox.CreateAsync();
        await AddAsync(sandbox);
        await using (var db = sandbox.NewDb())
            await db.AuditIntegrityEvents.Where(x => x.SequenceNumber == 3).ExecuteDeleteAsync();
        await AssertViolationAsync(sandbox);
    }

    [Fact]
    public async Task AUD_06_ConcurrentAppends_AreContiguous()
    {
        await using var sandbox = await Sandbox.CreateAsync();
        var tasks = Enumerable.Range(0, 10).Select(async _ =>
        {
            await using var db = sandbox.NewDb();
            await sandbox.Audit(db).AppendAsync(NewEvent());
        });
        await Task.WhenAll(tasks);
        await using var verifyDb = sandbox.NewDb();
        var result = await sandbox.Audit(verifyDb).VerifyAsync();
        Assert.Equal(10, result.Count);
        var sequences = await verifyDb.AuditIntegrityEvents.OrderBy(x => x.SequenceNumber)
            .Select(x => x.SequenceNumber).ToListAsync();
        Assert.Equal(Enumerable.Range(1, 10).Select(x => (long)x), sequences);
    }

    [Fact]
    public async Task AUD_07_AuditPayload_DoesNotStoreSecretCanaries()
    {
        await using var sandbox = await Sandbox.CreateAsync();
        const string secret = "NeverStoreThisSyntheticPasswordOrCookie_06";
        var http = new DefaultHttpContext();
        http.TraceIdentifier = "trace-aud07";
        http.Request.Headers.Cookie = $"auth={secret}";
        http.Request.Headers.Authorization = $"Bearer {secret}";
        var safeEvent = AuditIntegrity.Describe(http, "auth.login", null, "denied");
        await using (var db = sandbox.NewDb())
            await sandbox.Audit(db).AppendAsync(safeEvent);
        await using var verifyDb = sandbox.NewDb();
        var records = await verifyDb.AuditIntegrityEvents.AsNoTracking().ToListAsync();
        Assert.Single(records);
        var json = System.Text.Json.JsonSerializer.Serialize(records);
        Assert.DoesNotContain(secret, json, StringComparison.Ordinal);
        foreach (var record in records)
        {
            Assert.DoesNotContain("password", record.Action, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("cookie", record.Action, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("token", record.Action, StringComparison.OrdinalIgnoreCase);
        }
        Assert.Equal(1, (await sandbox.Audit(verifyDb).VerifyAsync()).Count);
    }

    [Fact]
    public async Task AUD_08_StaleAnchor_SimulatedCrash_FailsClosed()
    {
        await using var sandbox = await Sandbox.CreateAsync();
        await AddAsync(sandbox, 1);
        var oldAnchor = await File.ReadAllBytesAsync(sandbox.AnchorPath);
        await AddAsync(sandbox, 1);
        // Simulate interruption after DB commit, before the new anchor is published.
        await File.WriteAllBytesAsync(sandbox.AnchorPath, oldAnchor);
        await AssertViolationAsync(sandbox);
        await using var db = sandbox.NewDb();
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => sandbox.Audit(db).AppendAsync(NewEvent()));
        Assert.Equal(2, await db.AuditIntegrityEvents.CountAsync());
    }

    [Fact]
    public async Task AUD_09_MissingOrForgedAnchor_IsRejected()
    {
        await using var sandbox = await Sandbox.CreateAsync();
        await AddAsync(sandbox, 1);
        var original = await File.ReadAllTextAsync(sandbox.AnchorPath);
        await File.WriteAllTextAsync(sandbox.AnchorPath, original.Replace("\"Signature\":\"", "\"Signature\":\"00"));
        await AssertViolationAsync(sandbox);
        File.Delete(sandbox.AnchorPath);
        await AssertViolationAsync(sandbox);
    }

    [Fact]
    public async Task AUD_10_FailingBusinessMutation_RollsBackAudit()
    {
        await using var sandbox = await Sandbox.CreateAsync();
        await using (var db = sandbox.NewDb())
            await Assert.ThrowsAsync<InvalidOperationException>(() => sandbox.Audit(db)
                .ExecuteAsync(NewEvent(), () => throw new InvalidOperationException("synthetic rollback")));
        await using var verifyDb = sandbox.NewDb();
        var report = await sandbox.Audit(verifyDb).VerifyAsync();
        Assert.Equal(0, report.Count);
    }
}
