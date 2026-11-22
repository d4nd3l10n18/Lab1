using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace SecureLab.Api.Tests;

// Every class fixture gets a disposable PostgreSQL database and a distinct anchor.
// Never runs against the user's evidence database.
public sealed class SecureLabApiFactory : WebApplicationFactory<Program>
{
    private readonly string _databaseName = "lr06_test_" + Guid.NewGuid().ToString("N");
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), "lr06-" + Guid.NewGuid().ToString("N"));
    private readonly string _connectionString;
    private readonly string _hmacKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    public SecureLabApiFactory()
    {
        var configuration = new ConfigurationBuilder()
            .AddJsonFile(Path.Combine(AppContext.BaseDirectory, "appsettings.Development.json"), optional: true)
            .AddEnvironmentVariables().Build();
        var original = configuration.GetConnectionString("SecureLab")
            ?? throw new InvalidOperationException("Set ConnectionStrings__SecureLab for isolated integration tests.");
        var cs = new NpgsqlConnectionStringBuilder(original);
        if (cs.Host is not ("127.0.0.1" or "localhost" or "::1"))
            throw new InvalidOperationException("Integration tests require a local PostgreSQL host.");
        var admin = new NpgsqlConnectionStringBuilder(original) { Database = "postgres" };
        Directory.CreateDirectory(_tempDir);
        using var connection = new NpgsqlConnection(admin.ConnectionString);
        connection.Open();
        using var cmd = connection.CreateCommand();
        // Database name is generated solely from a GUID, never from user input.
        cmd.CommandText = $"CREATE DATABASE \"{_databaseName}\"";
        cmd.ExecuteNonQuery();
        cs.Database = _databaseName;
        _connectionString = cs.ConnectionString;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["ConnectionStrings:SecureLab"] = _connectionString,
                ["AuditIntegrity:HmacKey"] = _hmacKey,
                ["AuditIntegrity:InitializeEmptyForTests"] = "true",
                ["AuditIntegrity:AnchorPath"] = Path.Combine(_tempDir, "anchor.json"),
                ["RateLimiting:Login:PermitLimit"] = "1000",
                ["RateLimiting:Search:PermitLimit"] = "10000",
                ["RateLimiting:Search:WindowSeconds"] = "10"
            }));
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing) return;
        try
        {
            var admin = new NpgsqlConnectionStringBuilder(_connectionString) { Database = "postgres" };
            using var connection = new NpgsqlConnection(admin.ConnectionString);
            connection.Open();
            using var cmd = connection.CreateCommand();
            cmd.CommandText = $"DROP DATABASE IF EXISTS \"{_databaseName}\" WITH (FORCE)";
            cmd.ExecuteNonQuery();
        }
        finally { if (Directory.Exists(_tempDir)) Directory.Delete(_tempDir, recursive: true); }
    }
}
