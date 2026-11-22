using System;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SecureLab.Api.Data;
#nullable disable
namespace SecureLab.Api.Data.Migrations;
[DbContext(typeof(SecureLabDbContext))]
[Migration("20261122180000_AuditIntegrityEvents")]
public partial class AuditIntegrityEvents : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "AuditIntegrityEvents",
            columns: table => new
            {
                SequenceNumber = table.Column<long>(type: "bigint", nullable: false),
                TimestampUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                EventType = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                ActorUserId = table.Column<Guid>(type: "uuid", nullable: true),
                EntityType = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                EntityId = table.Column<string>(type: "character varying(80)", maxLength: 80, nullable: true),
                Action = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                Outcome = table.Column<string>(type: "character varying(24)", maxLength: 24, nullable: false),
                TraceId = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: false),
                PreviousHmac = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                CurrentHmac = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false)
            }, constraints: table => table.PrimaryKey("PK_AuditIntegrityEvents", x => x.SequenceNumber));
    }
    protected override void Down(MigrationBuilder migrationBuilder) => migrationBuilder.DropTable("AuditIntegrityEvents");
}
