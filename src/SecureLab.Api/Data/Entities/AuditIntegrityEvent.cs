namespace SecureLab.Api.Data.Entities;
public sealed class AuditIntegrityEvent
{
    public long SequenceNumber { get; set; }
    public DateTimeOffset TimestampUtc { get; set; }
    public string EventType { get; set; } = "";
    public Guid? ActorUserId { get; set; }
    public string EntityType { get; set; } = "";
    public string? EntityId { get; set; }
    public string Action { get; set; } = "";
    public string Outcome { get; set; } = "";
    public string TraceId { get; set; } = "";
    public string PreviousHmac { get; set; } = "";
    public string CurrentHmac { get; set; } = "";
}
