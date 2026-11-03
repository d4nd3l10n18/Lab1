using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace SecureLab.Api.Tests;

public sealed class CapturingLoggerProvider : ILoggerProvider
{
    public ConcurrentQueue<string> Messages { get; } = new();
    public ILogger CreateLogger(string categoryName) => new Sink(categoryName, Messages);
    public void Dispose() { }

    private sealed class Sink(string category, ConcurrentQueue<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? ex,
            Func<TState, Exception?, string> formatter) =>
            messages.Enqueue(category + "|" + formatter(state, ex));
    }
}