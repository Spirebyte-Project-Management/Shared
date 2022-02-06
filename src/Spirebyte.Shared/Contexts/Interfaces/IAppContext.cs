namespace Spirebyte.Shared.Contexts.Interfaces;

public interface IAppContext
{
    Guid RequestId { get; }
    string CorrelationId { get; }
    string TraceId { get; }
    string IpAddress { get; }
    string UserAgent { get; }
    IIdentityContext Identity { get; }
}