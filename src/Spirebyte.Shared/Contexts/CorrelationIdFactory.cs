using Convey.HTTP;
using Convey.MessageBrokers;
using Microsoft.AspNetCore.Http;

namespace Spirebyte.Shared.Contexts;

public class CorrelationIdFactory : ICorrelationIdFactory
{
    private static readonly AsyncLocal<CorrelationIdHolder> Holder = new();
    private readonly string _header;
    private readonly IHttpContextAccessor _httpContextAccessor;

    private readonly IMessagePropertiesAccessor _messagePropertiesAccessor;

    public CorrelationIdFactory(IMessagePropertiesAccessor messagePropertiesAccessor,
        IHttpContextAccessor httpContextAccessor, HttpClientOptions httpClientOptions)
    {
        _messagePropertiesAccessor = messagePropertiesAccessor;
        _httpContextAccessor = httpContextAccessor;
        _header = httpClientOptions.CorrelationIdHeader;
    }

    private static string? CorrelationId
    {
        get => Holder.Value?.Id;
        set
        {
            var holder = Holder.Value;
            if (holder is { }) holder.Id = null;

            if (value is { }) Holder.Value = new CorrelationIdHolder { Id = value };
        }
    }

    public string? Create()
    {
        if (!string.IsNullOrWhiteSpace(CorrelationId)) return CorrelationId;

        var correlationId = _messagePropertiesAccessor.MessageProperties?.CorrelationId;
        if (!string.IsNullOrWhiteSpace(correlationId))
        {
            CorrelationId = correlationId;
            return CorrelationId;
        }

        if (string.IsNullOrWhiteSpace(_header) || _httpContextAccessor.HttpContext is null)
        {
            CorrelationId = CreateId();
            return CorrelationId;
        }

        if (!_httpContextAccessor.HttpContext.Request.Headers.TryGetValue(_header, out var id))
        {
            CorrelationId = CreateId();
            return CorrelationId;
        }

        correlationId = id.ToString();
        CorrelationId = string.IsNullOrWhiteSpace(correlationId) ? CreateId() : correlationId;

        return CorrelationId;
    }

    private static string? CreateId()
    {
        return Guid.NewGuid().ToString("N");
    }

    private class CorrelationIdHolder
    {
        public string? Id;
    }
}