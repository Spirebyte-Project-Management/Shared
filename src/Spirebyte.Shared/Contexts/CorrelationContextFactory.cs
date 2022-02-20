using Convey.HTTP;
using Convey.MessageBrokers;
using Microsoft.AspNetCore.Http;

namespace Spirebyte.Shared.Contexts;

public class CorrelationContextFactory : ICorrelationContextFactory
{
    private static readonly AsyncLocal<CorrelationContextHolder> Holder = new();

    private readonly IMessagePropertiesAccessor _messagePropertiesAccessor;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly string _header;

    public CorrelationContextFactory(IMessagePropertiesAccessor messagePropertiesAccessor,
        IHttpContextAccessor httpContextAccessor, HttpClientOptions httpClientOptions)
    {
        _messagePropertiesAccessor = messagePropertiesAccessor;
        _httpContextAccessor = httpContextAccessor;
        _header = httpClientOptions.CorrelationContextHeader;
    }

    private static string? CorrelationContext
    {
        get => Holder.Value?.CorrelationContext;
        set
        {
            var holder = Holder.Value;
            if (holder is {})
            {
                holder.CorrelationContext = null;
            }

            if (value is {})
            {
                Holder.Value = new CorrelationContextHolder {CorrelationContext = value};
            }
        }
    }

    private class CorrelationContextHolder
    {
        public string? CorrelationContext;
    }
    
    public string? Create()
    {
        if (!string.IsNullOrWhiteSpace(CorrelationContext))
        {
            return CorrelationContext;
        }
        
        if (string.IsNullOrWhiteSpace(_header))
        {
            CorrelationContext = "";
            return CorrelationContext;
        }
        
        if (_messagePropertiesAccessor.MessageProperties?.Headers.TryGetValue(_header, out var messageContext) != null)
        {
            if (messageContext is string)
            {
                CorrelationContext = messageContext.ToString();
                return CorrelationContext;   
            }
        }

        if (_httpContextAccessor.HttpContext is null)
        {
            CorrelationContext = "";
            return CorrelationContext;
        }

        if (_httpContextAccessor.HttpContext.Request.Headers.TryGetValue(_header, out var httpContext))
        {
            CorrelationContext = httpContext;
            return CorrelationContext;
        }

        CorrelationContext = "";

        return CorrelationContext;
    }
}