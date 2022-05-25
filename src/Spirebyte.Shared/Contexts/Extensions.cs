using Convey.HTTP;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Open.Serialization.Json;
using Spirebyte.Shared.Contexts.Interfaces;

namespace Spirebyte.Shared.Contexts;

public static class Extensions
{
    public static IServiceCollection AddSharedContexts(this IServiceCollection services)
    {
        services.AddTransient<IAppContextFactory, AppContextFactory>();
        services.AddTransient(ctx => ctx.GetRequiredService<IAppContextFactory>().Create());

        return services;
    }

    public static IServiceCollection AddCorrelationContextFactories(this IServiceCollection services)
    {
        services.AddSingleton<ICorrelationIdFactory, CorrelationIdFactory>();
        services.AddSingleton<ICorrelationContextFactory, CorrelationContextFactory>();

        return services;
    }

    public static CorrelationContext? GetCorrelationContext(this IHttpContextAccessor accessor)
    {
        if (accessor.HttpContext is null) return null;

        if (!accessor.HttpContext.Request.Headers.TryGetValue("x-correlation-context", out var json)) return null;

        var jsonSerializer = accessor.HttpContext.RequestServices.GetRequiredService<IJsonSerializer>();
        var value = json.FirstOrDefault();

        return string.IsNullOrWhiteSpace(value) ? null : jsonSerializer.Deserialize<CorrelationContext>(value);
    }

    public static string GetUserIpAddress(this HttpContext? context)
    {
        if (context is null) return string.Empty;

        var ipAddress = context.Connection.RemoteIpAddress?.ToString();
        if (context.Request.Headers.TryGetValue("x-forwarded-for", out var forwardedFor))
        {
            var ipAddresses = forwardedFor.ToString().Split(",", StringSplitOptions.RemoveEmptyEntries);
            if (ipAddresses.Any()) ipAddress = ipAddresses[0];
        }

        return ipAddress ?? string.Empty;
    }
}