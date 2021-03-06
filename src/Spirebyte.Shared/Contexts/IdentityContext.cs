using System.Security.Claims;
using IdentityModel;
using Spirebyte.Shared.Contexts.Interfaces;

namespace Spirebyte.Shared.Contexts;

public class IdentityContext : IIdentityContext
{
    private IdentityContext()
    {
    }

    public IdentityContext(CorrelationContext.UserContext context)
        : this(context.Id, context.Role, context.IsAuthenticated, context.Claims)
    {
    }

    public IdentityContext(string id, string role, bool isAuthenticated, Dictionary<string, IEnumerable<string>> claims)
    {
        Id = Guid.TryParse(id, out var userId) ? userId : Guid.Empty;
        Role = role ?? string.Empty;
        IsAuthenticated = isAuthenticated;
        Claims = claims ?? new Dictionary<string, IEnumerable<string>>();
    }

    public IdentityContext(Guid? id)
    {
        Id = id ?? Guid.Empty;
        IsAuthenticated = id.HasValue;
    }

    public IdentityContext(ClaimsPrincipal principal)
    {
        if (principal?.Identity is null || string.IsNullOrWhiteSpace(principal.Identity.Name)) return;

        IsAuthenticated = principal.Identity?.IsAuthenticated is true;
        Id = Guid.Parse(principal.Claims.SingleOrDefault(x => x.Type == JwtClaimTypes.Subject)?.Value ?? string.Empty);
        Role = principal.Claims.SingleOrDefault(x => x.Type == ClaimTypes.Role)?.Value;
        Claims = principal.Claims.GroupBy(x => x.Type)
            .ToDictionary(x => x.Key, x => x.Select(c => c.Value.ToString()));
    }

    public static IIdentityContext Empty => new IdentityContext();
    public bool IsAuthenticated { get; }
    public Guid Id { get; }
    public string Role { get; }
    public Dictionary<string, IEnumerable<string>> Claims { get; }

    public bool IsUser()
    {
        return Role is "user";
    }

    public bool IsAdmin()
    {
        return Role is "admin";
    }
}