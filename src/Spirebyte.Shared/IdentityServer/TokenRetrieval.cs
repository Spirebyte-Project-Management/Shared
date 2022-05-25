using System.Text;
using Microsoft.AspNetCore.Http;

namespace Spirebyte.Shared.IdentityServer;

public static class TokenRetrieval
{
    public static Func<HttpRequest, string> BasicFromAuthorizationHeader(string scheme = "Basic")
    {
        return request =>
        {
            string authorization = request.Headers["Authorization"].FirstOrDefault();
            
            if (string.IsNullOrEmpty(authorization))
            {
                return null;
            }

            if (authorization.StartsWith(scheme + " ", StringComparison.OrdinalIgnoreCase))
            {
                return authorization.Substring(scheme.Length + 1).Trim();
            }
            
            var authBase64 = Encoding.UTF8.GetString(Convert.FromBase64String(authorization));
            var authSplit = authBase64.Split(Convert.ToChar(":"), 2);
            if (authSplit.Length > 1)
            {
                return authSplit[1];
            }

            return null;
        };
    }

    /// <summary>
    /// Reads the token from a query string parameter.
    /// </summary>
    /// <param name="name">The name (defaults to access_token).</param>
    /// <returns></returns>
    public static Func<HttpRequest, string> FromQueryString(string name = "access_token")
    {
        return request => request.Query[name].FirstOrDefault();
    }
}