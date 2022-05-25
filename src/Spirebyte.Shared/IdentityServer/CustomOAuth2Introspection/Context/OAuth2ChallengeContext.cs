using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;

namespace Spirebyte.Shared.IdentityServer.CustomOAuth2Introspection.Context;

public class OAuth2ChallengeContext : PropertiesContext<ExtendedOAuth2IntrospectionOptions>
{
    public OAuth2ChallengeContext(
        HttpContext context,
        AuthenticationScheme scheme,
        ExtendedOAuth2IntrospectionOptions options,
        AuthenticationProperties properties)
        : base(context, scheme, options, properties) { }
    
    public Exception? AuthenticateFailure { get; set; }
    
    public string? Error { get; set; }
    
    public string? ErrorDescription { get; set; }
    
    public string? ErrorUri { get; set; }
    public bool Handled { get; private set; }
    
    public void HandleResponse() => Handled = true;
}