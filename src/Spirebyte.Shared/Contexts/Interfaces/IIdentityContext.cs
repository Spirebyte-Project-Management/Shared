using System;
using System.Collections.Generic;

namespace Spirebyte.Shared.Contexts.Interfaces;

public interface IIdentityContext
{
    bool IsAuthenticated { get; }
    public Guid Id { get; }
    string Role { get; }
    Dictionary<string, IEnumerable<string>> Claims { get; }
    bool IsUser();
    bool IsAdmin();
}