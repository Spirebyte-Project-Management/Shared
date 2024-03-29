﻿namespace Spirebyte.Shared.Changes.ValueObjects;

public class Change
{
    public Change(string name, string? before, string? after)
    {
        Name = name;
        Before = before;
        After = after;
    }

    public string Name { get; set; }
    public string? Before { get; set; }
    public string? After { get; set; }
}