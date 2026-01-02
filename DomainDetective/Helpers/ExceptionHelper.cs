using System;

namespace DomainDetective.Helpers;

internal static class ExceptionHelper
{
    public static bool IsFatal(Exception ex)
    {
        if (ex is OutOfMemoryException or StackOverflowException or AccessViolationException or AppDomainUnloadedException)
        {
            return true;
        }

#if NET472
        if (ex is System.Threading.ThreadAbortException)
        {
            return true;
        }
#endif

        return false;
    }
}

