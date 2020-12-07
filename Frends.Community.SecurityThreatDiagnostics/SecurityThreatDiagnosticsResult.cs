using System;
using System.Collections.Generic;

namespace Frends.Community.SecurityThreatDiagnostics
{
    
    /// <summary>Gives response back in tasks. Uses la
    /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
    /// </summary>  
     public class SecurityThreatDiagnosticsResult
    {
        // Is valid content
        public bool IsValid;
        // Result of the query
        public Dictionary<String, Object> Data;
    }

}