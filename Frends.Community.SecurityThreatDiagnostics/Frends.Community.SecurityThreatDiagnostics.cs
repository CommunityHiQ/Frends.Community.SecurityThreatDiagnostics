using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml;
using System.Xml.Linq;

#pragma warning disable 1591

namespace Frends.Community.SecurityThreatDiagnostics
{
    public class SecurityRuleFilter
    {
        public string Id  { get; set; }
        
        public Regex Rule { get; set; }
        
        public string Description  { get; set; }
    }

    public sealed class SecurityFilterReader
    {
        private static readonly object PadLock = new object();
        private static readonly Lazy<ConcurrentDictionary<string, SecurityRuleFilter>>

            Lazy = 
                new Lazy<ConcurrentDictionary<string, SecurityRuleFilter>>
                (() =>
                 { 
                    lock (PadLock) {
                        XDocument xdoc = XDocument.Parse(SecurityFilters.SecurityRules);
                        XmlReader reader = new XmlTextReader(new StringReader(xdoc.ToString()));
                        try
                        {
                            ConcurrentDictionary<string, SecurityRuleFilter> concurrentRules = new ConcurrentDictionary<string, SecurityRuleFilter>();
                            while (reader.Read())
                            {
                                SecurityRuleFilter securityRuleFilter = new SecurityRuleFilter();
                                string id = Guid.NewGuid().ToString();
                                switch (reader.NodeType)
                                {
                                    case XmlNodeType.CDATA:
                                        securityRuleFilter.Id = id;
                                        securityRuleFilter.Rule = new Regex(reader.Value, RegexOptions.IgnoreCase);
                                        break;
                                    case XmlNodeType.Element:
                                    {
                                        securityRuleFilter.Description = reader.GetAttribute("description");
                                        break;
                                    } 
                               } 
                               if (securityRuleFilter.Id != null) {
                                    concurrentRules.TryAdd(id, securityRuleFilter);
                               }
                            }
                            return concurrentRules;
                        }
                        finally
                        {
                            if (reader != null)
                                reader.Dispose();
                        }
                    }
                });
      
    /// <summary>Gives instance access into the dictionary of security rule filters. Uses la
    /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
    /// Throws application exception if diagnostics finds a vulnerability from the challenged payload.
    /// </summary>    
    public static ConcurrentDictionary<string, SecurityRuleFilter> Instance
        {
            get
            {
                return Lazy.Value;
            }
        }
    }

    /// <summary>
    /// This is task which validates the common attack patterns against the underlying system.
    /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
    /// Throws application exception if diagnostics finds a vulnerability from the challenged payload.
    /// </summary>
    public static class SecurityThreatDiagnostics
    {
        private static string Decode(string payload, Options options)
        {
            for (int i = 0; i < options.MaxIterations; i++)
            {
                payload = WebUtility.UrlDecode(payload);
            }
            return payload;
        }

        /// <summary>
        /// If payload is Base-64 encoded it will be returned back as decoded. If message is not base 64 encoded the original string will be returned.
        /// </summary>
        private static string DecodeBase64Encoding(String payload)
        {
            string asciiEncoded = payload;
            try
            {
                byte[] data = Convert.FromBase64String(payload);
                asciiEncoded = ASCIIEncoding.ASCII.GetString(data);
            }
            catch (FormatException formatException)
            {
                // silent error, payload was not Base-64 encoded.
            }

            return asciiEncoded;
        }

        private static String ChangeCharacterEncoding(string payload, Options options)
        {
            // Create two different encodings.
            Encoding sourceEncoding = Encoding.GetEncoding(options.SourceEncoding);
            // Encoding of the underlying system.
            Encoding destinationEncoding = Encoding.GetEncoding(options.DestinationEncoding);
            // Convert the string into a byte array.
            byte[] destinationBytes = destinationEncoding.GetBytes(payload);
            // Perform the conversion from one encoding to the other.
            byte[] asciiBytes = Encoding.Convert(sourceEncoding,destinationEncoding, destinationBytes);
            // Turn into destination encoding
            return destinationEncoding.GetString(asciiBytes);
        }
        
        public static SecurityThreatDiagnosticsResult ChallengeCharacterSetEncoding(string payload, Options options)
        {
            string data = null;
            {
                try
                {
                    data = ChangeCharacterEncoding(payload, options);
                }
                catch (Exception exception)
                {
                    StringBuilder argumentExceptions =
                        new StringBuilder("Security Threat Diagnostics vulnerability report invalid character encoding:");
                    StringBuilder applicationExceptions =
                        new StringBuilder("Security Threat Diagnostics deep scanned the following attack vectors: ");
                    try
                    {
                        argumentExceptions.Append(exception.Message.ToString()).Append("\n");
                        applicationExceptions.Append("Contains illegal characters: ").Append(payload).Append("\n");
                        ApplicationException applicationException =
                            new ApplicationException(argumentExceptions.ToString());
                        ArgumentException argumentException = new ArgumentException(applicationExceptions.ToString());
                        throw new ApplicationException(applicationException.ToString(), argumentException);
                    }
                    finally
                    {
                        if (applicationExceptions != null)
                        {
                            argumentExceptions.Clear();
                            argumentExceptions.Clear();
                        }
                    }
                }
                SecurityThreatDiagnosticsResult securityThreatDiagnosticsResult = new SecurityThreatDiagnosticsResult();
                securityThreatDiagnosticsResult.IsValid = true;
                //securityThreatDiagnosticsResult.Data.Add("data", data);
        
                return securityThreatDiagnosticsResult;
            }
        }
        
        /// <summary>
        /// This is task which validates the common attack patterns against the underlying system from payload attributes.
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// Throws application exception if diagnostics find vulnerability from the payload challenge.
        /// </summary>
        public static SecurityThreatDiagnosticsResult ChallengeAttributesAgainstSecurityThreats(
            [PropertyTab] ValidationAttributes validationAttributes,
            [PropertyTab] Options options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var invalidAttributes = new Dictionary<string, ArgumentException>();
            ConcurrentDictionary<string, SecurityRuleFilter> securityRuleFilters = SecurityFilterReader.Instance;
            foreach (var attribute in validationAttributes.Attribute)
            {
                foreach (SecurityRuleFilter securityRuleFilter in securityRuleFilters.Values)
                {
                    Validation validation = new Validation();
                    validation.Payload = attribute;
                    try
                    {
                        ChallengeAgainstSecurityThreats(validation, options, cancellationToken);
                    }
                    catch (ArgumentException argumentException)
                    {
                        invalidAttributes.Add(attribute, argumentException);
                    }
                }
            }

            if (invalidAttributes.Count > 0)
            {
                StringBuilder argumentExceptions = new StringBuilder(
                    "Security Threat Diagnostics vulnerability report for attributes contains the following invalid messages:");
                StringBuilder applicationExceptions =
                    new StringBuilder("Security Threat Diagnostics deep scanned the following attack vectors: ");
                try
                {
                   
                    foreach (var securityRuleFilter in invalidAttributes)
                    {
                        argumentExceptions.Append(securityRuleFilter.Value.Message).Append("\n");
                        applicationExceptions.Append(securityRuleFilter.Value.InnerException.Message).Append("\n");
                    }

                    ApplicationException applicationException = new ApplicationException(argumentExceptions.ToString());
                    ArgumentException argumentException = new ArgumentException(applicationExceptions.ToString());
                    throw new ApplicationException(applicationException.ToString(), argumentException);
                }
                finally
                {
                    if (applicationExceptions != null)
                    {
                        argumentExceptions.Clear();
                        argumentExceptions.Clear();
                    }
                }
            }
            SecurityThreatDiagnosticsResult securityThreatDiagnosticsResult = new SecurityThreatDiagnosticsResult();
            securityThreatDiagnosticsResult.IsValid = true;
            
            return securityThreatDiagnosticsResult;
        }

        /// <summary>
        /// This is task which validates data 
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// Throws application exception if diagnostics find vulnerability from the payload challenge.
        /// </summary>
        /// <param name="validation">Runtime element to be diagnosted.</param>
        /// <param name="options">Options for the runtime validation.</param>
        /// <param name="cancellationToken"></param>
        /// <returns>{bool challenges for validation} </returns>
        public static SecurityThreatDiagnosticsResult ChallengeAgainstSecurityThreats(
            [PropertyTab] Validation validation,
            [PropertyTab] Options options, 
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Dictionary<string, string> dictionary = new Dictionary<string, string>();
            StringBuilder validationChallengeMessage = new StringBuilder();
            validationChallengeMessage
                .Append("Payload challenged for input validation [")
                .Append(validation.Payload)
                .Append("] \n\n");

            StringBuilder innerExceptionMessage = new StringBuilder();
            innerExceptionMessage
                .Append("Payload challenged for input validation [")
                .Append(validation.Payload)
                .Append("] \n\n");
            
            ConcurrentDictionary<string, SecurityRuleFilter> ruleDictionary = SecurityFilterReader.Instance;

            foreach (var entry in ruleDictionary)
            {
                ChallengeCharacterSetEncoding(validation.Payload, options);
                string base64DecodedPayload = DecodeBase64Encoding(validation.Payload);
                
                if (entry.Value.Rule.IsMatch(validation.Payload) ||
                    entry.Value.Rule.IsMatch(base64DecodedPayload))
                {
                    validationChallengeMessage
                        .Append("id [")
                        .Append(entry.Key)
                        .Append("]")
                        .Append(" contains vulnerability [")
                        .Append(entry.Value.Description)
                        .Append("], ")
                        .Append("encoded value [")
                        .Append(base64DecodedPayload)
                        .Append("]");
                    dictionary.Add(entry.Key, validationChallengeMessage.ToString());
                    innerExceptionMessage
                        .Append("id [")
                        .Append(entry.Key)
                        .Append("] ")
                        .Append("Validation pattern [")
                        .Append(entry.Value.Rule.ToString())
                        .Append("], ")
                        .Append("encoded value [")
                        .Append(base64DecodedPayload)
                        .Append("]");
                }
            }
            
            if (dictionary.Count > 0)
            {
                ArgumentException argumentException = new ArgumentException("Invalid argument information " + innerExceptionMessage.ToString());
                ApplicationException applicationException = new ApplicationException(validationChallengeMessage.ToString(), argumentException);
                throw applicationException;
            }

            SecurityThreatDiagnosticsResult securityThreatDiagnosticsResult = new SecurityThreatDiagnosticsResult();
            securityThreatDiagnosticsResult.IsValid = true;
            
            return securityThreatDiagnosticsResult;
        }
        
        /// <summary>
        ///  Verifies that the IP is in given whitelist of known IP addresses.
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// Throws application exception if diagnostics find that IP address is not valid.
        /// </summary>
        /// <param name="allowedIpAddresses">Define IP addresses which can bypass the validation.</param>
        /// <param name="cancellationToken"></param>
        /// <returns>{SecurityThreatDiagnosticsResult.IsValid challenge}</returns>
        public static SecurityThreatDiagnosticsResult ChallengeIPAddresses(
            [PropertyTab] AllowedIPAddresses allowedIpAddresses,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            List<string> invalidIPAddresses = new List<string>();
            allowedIpAddresses.WhiteListedIpAddress?.ToList().ForEach(
                entry =>
                {
                    Regex allowedInboundTrafficRule = new Regex(entry);
                    if  (!allowedInboundTrafficRule.IsMatch(allowedIpAddresses.Host)) 
                    {
                        invalidIPAddresses.Append(entry);
                    }
                });
            
            allowedIpAddresses.BlackListedIpAddresses?.ToList().ForEach(
                entry =>
                {
                    Regex allowedInboundTrafficRule = new Regex(entry);
                    if (allowedInboundTrafficRule.IsMatch(allowedIpAddresses.Host))
                    {
                        invalidIPAddresses.Append(entry);
                    }
                });
            if (invalidIPAddresses.Count > 0)
            {
                throw new ApplicationException("Invalid IP Address or range [" + allowedIpAddresses.Host + "]");
            }
            SecurityThreatDiagnosticsResult securityThreatDiagnosticsResult = new SecurityThreatDiagnosticsResult();
            securityThreatDiagnosticsResult.IsValid = true;
            
            return securityThreatDiagnosticsResult;
        }
        
        /// <summary>
        ///  Verifies the header content and validates data.
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// Throws application exception if diagnostics find that header data is not valid.
        /// </summary>
        /// <param name="whiteListedHeaders">Known HTTP headers to be bypassed in validation.</param>
        /// <param name="options">Configuration of the task</param>
        /// <param name="cancellationToken"></param>
        /// <returns>{SecurityThreatDiagnosticsResult.IsValid challenge}</returns>
        public static SecurityThreatDiagnosticsResult ChallengeSecurityHeaders(
            [PropertyTab] WhiteListedHeaders whiteListedHeaders, 
            [PropertyTab] Options options, 
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Dictionary<string, string> dictionary = new Dictionary<string, string>();
            ConcurrentDictionary<string, SecurityRuleFilter> ruleDictionary = SecurityFilterReader.Instance;
            
            StringBuilder validationChallengeMessage = new StringBuilder();
            validationChallengeMessage
                .Append("HTTP headers challenged for input validation ");
            
            StringBuilder innerExceptionMessage = new StringBuilder();
            innerExceptionMessage
                .Append("HTTP headers challenged for input validation, \n");
            
            foreach (KeyValuePair<string, string> HttpHeaderPair in whiteListedHeaders?.HttpHeaders)
            {
                whiteListedHeaders?.AllowedHttpHeaders?.ToList().Select(allowedHeader =>
                {
                    if (HttpHeaderPair.Key.Equals(allowedHeader))
                    {
                        foreach (var rule in ruleDictionary)
                        {
                            ChallengeCharacterSetEncoding(HttpHeaderPair.Value, options);
                            string base64DecodedHeaderValue = DecodeBase64Encoding(HttpHeaderPair.Value);
                            
                            if (rule.Value.Rule.IsMatch(HttpHeaderPair.Value) || base64DecodedHeaderValue.Length > 0 &&
                                rule.Value.Rule.IsMatch(base64DecodedHeaderValue))
                            if (rule.Value.Rule.IsMatch(HttpHeaderPair.Value))
                            {
                                validationChallengeMessage
                                    .Append("Header [")
                                    .Append(rule.Key)
                                    .Append("]")
                                    .Append(" contains vulnerability [")
                                    .Append(rule.Value.Description)
                                    .Append("]");
                                dictionary.Add(rule.Value.Id, innerExceptionMessage.ToString());
                                innerExceptionMessage
                                    .Append("id [")
                                    .Append(HttpHeaderPair.Key)
                                    .Append("]")
                                    .Append(HttpHeaderPair.Value)
                                    .Append("], ")
                                    .Append("encoded value [")
                                    .Append(base64DecodedHeaderValue)
                                    .Append("]");
                            }
                        }
                    }
                    else
                    {
                        StringBuilder builder = new StringBuilder("Invalid Header name [");
                        builder
                            .Append(HttpHeaderPair.Key)
                            .Append("] found.");
                    }
                    return allowedHeader;
                });
            }
            
            if (dictionary.Count > 0)
            {
                ArgumentException argumentException = new ArgumentException("Invalid argument information " + innerExceptionMessage.ToString());
                StringBuilder builder = new StringBuilder("Invalid Header information contains [");
                builder.Append(dictionary.Count).Append("]\n\n");
                builder.Append(validationChallengeMessage.ToString());
                throw new ApplicationException(builder.ToString(), argumentException);
            }
            
            SecurityThreatDiagnosticsResult securityThreatDiagnosticsResult = new SecurityThreatDiagnosticsResult();
            securityThreatDiagnosticsResult.IsValid = true;
            
            return securityThreatDiagnosticsResult;
        }
        
        
        /// <summary>
        ///  Challenges character encoding of the given data.
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// Throws application exception if diagnostics find that character is not part of the encoding set.
        /// </summary>
        /// <param name="validation">Known data to be bypassed into the validation.</param>
        /// <param name="options">Configuration parameters</param>
        /// <param name="cancellationToken"></param>
        /// <returns>{SecurityThreatDiagnosticsResult.IsValid challenge}</returns>
        public static SecurityThreatDiagnosticsResult ChallengeUrlEncoding
        (
            [PropertyTab] Validation validation,     
            [PropertyTab] Options options, 
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                validation.Payload = Decode(validation.Payload, options);
                ChallengeAgainstSecurityThreats(validation, options, cancellationToken);
            }
            catch (Exception exception)
            {
                StringBuilder builder = new StringBuilder("Invalid URL encoding in character set [");
                builder
                    .Append(validation.Payload)
                    .Append("]");
                ArgumentException argumentException = new ArgumentException("Invalid URL encoding information "  + exception.ToString(), exception);
                throw new ApplicationException(builder.ToString(), argumentException);                
            }
            SecurityThreatDiagnosticsResult securityThreatDiagnosticsResult = new SecurityThreatDiagnosticsResult();
            securityThreatDiagnosticsResult.IsValid = true;
            
            return securityThreatDiagnosticsResult;
        }

    }
    
}