# Frends.Community.SecurityThreatDiagnostics

frends Community Task for SecurityThreatDiagnostics

[![Actions Status](https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics/workflows/PackAndPushAfterMerge/badge.svg)](https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics/actions) ![MyGet](https://img.shields.io/myget/frends-community/v/Frends.Community.SecurityThreatDiagnostics) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 

- [Installing](#installing)
- [Tasks](#tasks)
     - [SecurityThreatDiagnostics](#SecurityThreatDiagnostics)
- [Building](#building)
- [Contributing](#contributing)
- [Change Log](#change-log)

# Installing

You can install the task via frends UI Task View or you can find the NuGet package from the following NuGet feed
https://www.myget.org/F/frends-community/api/v3/index.json and in Gallery view in MyGet https://www.myget.org/feed/frends-community/package/nuget/Frends.Community.SecurityThreatDiagnostics

# Tasks

## SecurityThreatDiagnostics

Challenge and validate message payload against commonly known attack vectors provided by OWASP 10.

### Properties

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| Payload | `string` | Payload text that will be challenged. | `This is a valid message.` |

### Options

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| MaxIterations | integer | Iterations for encoding. | 2 |
| Source encoding | 'string' | Datasource encoding. | UTF-8 |
| Destination encoding | 'string' | Datasource encoding. | UTF-8 |
| Base64 decode | bool | Payload will be Base64 decoded. | TRUE/FALSE |

### Returns

A result object with parameters.

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| IsValid | `bool` | Challenged threats | new Frends.Community.SecurityThreatDiagnostics.SecurityThreatDiagnosticsResult() { IsValid = false } |
| Data | `Dictionary` | Information about threats | <ID> = 79 |

Challenge and validate message payload attributes against commonly known attack vectors provided by OWASP 10.

### Properties

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| Attribute | `string` | Payload attribute text that will be challenged. | #trigger.data.body.Name |

### Options

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| MaxIterations | integer | Iterations for encoding. | 2 |
| Source encoding | 'string' | Datasource encoding. | UTF-8 |
| Destination encoding | 'string' | Datasource encoding. | UTF-8 |
| Base64 decode | bool | Payload will be Base64 decoded. | TRUE/FALSE |

### Returns

A result object with parameters.

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| IsValid | `bool` | Challenged threats | new Frends.Community.SecurityThreatDiagnostics.SecurityThreatDiagnosticsResult() { IsValid = false } |
| Data | `Dictionary` | Information about threats | <Unique ID of the threat> = 79 |

Challenge TCP/IP packages against known IP addresses (whitelisted IP) and blocked IP addresses (blacklisted IP).

###  Challege allowed and diswalloed TCP/IP Headers 

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| Host | `string` | Known ip address. | #trigger.data.httpClientIp |
| Whitelisted IP addresses | `regular expression - string` | Known ip address to be passed. | `\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}` |
| Blacklisted IP addresses | `regular expression - string` | Known ip address to be blocked. | `\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}` |

### Returns

A result object with parameters.

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| bool | `bool` | Challenged threats | #result.IsValid |

### Validate known encoding character set
| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| Payload | `string` | Known ip address. | `xxx.yyy.ccc.aaa` |
    
Challenge and validate URL for commonly known attack vectors provided by OWASP 10.

### Properties

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| Payload | `string` | https://payments.services.com. | #trigger.data.httpRequestUri |

### Options

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| MaxIterations | integer | Iterations for encoding. | 2 |
| Source encoding | 'string' | Datasource encoding. | UTF-8 |
| Destination encoding | 'string' | Datasource encoding. | UTF-8 |
| Base64 decode | bool | Payload will be Base64 decoded. | TRUE/FALSE |

### Returns

A result object with parameters.

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| bool | `bool` | Challenged threats | #result.IsValid |

### Challenge known HTTP based security headers
| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| Allowed http headers | `string` | Known ip address. | `Authorization` |
| HttpHeaders | `Collection` | Known ip headers to be passed. | `#trigger.data.httpHeaders` |

Usage:
To fetch result use syntax:

`#result.IsValid` or `#result.Data'

# Building

Clone a copy of the repo

`git clone https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics.git`

Rebuild the project

`dotnet build`

Run Tests

`dotnet test`

Create a NuGet package

`dotnet pack --configuration Release`

# Contributing
When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change.

1. Fork the repo on GitHub
2. Clone the project to your own machine
3. Commit changes to your own branch
4. Push your work back up to your fork
5. Submit a Pull request so that we can review your changes

NOTE: Be sure to merge the latest from "upstream" before making a pull request!

# Change Log

| Version | Changes |
| ------- | ------- |
| 1.0.0   | Initial version |
