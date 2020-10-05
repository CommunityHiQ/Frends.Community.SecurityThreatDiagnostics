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

Challenging message payload attributes for input validation and known attack vectors.

### Properties

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| Payload | `string` | Payload text that will be challenged. | `This is a valid message.` |

### Options

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| Encoding | `string` | Encoding of the character set. | `UTF-8` |

### Returns

A result object with parameters.

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| bool | `bool` | Challenged threats | `true, true, true` |

Challenge known IP adresses against request based information about IP addresses. Challenge against known IP addresses (whitelist) and blocked IP addresses (blacklisted).

### Allowed IP Addresses

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| Host | `string` | Known ip address. | `192.16.8.2` |
| Whitelisted IP addresses | `item` | Known ip address to be passed. | `\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}` |
| Blacklisted IP addresses | `item` | Known ip address to be blocked. | `\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}` |

### Returns

A result object with parameters.

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| bool | `bool` | Challenged threats | `true` |

### Challenge known HTTP based security headers
| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| Allowed http headers | `string` | Known ip address. | `Authrozation` |
| HttpHeaders | `Collection` | Known ip headers to be passed. | `#trigger.data.httpHeaders` |

### Returns

A result object with parameters.

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| bool | `bool` | Challenged threats | `true` |

### Validate known encoding character set
| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| Payload | `string` | Known ip address. | `Authrozation` |
### Options

| Property | Type | Description | Example |
| -------- | -------- | -------- | -------- |
| MaxIterations | `number` | Number of itertion rounds for hex tranformation to ascii. | 2 |
| Encoding | `string` | Encoding of the character set. | `UTF-8` |

Usage:
To fetch result use syntax:

`#result.Replication`

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
| 0.0.1   | Development stil going on. |
