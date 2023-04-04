# Session Decoder

[![CircleCI](https://circleci.com/gh/Financial-Times/session-decoder-js/tree/main.svg?style=svg)](https://circleci.com/gh/Financial-Times/session-decoder-js/tree/main)

A library that allows you to decode the UUID from an FT session.

## Usage

To use the Session Decoder, you need to provide a public key to the constructor. The public key is used to verify the digital signature of the session token. Here is an example of how to use the Session Decoder to decode a session token:

```js
const SessionDecoder = require('@financial-times/session-decoder-js');
const secureDecoder = new SessionDecoder(SESSION_PUBLIC_KEY);
const uuid = secureDecoder.decode(Session);
```

## Installation

```shell
npm install @financial-times/session-decoder-js
```

## Security Warning

It is important to note that the session token only holds the UUID and does not indicate the validity of the session, such as whether it has expired or been revoked. As a result, it is not recommended to use this library for authentication. Requests that read and write user data must authenticate directly against the Session API to ensure that the session is valid.

For more information:-

* [next-session](https://github.com/Financial-Times/next-session)
* [next-session-client](https://github.com/Financial-Times/next-session-client)
