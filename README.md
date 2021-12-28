# Session Decoder

[![CircleCI](https://circleci.com/gh/Financial-Times/session-decoder-js/tree/main.svg?style=svg)](https://circleci.com/gh/Financial-Times/session-decoder-js/tree/main)

A simple lib that allows you to decode the uuid from an FT session.

## How to use

```shell
make install
make test
```

## Warning

The session token holds the UUID but not any information as to the validity of the session - for example if the session
was revoked by the FT or expired.

It is therefore unsuitable to use this library for authentication.

Requests that read and write a user's data MUST authenticate directly against the Session API to ensure the session is
valid.

For more information:-

* [next-session](https://github.com/Financial-Times/next-session)
* [next-session-client](https://github.com/Financial-Times/next-session-client)
