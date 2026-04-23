# Auth Gateway (Cloudflare Workers)

Simple authentication gateway for Cloudflare Workers.
Handles OAuth and password login, manages sessions, and forwards requests to internal services.

---

## Features

* OAuth login (e.g. Google)
* Email + password login
* Session handling (Durable Object or JWT)
* Route-based auth protection
* CSRF + optional Turnstile support
* Password hashing with pepper rotation
* Optional username support

---

## Basic Usage

```ts
import createGateway from '@electr0zed/auth-gateway-cf';
import config from './config';

export default createGateway(config);
```

---

## Auth Routes

### OAuth

* `/auth/login`
* `/auth/callback`
* `/auth/logout`

### Password

* `GET  /auth/csrf`
* `POST /auth/password/register`
* `POST /auth/password/login`
* `POST /auth/password/change`

---

## Config Example

Can be found at src/config.example.ts

---

## Notes

* `/auth/*` is used internally by the gateway
* UI (e.g. `/sign-in`) should be handled separately
* Public env vars (e.g. Turnstile site key) are set at build time
* Worker secrets are configured via Wrangler
