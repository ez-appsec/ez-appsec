<?php
// True negative: no CSRF exclusions (safe)
// ok: ez-laravel-csrf-exclude
class VerifyCsrfMiddleware extends VerifyCsrfToken {
    // No exclusions — all routes are CSRF-protected
}
