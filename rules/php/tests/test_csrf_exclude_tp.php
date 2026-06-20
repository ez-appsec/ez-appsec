<?php
// True positive: CSRF exclusions
// ruleid: ez-laravel-csrf-exclude
class VerifyCsrfMiddleware extends VerifyCsrfToken {
    protected $except = [
        'api/*',
        'webhook/*',
    ];
}
