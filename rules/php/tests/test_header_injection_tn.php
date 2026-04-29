<?php
// True negative: hardcoded header value (safe)
class LanguageController extends Controller
{
    public function setLang()
    {
        // ok: ez-laravel-header-injection
        return response('OK')->header('Content-Language', 'en-US');
    }
}
