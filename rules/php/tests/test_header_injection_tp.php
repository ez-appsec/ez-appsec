<?php
// True positive: user input in response header
class LanguageController extends Controller
{
    public function setLang(Request $request)
    {
        // ruleid: ez-laravel-header-injection
        return response('OK')->header('Content-Language', $request->input('lang'));
    }
}
