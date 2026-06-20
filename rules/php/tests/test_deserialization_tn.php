<?php
// True negative: json_decode is safe
class DataController extends Controller
{
    public function import(Request $request)
    {
        // ok: ez-laravel-insecure-deserialization
        $obj = json_decode($request->input('data'), true);
        return response()->json($obj);
    }
}
