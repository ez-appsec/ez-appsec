<?php
// True positive: unserialize on user input
class DataController extends Controller
{
    public function import(Request $request)
    {
        // ruleid: ez-laravel-insecure-deserialization
        $obj = unserialize($request->input('data'));
        return response()->json($obj);
    }
}
