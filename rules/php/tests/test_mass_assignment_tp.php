<?php
// True positive: mass assignment via $request->all()
class UserController extends Controller
{
    public function store(Request $request)
    {
        // ruleid: ez-laravel-mass-assignment
        $user = User::create($request->all());
        return response()->json($user);
    }
}
