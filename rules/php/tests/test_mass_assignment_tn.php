<?php
// True negative: validated input (safe)
class UserController extends Controller
{
    public function store(Request $request)
    {
        // ok: ez-laravel-mass-assignment
        $validated = $request->validate([
            'name' => 'required|string',
            'email' => 'required|email',
        ]);
        $user = User::create($validated);
        return response()->json($user);
    }
}
