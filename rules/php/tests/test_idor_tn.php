<?php
// True negative: scoped to authenticated user (safe)
class InvoiceController extends Controller
{
    public function show(Request $request)
    {
        // ok: ez-laravel-idor-find
        $invoice = auth()->user()->invoices()->findOrFail($request->input('id'));
        return response()->json($invoice);
    }
}
