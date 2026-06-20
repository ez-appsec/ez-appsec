<?php
// True positive: IDOR via direct find without scoping
class InvoiceController extends Controller
{
    public function show(Request $request)
    {
        // ruleid: ez-laravel-idor-find
        $invoice = Invoice::find($request->input('id'));
        return response()->json($invoice);
    }
}
