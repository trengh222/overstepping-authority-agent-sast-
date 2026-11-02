<?php

namespace App\Http\Controllers;

use App\Models\Invoice;
use Illuminate\Support\Facades\Auth;

class InvoiceController
{
    public function show($id)
    {
        $uid = Auth::id();
        $item = Invoice::where('id', $id)->where('user_id', $uid)->firstOrFail();
        return response()->json($item);
    }
}
