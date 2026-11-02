<?php

namespace App\Http\Controllers;

use App\Models\Invoice;

class InvoiceController
{
    public function show($id)
    {
        return response()->json(Invoice::find($id));
    }
}
