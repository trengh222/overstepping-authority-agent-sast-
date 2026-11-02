<?php

namespace App\Http\Controllers;

use App\Models\Order;

class OrderController
{
    public function show($id)
    {
        return response()->json(Order::find($id));
    }
}
