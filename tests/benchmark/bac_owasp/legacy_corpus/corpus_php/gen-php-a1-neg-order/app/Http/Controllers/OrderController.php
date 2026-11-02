<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Support\Facades\Auth;

class OrderController
{
    public function show($id)
    {
        $uid = Auth::id();
        $item = Order::where('id', $id)->where('user_id', $uid)->firstOrFail();
        return response()->json($item);
    }
}
