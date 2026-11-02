<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class OrderController extends Controller
{
    public function show(Request $request): JsonResponse
    {
        $order = Order::findOrFail($request->route('id'));

        return response()->json([
            'id' => $order->id,
            'status' => $order->status,
            'total' => $order->total,
        ]);
    }
}
