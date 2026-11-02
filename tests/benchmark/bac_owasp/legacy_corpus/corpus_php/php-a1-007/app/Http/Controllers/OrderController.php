<?php

namespace App\Http\Controllers;

use App\Models\Order;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class OrderController extends Controller
{
    public function show(Request $request): JsonResponse
    {
        $uid = $request->user()->id;

        $order = Order::where('id', $request->route('id'))
            ->where('user_id', $uid)
            ->firstOrFail();

        return response()->json([
            'id' => $order->id,
            'status' => $order->status,
            'total' => $order->total,
        ]);
    }
}
